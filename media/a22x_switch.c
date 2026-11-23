/* SPDX-License-Identifier: MIT */
/*
 * a22x_switch: the browser's ALSA output, which moves at once between the phone (speaker or jack)
 * and Bluetooth headphones (2026-11-22, the owner: YouTube in the browser stayed on the speaker with
 * headphones connected).
 *
 * The browser opens "default", this plugin. It plays into one slave PCM at a time, named by the first
 * line of a small file (sound.py writes it: "a22x_phone", or "a22x_bt:DEV=address"), and looks at
 * that file at most every SWITCH_CHECK_MS while it plays. A new name opens the new slave with the same
 * format and size and closes the old one, without telling the browser: its stream goes on, which
 * Chromium's own ALSA output cannot do (it keeps a device open for many seconds after a pause). What
 * the old slave still held (a buffer, some tens of ms) is dropped.
 *
 *   pcm.!default { type a22x_switch select "/path/of/the/file" fallback "a22x_phone" }
 *
 * The delay told to the browser is the slave's, so a video stays in step with the headphones' longer
 * delay. A slave that fails (headphones gone) gives the sound to the fallback; a slave that cannot be
 * opened yet (headphones just connected, their audio not ready) is tried again every second.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <alsa/asoundlib.h>
#include <alsa/pcm_external.h>

#define SWITCH_CHECK_MS 150ull
#define SWITCH_RETRY_MS 1000ull
#define NAME_MAX_LEN 160

typedef struct {
	snd_pcm_ioplug_t io;
	char *select, *fallback;
	char current[NAME_MAX_LEN];
	char wanted[NAME_MAX_LEN];
	snd_pcm_t *slave;
	snd_pcm_uframes_t slave_buffer;
	struct stat seen;
	bool seen_valid, force;
	unsigned long long next_check, retry_at;
	unsigned long long written, played;
	int event_fd;
} Switch;

static unsigned long long now_ms(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (unsigned long long)t.tv_sec * 1000ull + (unsigned long long)t.tv_nsec / 1000000ull;
}

static void copy_name(char *out, const char *in)
{
	snprintf(out, NAME_MAX_LEN, "%s", in);
}

/* The name in the file: one line of [A-Za-z0-9_:=,.-]; anything else is the fallback. */
static void read_wanted(Switch *s, char *out)
{
	char line[NAME_MAX_LEN] = "";
	FILE *f = fopen(s->select, "re");
	if (f) {
		if (!fgets(line, sizeof(line), f))
			line[0] = 0;
		fclose(f);
	}
	line[strcspn(line, "\r\n")] = 0;
	bool ok = line[0] != 0;
	for (const char *p = line; *p && ok; p++)
		ok = (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') ||
		     strchr("_:=,.-", *p) != NULL;
	copy_name(out, ok ? line : s->fallback);
}

static int open_slave(Switch *s, const char *name, snd_pcm_t **out, snd_pcm_uframes_t *buffer)
{
	snd_pcm_t *pcm;
	int err = snd_pcm_open(&pcm, name, SND_PCM_STREAM_PLAYBACK, SND_PCM_NONBLOCK);
	if (err < 0)
		return err;
	unsigned int latency = (unsigned int)((unsigned long long)s->io.buffer_size * 1000000ull / s->io.rate);
	err = snd_pcm_set_params(pcm, s->io.format, SND_PCM_ACCESS_RW_INTERLEAVED, s->io.channels, s->io.rate, 1, latency);
	snd_pcm_uframes_t size = 0, period = 0;
	if (err >= 0)
		err = snd_pcm_get_params(pcm, &size, &period);
	if (err >= 0) {
		/* A slave starts after one period: a switch in the middle of a stream sounds at once. */
		snd_pcm_sw_params_t *sw;
		snd_pcm_sw_params_alloca(&sw);
		err = snd_pcm_sw_params_current(pcm, sw);
		if (err >= 0)
			err = snd_pcm_sw_params_set_start_threshold(pcm, sw, period ? period : 1);
		if (err >= 0)
			err = snd_pcm_sw_params(pcm, sw);
	}
	if (err >= 0)
		err = snd_pcm_prepare(pcm);
	if (err < 0) {
		snd_pcm_close(pcm);
		return err;
	}
	*out = pcm;
	*buffer = size;
	return 0;
}

/* The slave NAME instead of the one open now. Another output opens before the old one closes, which
   stays when the new one cannot open; the same one again (the jack changed its channels) is closed
   first, as its device takes one stream only, and the fallback serves if it does not open again. */
static int reopen(Switch *s, const char *name)
{
	snd_pcm_t *pcm;
	snd_pcm_uframes_t buffer;
	if (s->slave && !strcmp(name, s->current)) {
		snd_pcm_drop(s->slave);
		snd_pcm_close(s->slave);
		s->slave = NULL;
		int err = open_slave(s, name, &pcm, &buffer);
		if (err < 0 && strcmp(name, s->fallback)) {
			if (open_slave(s, s->fallback, &pcm, &buffer) >= 0) {
				s->slave = pcm;
				s->slave_buffer = buffer;
				copy_name(s->current, s->fallback);
			}
			return err;
		}
		if (err < 0)
			return err;
		s->slave = pcm;
		s->slave_buffer = buffer;
		return 0;
	}
	int err = open_slave(s, name, &pcm, &buffer);
	if (err < 0)
		return err;
	if (s->slave) {
		snd_pcm_drop(s->slave);
		snd_pcm_close(s->slave);
	}
	s->slave = pcm;
	s->slave_buffer = buffer;
	copy_name(s->current, name);
	return 0;
}

static void maybe_switch(Switch *s)
{
	unsigned long long t = now_ms();
	if (t < s->next_check)
		return;
	s->next_check = t + SWITCH_CHECK_MS;
	struct stat st;
	bool there = stat(s->select, &st) == 0;
	if (!there)
		memset(&st, 0, sizeof(st));
	if (!s->seen_valid || st.st_ino != s->seen.st_ino || st.st_size != s->seen.st_size ||
	    st.st_mtim.tv_sec != s->seen.st_mtim.tv_sec || st.st_mtim.tv_nsec != s->seen.st_mtim.tv_nsec) {
		/* a change of the file, even to the same name, opens the output anew (sound.py writes it
		   again when the jack changes the phone's channels) */
		s->force = s->seen_valid;
		s->seen = st;
		s->seen_valid = true;
		read_wanted(s, s->wanted);
		s->retry_at = 0;
	}
	if (!s->slave || (!s->force && !strcmp(s->wanted, s->current)) || t < s->retry_at)
		return;
	if (reopen(s, s->wanted) < 0) {
		s->retry_at = t + SWITCH_RETRY_MS;
		return;
	}
	s->force = false;
}

static int sw_hw_params(snd_pcm_ioplug_t *io, snd_pcm_hw_params_t *params)
{
	Switch *s = io->private_data;
	(void)params;
	if (s->slave) {
		snd_pcm_close(s->slave);
		s->slave = NULL;
	}
	s->seen_valid = false;
	s->next_check = 0;
	maybe_switch(s);
	int err = open_slave(s, s->wanted, &s->slave, &s->slave_buffer);
	if (err >= 0) {
		copy_name(s->current, s->wanted);
		return 0;
	}
	if (strcmp(s->wanted, s->fallback)) {
		s->retry_at = now_ms() + SWITCH_RETRY_MS;
		err = open_slave(s, s->fallback, &s->slave, &s->slave_buffer);
		if (err >= 0)
			copy_name(s->current, s->fallback);
	}
	return err;
}

static int sw_hw_free(snd_pcm_ioplug_t *io)
{
	Switch *s = io->private_data;
	if (s->slave) {
		snd_pcm_close(s->slave);
		s->slave = NULL;
	}
	return 0;
}

static int sw_prepare(snd_pcm_ioplug_t *io)
{
	Switch *s = io->private_data;
	s->written = s->played = 0;
	if (!s->slave)
		return -EBADFD;
	snd_pcm_drop(s->slave);
	return snd_pcm_prepare(s->slave);
}

static int sw_start(snd_pcm_ioplug_t *io)
{
	Switch *s = io->private_data;
	snd_pcm_sframes_t delay = 0;
	if (s->slave && snd_pcm_state(s->slave) == SND_PCM_STATE_PREPARED && snd_pcm_delay(s->slave, &delay) >= 0 && delay > 0)
		snd_pcm_start(s->slave);
	return 0;
}

static int sw_stop(snd_pcm_ioplug_t *io)
{
	Switch *s = io->private_data;
	if (s->slave)
		snd_pcm_drop(s->slave);
	return 0;
}

/* Frames played: what was written less what the slave still holds, and less the room this PCM has
   beyond the slave's (so that the browser never writes more than the slave takes). Never backwards. */
static snd_pcm_sframes_t sw_pointer(snd_pcm_ioplug_t *io)
{
	Switch *s = io->private_data;
	maybe_switch(s);
	if (!s->slave)
		return -EBADFD;
	if (snd_pcm_state(s->slave) == SND_PCM_STATE_XRUN)
		return -EPIPE;
	snd_pcm_sframes_t delay = 0;
	if (snd_pcm_delay(s->slave, &delay) < 0 || delay < 0)
		delay = 0;
	long long extra = (long long)io->buffer_size - (long long)s->slave_buffer;
	if (extra < 0)
		extra = 0;
	long long played = (long long)s->written - (long long)delay - extra;
	if (played > (long long)s->played)
		s->played = (unsigned long long)played;
	return (snd_pcm_sframes_t)(s->played % io->buffer_size);
}

static int sw_delay(snd_pcm_ioplug_t *io, snd_pcm_sframes_t *delayp)
{
	Switch *s = io->private_data;
	snd_pcm_sframes_t delay = 0;
	if (!s->slave || snd_pcm_delay(s->slave, &delay) < 0 || delay < 0)
		delay = 0;
	*delayp = delay;
	return 0;
}

static snd_pcm_sframes_t sw_transfer(snd_pcm_ioplug_t *io, const snd_pcm_channel_area_t *areas,
				     snd_pcm_uframes_t offset, snd_pcm_uframes_t size)
{
	Switch *s = io->private_data;
	maybe_switch(s);
	if (!s->slave)
		return -EBADFD;
	const char *data = (const char *)areas->addr + (areas->first + areas->step * offset) / 8;
	snd_pcm_sframes_t n = snd_pcm_writei(s->slave, data, size);
	if (n == -EPIPE || n == -ESTRPIPE) {
		if (snd_pcm_recover(s->slave, (int)n, 1) >= 0)
			n = snd_pcm_writei(s->slave, data, size);
	}
	if (n == -EAGAIN) {
		/* full and not started yet: start it, the browser writes the rest later */
		if (snd_pcm_state(s->slave) == SND_PCM_STATE_PREPARED)
			snd_pcm_start(s->slave);
		return 0;
	}
	if (n < 0 && strcmp(s->current, s->fallback)) {
		/* the output went away (headphones off or out of reach): the phone takes the sound */
		if (reopen(s, s->fallback) >= 0) {
			s->retry_at = now_ms() + SWITCH_RETRY_MS;
			n = snd_pcm_writei(s->slave, data, size);
			if (n == -EAGAIN)
				return 0;
		}
	}
	if (n < 0)
		return n;
	s->written += (unsigned long long)n;
	return n;
}

static int sw_poll_count(snd_pcm_ioplug_t *io)
{
	Switch *s = io->private_data;
	return s->slave ? snd_pcm_poll_descriptors_count(s->slave) : 1;
}

static int sw_poll_descriptors(snd_pcm_ioplug_t *io, struct pollfd *pfd, unsigned int space)
{
	Switch *s = io->private_data;
	if (s->slave)
		return snd_pcm_poll_descriptors(s->slave, pfd, space);
	if (space < 1)
		return 0;
	pfd->fd = s->event_fd;
	pfd->events = POLLOUT;
	pfd->revents = 0;
	return 1;
}

static int sw_poll_revents(snd_pcm_ioplug_t *io, struct pollfd *pfd, unsigned int nfds, unsigned short *revents)
{
	Switch *s = io->private_data;
	if (s->slave)
		return snd_pcm_poll_descriptors_revents(s->slave, pfd, nfds, revents);
	*revents = nfds && (pfd[0].revents & POLLOUT) ? POLLOUT : 0;
	return 0;
}

static int sw_close(snd_pcm_ioplug_t *io)
{
	Switch *s = io->private_data;
	if (s->slave)
		snd_pcm_close(s->slave);
	if (s->event_fd >= 0)
		close(s->event_fd);
	free(s->select);
	free(s->fallback);
	free(s);
	return 0;
}

static const snd_pcm_ioplug_callback_t callbacks = {
	.start = sw_start,
	.stop = sw_stop,
	.pointer = sw_pointer,
	.transfer = sw_transfer,
	.close = sw_close,
	.hw_params = sw_hw_params,
	.hw_free = sw_hw_free,
	.prepare = sw_prepare,
	.delay = sw_delay,
	.poll_descriptors_count = sw_poll_count,
	.poll_descriptors = sw_poll_descriptors,
	.poll_revents = sw_poll_revents,
};

SND_PCM_PLUGIN_DEFINE_FUNC(a22x_switch)
{
	snd_config_iterator_t i, next;
	const char *select = NULL, *fallback = NULL;
	(void)root;
	snd_config_for_each(i, next, conf) {
		snd_config_t *n = snd_config_iterator_entry(i);
		const char *id;
		if (snd_config_get_id(n, &id) < 0)
			continue;
		if (!strcmp(id, "comment") || !strcmp(id, "type") || !strcmp(id, "hint"))
			continue;
		if (!strcmp(id, "select")) {
			if (snd_config_get_string(n, &select) < 0)
				return -EINVAL;
			continue;
		}
		if (!strcmp(id, "fallback")) {
			if (snd_config_get_string(n, &fallback) < 0)
				return -EINVAL;
			continue;
		}
		SNDERR("Unknown field %s", id);
		return -EINVAL;
	}
	if (!select || !fallback || strlen(fallback) >= NAME_MAX_LEN) {
		SNDERR("a22x_switch needs select and fallback");
		return -EINVAL;
	}
	if (stream != SND_PCM_STREAM_PLAYBACK)
		return -EINVAL;
	Switch *s = calloc(1, sizeof(*s));
	if (!s)
		return -ENOMEM;
	s->select = strdup(select);
	s->fallback = strdup(fallback);
	s->event_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (!s->select || !s->fallback || s->event_fd < 0) {
		int err = s->event_fd < 0 ? -errno : -ENOMEM;
		if (s->event_fd >= 0)
			close(s->event_fd);
		free(s->select);
		free(s->fallback);
		free(s);
		return err;
	}
	copy_name(s->wanted, s->fallback);
	s->io.version = SND_PCM_IOPLUG_VERSION;
	s->io.name = "A22x sound output";
	s->io.callback = &callbacks;
	s->io.private_data = s;
	s->io.poll_fd = s->event_fd;
	s->io.poll_events = POLLOUT;
	s->io.mmap_rw = 0;
	int err = snd_pcm_ioplug_create(&s->io, name, stream, mode);
	if (err < 0) {
		close(s->event_fd);
		free(s->select);
		free(s->fallback);
		free(s);
		return err;
	}
	static const unsigned int access[] = {SND_PCM_ACCESS_RW_INTERLEAVED};
	static const unsigned int formats[] = {SND_PCM_FORMAT_S16_LE, SND_PCM_FORMAT_S32_LE, SND_PCM_FORMAT_FLOAT_LE,
					       SND_PCM_FORMAT_S24_LE, SND_PCM_FORMAT_U8};
	if ((err = snd_pcm_ioplug_set_param_list(&s->io, SND_PCM_IOPLUG_HW_ACCESS, 1, access)) < 0 ||
	    (err = snd_pcm_ioplug_set_param_list(&s->io, SND_PCM_IOPLUG_HW_FORMAT, sizeof(formats) / sizeof(formats[0]), formats)) < 0 ||
	    (err = snd_pcm_ioplug_set_param_minmax(&s->io, SND_PCM_IOPLUG_HW_CHANNELS, 1, 8)) < 0 ||
	    (err = snd_pcm_ioplug_set_param_minmax(&s->io, SND_PCM_IOPLUG_HW_RATE, 8000, 192000)) < 0 ||
	    (err = snd_pcm_ioplug_set_param_minmax(&s->io, SND_PCM_IOPLUG_HW_PERIOD_BYTES, 256, 1 << 20)) < 0 ||
	    (err = snd_pcm_ioplug_set_param_minmax(&s->io, SND_PCM_IOPLUG_HW_PERIODS, 2, 64)) < 0 ||
	    (err = snd_pcm_ioplug_set_param_minmax(&s->io, SND_PCM_IOPLUG_HW_BUFFER_BYTES, 1024, 4 << 20)) < 0) {
		snd_pcm_ioplug_delete(&s->io);
		return err;
	}
	*pcmp = s->io.pcm;
	return 0;
}

SND_PCM_PLUGIN_SYMBOL(a22x_switch);
