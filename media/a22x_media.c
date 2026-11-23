// SPDX-License-Identifier: MIT
/*
 * a22x-media: the recovery's player of local music and video (2026-11-22, the owner).
 *
 * One file plays at a time; the interface keeps the queue. FFmpeg (Alpine's libraries, in the media
 * runtime the recovery downloads like the browser's) reads and decodes it. Sound goes to ALSA, to the
 * device the interface names: the recovery's speaker ("default", sound.py's configuration) or a
 * Bluetooth device through BlueALSA ("bluealsa:DEV=..."), at 48 kHz in stereo, with the player's own
 * volume. Pictures are scaled to the size the interface asks for (a window over the interface, or the
 * whole panel) and written to a shared memory file the interface maps; the sound's clock decides when
 * each shows. The player runs at a low priority: backups, restores and flashing come first.
 *
 * Control, one line each on the socket (the interface is the only client):
 *   open PATH            play PATH from its start (paused when "open-paused")
 *   openfd               play the file whose descriptor came with this line (SCM_RIGHTS); the interface
 *                        opens it outside, so no card is mounted where the player runs ("openfd-paused")
 *   play | pause | stop
 *   seek MS              go to MS
 *   volume PERCENT       0..100, the player's own gain
 *   output DEVICE        ALSA device for the sound; the stream moves there at once
 *   video W H            the size pictures are scaled to (0 0: no pictures, sound only)
 *   quit
 * Reports, one line each:
 *   state playing=0|1 position=MS duration=MS video=0|1 width=W height=H output=DEVICE
 *   title TEXT / artist TEXT
 *   frame SEQ W H        a picture is in the shared memory (sent once with the descriptor: "shm")
 *   ended | error TEXT
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include <alsa/asoundlib.h>
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libavutil/channel_layout.h>
#include <libavutil/imgutils.h>
#include <libavutil/opt.h>
#include <libswresample/swresample.h>
#include <libswscale/swscale.h>

#define RATE 48000
#define SHM_BYTES (1080u * 2408u * 4u + 64u)
#define LINE_MAX_BYTES 4200

struct shm_head { uint32_t seq, width, height, stride; };

static int client = -1;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t wake = PTHREAD_COND_INITIALIZER;

/* What the interface asked for; the play thread follows it. */
static char want_path[4096], want_output[256] = "default";
static bool want_open, want_playing, want_stop, want_quit;
static int64_t want_seek = -1;
static atomic_int volume = 100;
static atomic_int video_w, video_h;
static atomic_bool output_changed;

static int shm_fd = -1;
static int received_fd = -1, playing_fd = -1;   /* a descriptor sent with the last line; the file now open */
static uint8_t *shm;

static void say(const char *fmt, ...)
{
	char line[LINE_MAX_BYTES];
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(line, sizeof(line) - 1, fmt, ap);
	va_end(ap);
	if (n < 0)
		return;
	if (n > (int)sizeof(line) - 2)
		n = sizeof(line) - 2;
	line[n++] = '\n';
	pthread_mutex_lock(&lock);
	if (client >= 0 && send(client, line, (size_t)n, MSG_NOSIGNAL | MSG_DONTWAIT) < 0 && errno != EAGAIN)
		client = -1;
	pthread_mutex_unlock(&lock);
}

static uint64_t now_us(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (uint64_t)t.tv_sec * 1000000u + (uint64_t)t.tv_nsec / 1000u;
}

/* --- sound -------------------------------------------------------------------------------------------- */
static snd_pcm_t *pcm;
static char pcm_name[256];

static void pcm_close(void)
{
	if (pcm) {
		snd_pcm_drop(pcm);
		snd_pcm_close(pcm);
		pcm = NULL;
	}
}

static bool pcm_open(const char *name)
{
	pcm_close();
	if (snd_pcm_open(&pcm, name, SND_PCM_STREAM_PLAYBACK, 0) < 0) {
		pcm = NULL;
		say("error Cannot open the sound output %s", name);
		return false;
	}
	/* A long buffer: the decoder may wait behind a backup for a while without a gap in the sound. */
	if (snd_pcm_set_params(pcm, SND_PCM_FORMAT_S16_LE, SND_PCM_ACCESS_RW_INTERLEAVED, 2, RATE, 1, 400000) < 0) {
		snd_pcm_close(pcm);
		pcm = NULL;
		say("error The sound output %s refuses 48 kHz stereo", name);
		return false;
	}
	snprintf(pcm_name, sizeof(pcm_name), "%s", name);
	return true;
}

static int64_t pcm_delay_us(void)
{
	snd_pcm_sframes_t delay = 0;
	if (!pcm || snd_pcm_delay(pcm, &delay) < 0 || delay < 0)
		return 0;
	return (int64_t)delay * 1000000 / RATE;
}

static void pcm_write(int16_t *samples, int frames)
{
	int gain = atomic_load(&volume);
	if (gain < 100)
		for (int n = 0; n < frames * 2; n++)
			samples[n] = (int16_t)(samples[n] * gain / 100);
	while (pcm && frames > 0) {
		snd_pcm_sframes_t done = snd_pcm_writei(pcm, samples, (snd_pcm_uframes_t)frames);
		if (done == -EPIPE || done == -ESTRPIPE || done == -EINTR) {
			snd_pcm_recover(pcm, (int)done, 1);
			continue;
		}
		if (done < 0) {
			say("error The sound output stopped: %s", snd_strerror((int)done));
			pcm_close();
			return;
		}
		samples += done * 2;
		frames -= (int)done;
	}
}

/* --- one file ---------------------------------------------------------------------------------------- */
struct play {
	AVFormatContext *fmt;
	AVCodecContext *audio, *video;
	int audio_index, video_index;
	SwrContext *swr;
	struct SwsContext *sws;
	int sws_w, sws_h, sws_src_w, sws_src_h, sws_src_fmt;
	AVFrame *frame;
	AVPacket *packet;
	int64_t duration_ms;
	int64_t clock_us;          /* the position of the sound written last, in the file's time */
	uint64_t wall_base;        /* without sound: when position 0 would have been */
	uint32_t seq;
	bool playing;
};

static void play_close(struct play *p)
{
	avcodec_free_context(&p->audio);
	avcodec_free_context(&p->video);
	swr_free(&p->swr);
	sws_freeContext(p->sws);
	av_frame_free(&p->frame);
	av_packet_free(&p->packet);
	avformat_close_input(&p->fmt);
	memset(p, 0, sizeof(*p));
	p->audio_index = p->video_index = -1;
}

static AVCodecContext *open_stream(AVFormatContext *fmt, int index)
{
	const AVCodec *codec = avcodec_find_decoder(fmt->streams[index]->codecpar->codec_id);
	if (!codec)
		return NULL;
	AVCodecContext *ctx = avcodec_alloc_context3(codec);
	if (!ctx || avcodec_parameters_to_context(ctx, fmt->streams[index]->codecpar) < 0) {
		avcodec_free_context(&ctx);
		return NULL;
	}
	ctx->thread_count = 4;
	if (avcodec_open2(ctx, codec, NULL) < 0)
		avcodec_free_context(&ctx);
	return ctx;
}

static void tag(AVFormatContext *fmt, const char *key, const char *report)
{
	AVDictionaryEntry *e = av_dict_get(fmt->metadata, key, NULL, 0);
	if (e && e->value[0])
		say("%s %.1000s", report, e->value);
}

static bool play_open(struct play *p, const char *path)
{
	play_close(p);
	if (avformat_open_input(&p->fmt, path, NULL, NULL) < 0 || avformat_find_stream_info(p->fmt, NULL) < 0) {
		say("error This file cannot be read as music or video");
		play_close(p);
		return false;
	}
	p->audio_index = av_find_best_stream(p->fmt, AVMEDIA_TYPE_AUDIO, -1, -1, NULL, 0);
	p->video_index = av_find_best_stream(p->fmt, AVMEDIA_TYPE_VIDEO, -1, -1, NULL, 0);
	/* A cover picture inside a music file is no video. */
	if (p->video_index >= 0 && (p->fmt->streams[p->video_index]->disposition & AV_DISPOSITION_ATTACHED_PIC))
		p->video_index = -1;
	if (p->audio_index >= 0 && !(p->audio = open_stream(p->fmt, p->audio_index)))
		p->audio_index = -1;
	if (p->video_index >= 0 && !(p->video = open_stream(p->fmt, p->video_index)))
		p->video_index = -1;
	if (p->audio_index < 0 && p->video_index < 0) {
		say("error No sound or picture this player can decode");
		play_close(p);
		return false;
	}
	if (p->audio) {
		AVChannelLayout stereo = AV_CHANNEL_LAYOUT_STEREO;
		if (swr_alloc_set_opts2(&p->swr, &stereo, AV_SAMPLE_FMT_S16, RATE, &p->audio->ch_layout,
					p->audio->sample_fmt, p->audio->sample_rate, 0, NULL) < 0 || swr_init(p->swr) < 0) {
			say("error The sound of this file cannot be converted");
			play_close(p);
			return false;
		}
	}
	p->frame = av_frame_alloc();
	p->packet = av_packet_alloc();
	p->duration_ms = p->fmt->duration > 0 ? p->fmt->duration / 1000 : 0;
	tag(p->fmt, "title", "title");
	tag(p->fmt, "artist", "artist");
	return true;
}

static int64_t stream_us(const struct play *p, int index, int64_t pts)
{
	AVRational base = p->fmt->streams[index]->time_base;
	if (pts == AV_NOPTS_VALUE)
		return -1;
	int64_t start = p->fmt->start_time != AV_NOPTS_VALUE ? p->fmt->start_time : 0;
	return av_rescale_q(pts, base, AV_TIME_BASE_Q) - start;
}

/* The position now: the sound written, less what still waits in the device; or the wall clock. */
static int64_t position_us(const struct play *p)
{
	if (p->audio && pcm)
		return p->clock_us - pcm_delay_us();
	return p->playing ? (int64_t)(now_us() - p->wall_base) : p->clock_us;
}

static void report(const struct play *p)
{
	int64_t pos = position_us(p);
	say("state playing=%d position=%lld duration=%lld video=%d width=%d height=%d output=%s", p->playing,
	    (long long)(pos > 0 ? pos / 1000 : 0), (long long)p->duration_ms, p->video != NULL,
	    p->video ? p->video->width : 0, p->video ? p->video->height : 0, pcm_name[0] ? pcm_name : want_output);
}

static void show_picture(struct play *p)
{
	int w = atomic_load(&video_w), h = atomic_load(&video_h);
	if (w <= 0 || h <= 0 || !shm)
		return;
	if ((uint64_t)w * (uint64_t)h * 4u + sizeof(struct shm_head) > SHM_BYTES)
		return;
	AVFrame *f = p->frame;
	if (!p->sws || p->sws_w != w || p->sws_h != h || p->sws_src_w != f->width || p->sws_src_h != f->height ||
	    p->sws_src_fmt != f->format) {
		sws_freeContext(p->sws);
		p->sws = sws_getContext(f->width, f->height, (enum AVPixelFormat)f->format, w, h, AV_PIX_FMT_BGRA,
					SWS_BILINEAR, NULL, NULL, NULL);
		p->sws_w = w;
		p->sws_h = h;
		p->sws_src_w = f->width;
		p->sws_src_h = f->height;
		p->sws_src_fmt = f->format;
		if (!p->sws)
			return;
	}
	struct shm_head *head = (struct shm_head *)shm;
	uint8_t *dst[4] = { shm + sizeof(*head) };
	int stride[4] = { w * 4 };
	sws_scale(p->sws, (const uint8_t *const *)f->data, f->linesize, 0, f->height, dst, stride);
	head->width = (uint32_t)w;
	head->height = (uint32_t)h;
	head->stride = (uint32_t)w * 4u;
	__atomic_store_n(&head->seq, ++p->seq, __ATOMIC_RELEASE);
	say("frame %u %d %d", p->seq, w, h);
}

static void decode_audio(struct play *p)
{
	if (avcodec_send_packet(p->audio, p->packet) < 0)
		return;
	while (avcodec_receive_frame(p->audio, p->frame) == 0) {
		int64_t at = stream_us(p, p->audio_index, p->frame->best_effort_timestamp);
		int out = swr_get_out_samples(p->swr, p->frame->nb_samples);
		int16_t *buf = malloc((size_t)out * 4u + 64u);
		if (!buf)
			return;
		uint8_t *planes[1] = { (uint8_t *)buf };
		int n = swr_convert(p->swr, planes, out, (const uint8_t **)p->frame->extended_data, p->frame->nb_samples);
		if (n > 0) {
			pcm_write(buf, n);
			if (at >= 0)
				p->clock_us = at + (int64_t)n * 1000000 / RATE;
			else
				p->clock_us += (int64_t)n * 1000000 / RATE;
		}
		free(buf);
	}
}

static void decode_video(struct play *p)
{
	if (avcodec_send_packet(p->video, p->packet) < 0)
		return;
	while (avcodec_receive_frame(p->video, p->frame) == 0) {
		int64_t at = stream_us(p, p->video_index, p->frame->best_effort_timestamp);
		if (!p->audio && at >= 0 && p->playing) {
			/* No sound: the wall clock paces the pictures. */
			int64_t ahead = at - (int64_t)(now_us() - p->wall_base);
			if (ahead > 0 && ahead < 2000000)
				usleep((useconds_t)ahead);
			p->clock_us = at;
		} else if (at >= 0) {
			int64_t ahead = at - position_us(p);
			if (ahead < -120000)
				continue;           /* late: skip, the sound goes on */
			if (ahead > 0 && ahead < 500000)
				usleep((useconds_t)ahead);
		}
		show_picture(p);
	}
}

static void *player(void *unused)
{
	(void)unused;
	struct play p;
	memset(&p, 0, sizeof(p));
	p.audio_index = p.video_index = -1;
	uint64_t last_report = 0;
	for (;;) {
		pthread_mutex_lock(&lock);
		while (!want_quit && !want_open && !want_stop && want_seek < 0 && !atomic_load(&output_changed) &&
		       !(p.fmt && want_playing))
			pthread_cond_wait(&wake, &lock);
		if (want_quit) {
			pthread_mutex_unlock(&lock);
			break;
		}
		bool open = want_open, stop = want_stop, out = atomic_exchange(&output_changed, false);
		char path[4096], device[256];
		snprintf(path, sizeof(path), "%s", want_path);
		snprintf(device, sizeof(device), "%s", want_output);
		int64_t seek = want_seek;
		want_open = want_stop = false;
		want_seek = -1;
		bool playing = want_playing;
		pthread_mutex_unlock(&lock);

		if (stop) {
			play_close(&p);
			pcm_close();
			say("state playing=0 position=0 duration=0 video=0 width=0 height=0 output=%s", device);
			continue;
		}
		if (open) {
			pcm_close();
			if (!play_open(&p, path)) {
				say("ended");
				continue;
			}
			p.clock_us = 0;
			p.wall_base = now_us();
		}
		if (!p.fmt)
			continue;
		if ((out || !pcm) && p.audio && !pcm_open(device)) {
			pthread_mutex_lock(&lock);
			want_playing = false;
			pthread_mutex_unlock(&lock);
			playing = false;
		}
		if (seek >= 0) {
			if (av_seek_frame(p.fmt, -1, seek * 1000 + (p.fmt->start_time != AV_NOPTS_VALUE ? p.fmt->start_time : 0),
					  AVSEEK_FLAG_BACKWARD) >= 0) {
				if (p.audio)
					avcodec_flush_buffers(p.audio);
				if (p.video)
					avcodec_flush_buffers(p.video);
				if (pcm)
					snd_pcm_drop(pcm), snd_pcm_prepare(pcm);
				p.clock_us = seek * 1000;
				p.wall_base = now_us() - (uint64_t)seek * 1000u;
			}
		}
		if (playing != p.playing) {
			if (!playing && pcm)
				snd_pcm_drop(pcm), snd_pcm_prepare(pcm);
			if (playing && !p.audio)
				p.wall_base = now_us() - (uint64_t)(p.clock_us > 0 ? p.clock_us : 0);
			p.playing = playing;
			report(&p);
		}
		if (!p.playing)
			continue;
		/* One packet a turn, so a command waits no longer than one packet's decoding. */
		int got = av_read_frame(p.fmt, p.packet);
		if (got < 0) {
			if (pcm)
				snd_pcm_drain(pcm);
			report(&p);
			say("ended");
			play_close(&p);
			pcm_close();
			pthread_mutex_lock(&lock);
			want_playing = false;
			pthread_mutex_unlock(&lock);
			continue;
		}
		if (p.packet->stream_index == p.audio_index)
			decode_audio(&p);
		else if (p.packet->stream_index == p.video_index)
			decode_video(&p);
		av_packet_unref(p.packet);
		if (now_us() - last_report > 500000) {
			last_report = now_us();
			report(&p);
		}
	}
	play_close(&p);
	pcm_close();
	return NULL;
}

/* --- control ----------------------------------------------------------------------------------------- */
static void send_shm(int fd)
{
	char cmsgbuf[CMSG_SPACE(sizeof(int))];
	char text[] = "shm\n";
	struct iovec io = { text, sizeof(text) - 1 };
	struct msghdr msg = { .msg_iov = &io, .msg_iovlen = 1, .msg_control = cmsgbuf, .msg_controllen = sizeof(cmsgbuf) };
	struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
	c->cmsg_level = SOL_SOCKET;
	c->cmsg_type = SCM_RIGHTS;
	c->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(c), &shm_fd, sizeof(int));
	(void)sendmsg(fd, &msg, MSG_NOSIGNAL);
}

static void command(char *line)
{
	pthread_mutex_lock(&lock);
	if (!strcmp(line, "openfd") || !strcmp(line, "openfd-paused")) {
		if (received_fd >= 0) {
			/* The previous file stays open until this one replaces it: the play thread may still read it. */
			if (playing_fd >= 0)
				close(playing_fd);
			playing_fd = received_fd;
			received_fd = -1;
			snprintf(want_path, sizeof(want_path), "/proc/self/fd/%d", playing_fd);
			want_open = true;
			want_playing = line[6] != '-';
		}
	} else if (!strncmp(line, "open ", 5) || !strncmp(line, "open-paused ", 12)) {
		bool paused = line[4] == '-';
		snprintf(want_path, sizeof(want_path), "%s", line + (paused ? 12 : 5));
		want_open = true;
		want_playing = !paused;
	} else if (!strcmp(line, "play"))
		want_playing = true;
	else if (!strcmp(line, "pause"))
		want_playing = false;
	else if (!strcmp(line, "stop")) {
		want_stop = true;
		want_playing = false;
	} else if (!strncmp(line, "seek ", 5))
		want_seek = strtoll(line + 5, NULL, 10);
	else if (!strncmp(line, "volume ", 7)) {
		int v = atoi(line + 7);
		atomic_store(&volume, v < 0 ? 0 : v > 100 ? 100 : v);
	} else if (!strncmp(line, "output ", 7)) {
		snprintf(want_output, sizeof(want_output), "%s", line + 7);
		atomic_store(&output_changed, true);
	} else if (!strncmp(line, "video ", 6)) {
		int w = 0, h = 0;
		if (sscanf(line + 6, "%d %d", &w, &h) == 2 && w >= 0 && h >= 0 && w <= 2408 && h <= 2408) {
			atomic_store(&video_w, w);
			atomic_store(&video_h, h);
		}
	} else if (!strcmp(line, "quit"))
		want_quit = true;
	pthread_cond_broadcast(&wake);
	pthread_mutex_unlock(&lock);
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "usage: a22x-media SOCKET\n");
		return 2;
	}
	signal(SIGPIPE, SIG_IGN);
	av_log_set_level(AV_LOG_ERROR);
	shm_fd = memfd_create("a22x-media-frames", MFD_CLOEXEC);
	if (shm_fd < 0 || ftruncate(shm_fd, SHM_BYTES) < 0 ||
	    (shm = mmap(NULL, SHM_BYTES, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0)) == MAP_FAILED) {
		perror("a22x-media: frames");
		return 1;
	}
	int server = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", argv[1]);
	unlink(argv[1]);
	if (server < 0 || bind(server, (struct sockaddr *)&addr, sizeof(addr)) < 0 || listen(server, 1) < 0) {
		perror("a22x-media: socket");
		return 1;
	}
	pthread_t thread;
	pthread_create(&thread, NULL, player, NULL);
	char buf[LINE_MAX_BYTES];
	size_t have = 0;
	for (;;) {
		int fd = accept4(server, NULL, NULL, SOCK_CLOEXEC);
		if (fd < 0)
			continue;
		pthread_mutex_lock(&lock);
		if (client >= 0)
			close(client);
		client = fd;
		pthread_mutex_unlock(&lock);
		send_shm(fd);
		have = 0;
		for (;;) {
			char cmsgbuf[CMSG_SPACE(sizeof(int))];
			struct iovec io = { buf + have, sizeof(buf) - 1 - have };
			struct msghdr msg = { .msg_iov = &io, .msg_iovlen = 1, .msg_control = cmsgbuf, .msg_controllen = sizeof(cmsgbuf) };
			ssize_t n = recvmsg(fd, &msg, MSG_CMSG_CLOEXEC);
			if (n <= 0)
				break;
			/* One descriptor at most: the first control message is the only one read (musl's CMSG_NXTHDR
			   trips -Wsign-compare). */
			struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
			if (c && c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS && c->cmsg_len == CMSG_LEN(sizeof(int))) {
				pthread_mutex_lock(&lock);
				if (received_fd >= 0)
					close(received_fd);
				memcpy(&received_fd, CMSG_DATA(c), sizeof(int));
				pthread_mutex_unlock(&lock);
			}
			have += (size_t)n;
			char *start = buf, *end;
			while ((end = memchr(start, '\n', have - (size_t)(start - buf)))) {
				*end = 0;
				command(start);
				start = end + 1;
			}
			have -= (size_t)(start - buf);
			memmove(buf, start, have);
			if (have >= sizeof(buf) - 1)
				have = 0;
			if (want_quit)
				break;
		}
		pthread_mutex_lock(&lock);
		if (client == fd)
			client = -1;
		bool quit = want_quit;
		pthread_mutex_unlock(&lock);
		close(fd);
		if (quit)
			break;
	}
	pthread_join(thread, NULL);
	return 0;
}
