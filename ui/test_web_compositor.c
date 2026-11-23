/* Host test of the browser compositor (2026-11-20): a Wayland client that draws numbered frames
 * into shared-memory buffers, and a stand-in for the native UI that takes the compositor's frame
 * messages like web_ui.h does (F0/F1, the previous slot given back with A0/A1). It checks that
 * every shown slot holds a frame that was really committed, that frames keep coming at the
 * compositor's 90 Hz, and that with a frame socket of its own nothing travels on the control
 * socket. Usage: test-web-compositor COMPOSITOR (direct|relay) */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <wayland-client.h>
#include "xdg-shell-client-protocol.h"
#include "presentation-time-client-protocol.h"

enum { WIDTH = 1080, HEIGHT = 2058, BYTES = WIDTH * HEIGHT * 4, SLOT = 1080 * 2400, BUFFERS = 3, SECONDS = 2 };

struct client {
    struct wl_compositor *compositor;
    struct wl_shm *shm;
    struct xdg_wm_base *shell;
    struct wl_surface *surface;
    struct wl_buffer *buffers[BUFFERS];
    uint32_t *pixels[BUFFERS];
    bool busy[BUFFERS], configured, callback_done;
    uint32_t committed;   /* number of the last committed frame */
    struct wp_presentation *presentation;
    int presented, discarded, bad_refresh;
};

/* Presentation feedback (2026-11-21): every frame is answered once, presented at 90 Hz or discarded. */
static void fb_sync(void *d, struct wp_presentation_feedback *f, struct wl_output *o) { (void)d; (void)f; (void)o; }
static void fb_presented(void *data, struct wp_presentation_feedback *f, uint32_t sh, uint32_t sl, uint32_t ns,
                         uint32_t refresh, uint32_t qh, uint32_t ql, uint32_t flags) {
    struct client *c = data;
    (void)sh; (void)sl; (void)ns; (void)qh; (void)ql; (void)flags;
    c->presented++;
    if (refresh != 1000000000u / 90u) c->bad_refresh++;
    wp_presentation_feedback_destroy(f);
}
static void fb_discarded(void *data, struct wp_presentation_feedback *f) {
    struct client *c = data;
    c->discarded++;
    wp_presentation_feedback_destroy(f);
}
static const struct wp_presentation_feedback_listener feedback_listener = {
    .sync_output = fb_sync, .presented = fb_presented, .discarded = fb_discarded };

static uint64_t now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000u + (uint64_t)t.tv_nsec;
}

static void fail(const char *what) { fprintf(stderr, "FAIL: %s\n", what); exit(1); }

static void buffer_release(void *data, struct wl_buffer *buffer) {
    struct client *c = data;
    for (int i = 0; i < BUFFERS; i++) if (c->buffers[i] == buffer) c->busy[i] = false;
}
static const struct wl_buffer_listener buffer_listener = { .release = buffer_release };

static void ping(void *data, struct xdg_wm_base *shell, uint32_t serial) { (void)data; xdg_wm_base_pong(shell, serial); }
static const struct xdg_wm_base_listener shell_listener = { .ping = ping };

static void xdg_configure(void *data, struct xdg_surface *xdg, uint32_t serial) {
    struct client *c = data;
    xdg_surface_ack_configure(xdg, serial);
    c->configured = true;
}
static const struct xdg_surface_listener xdg_listener = { .configure = xdg_configure };

static void top_configure(void *d, struct xdg_toplevel *t, int32_t w, int32_t h, struct wl_array *s) { (void)d; (void)t; (void)w; (void)h; (void)s; }
static void top_close(void *d, struct xdg_toplevel *t) { (void)d; (void)t; }
static void top_bounds(void *d, struct xdg_toplevel *t, int32_t w, int32_t h) { (void)d; (void)t; (void)w; (void)h; }
static void top_caps(void *d, struct xdg_toplevel *t, struct wl_array *a) { (void)d; (void)t; (void)a; }
static const struct xdg_toplevel_listener top_listener = {
    .configure = top_configure, .close = top_close, .configure_bounds = top_bounds, .wm_capabilities = top_caps };

static void global(void *data, struct wl_registry *registry, uint32_t name, const char *interface, uint32_t version) {
    struct client *c = data;
    (void)version;
    if (!strcmp(interface, wl_compositor_interface.name))
        c->compositor = wl_registry_bind(registry, name, &wl_compositor_interface, 4);
    else if (!strcmp(interface, wp_presentation_interface.name))
        c->presentation = wl_registry_bind(registry, name, &wp_presentation_interface, 1);
    else if (!strcmp(interface, wl_shm_interface.name))
        c->shm = wl_registry_bind(registry, name, &wl_shm_interface, 1);
    else if (!strcmp(interface, xdg_wm_base_interface.name)) {
        c->shell = wl_registry_bind(registry, name, &xdg_wm_base_interface, 1);
        xdg_wm_base_add_listener(c->shell, &shell_listener, c);
    }
}
static void global_remove(void *d, struct wl_registry *r, uint32_t n) { (void)d; (void)r; (void)n; }
static const struct wl_registry_listener registry_listener = { .global = global, .global_remove = global_remove };

static void frame_done(void *data, struct wl_callback *callback, uint32_t time) {
    (void)time;
    ((struct client *)data)->callback_done = true;
    wl_callback_destroy(callback);
}
static const struct wl_callback_listener frame_listener = { .done = frame_done };

/* The fake native UI: the slot it shows, where acknowledgements go, what it saw. */
struct ui {
    int frames_fd, control_fd, slot, frames, stray, wrong;
    uint32_t *map, newest_seen;
};

static void ui_take(struct ui *u, int fd, struct client *c) {
    char msg[32];
    ssize_t n;
    while ((n = recv(fd, msg, sizeof(msg) - 1, MSG_DONTWAIT)) > 0) {
        if (fd == u->control_fd && u->frames_fd != u->control_fd) { u->stray++; continue; }
        msg[n] = 0;
        int fw = 0, fh = 0;
        /* F<slot>:<w>x<h> (2026-11-20: frames carry their size, for the full screen of a video). */
        if (n < 3 || msg[0] != 'F' || msg[1] < '0' || msg[1] > '1' || sscanf(msg + 2, ":%dx%d", &fw, &fh) != 2 ||
            fw != WIDTH || fh != HEIGHT) fail("unexpected frame message");
        int next = msg[1] - '0';
        if (u->slot >= 0 && u->slot != next) {
            const char release[] = {'A', (char)('0' + u->slot)};
            if (send(u->frames_fd, release, 2, MSG_NOSIGNAL) != 2) fail("ack");
        }
        u->slot = next;
        uint32_t number = u->map[(size_t)next * SLOT];
        uint32_t last = u->map[(size_t)next * SLOT + (size_t)(HEIGHT - 1) * WIDTH + WIDTH - 1];
        /* Torn or stale: the frame's first and last pixels carry the same number, not newer than committed. */
        if (number != last || number > c->committed || number < u->newest_seen) u->wrong++;
        if (number > u->newest_seen) u->newest_seen = number;
        u->frames++;
    }
    if (n == 0) fail("compositor closed the frame socket");
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: %s COMPOSITOR direct|relay\n", argv[0]); return 2; }
    bool direct = !strcmp(argv[2], "direct");
    char runtime[] = "/tmp/web-compositor-test-XXXXXX";
    if (!mkdtemp(runtime)) fail("runtime dir");
    setenv("XDG_RUNTIME_DIR", runtime, 1);
    int frame = memfd_create("browser-frame", MFD_CLOEXEC);
    if (frame < 0 || ftruncate(frame, 2 * (off_t)SLOT * 4)) fail("frame memfd");
    int control[2], frames[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, control) ||
        socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, frames)) fail("sockets");
    pid_t pid = fork();
    if (pid == 0) {
        /* Out of the way first: a descriptor can already be 5, 7 or 8. */
        int f = fcntl(frame, F_DUPFD_CLOEXEC, 20), k = fcntl(control[1], F_DUPFD_CLOEXEC, 20);
        int s = fcntl(frames[1], F_DUPFD_CLOEXEC, 20);
        if (f < 0 || k < 0 || s < 0 || dup2(f, 5) < 0 || dup2(k, 7) < 0 || (direct && dup2(s, 8) < 0)) _exit(126);
        if (direct) execl(argv[1], argv[1], "7", "8", (char *)NULL);
        else execl(argv[1], argv[1], "7", (char *)NULL);
        _exit(127);
    }
    close(control[1]); close(frames[1]);
    char started = 0;
    struct pollfd wait_start = { .fd = control[0], .events = POLLIN };
    if (poll(&wait_start, 1, 5000) != 1 || recv(control[0], &started, 1, 0) != 1 || started != 'S') fail("compositor did not start");

    struct ui u = { .frames_fd = direct ? frames[0] : control[0], .control_fd = control[0], .slot = -1 };
    u.map = mmap(NULL, 2 * (size_t)SLOT * 4, PROT_READ, MAP_SHARED, frame, 0);
    if (u.map == MAP_FAILED) fail("map");

    struct client c = {0};
    struct wl_display *display = wl_display_connect("recovery-wayland");
    if (!display) fail("connect");
    struct wl_registry *registry = wl_display_get_registry(display);
    wl_registry_add_listener(registry, &registry_listener, &c);
    wl_display_roundtrip(display);
    if (!c.compositor || !c.shm || !c.shell) fail("globals");
    int pool_fd = memfd_create("client-pool", MFD_CLOEXEC);
    if (pool_fd < 0 || ftruncate(pool_fd, (off_t)BUFFERS * BYTES)) fail("pool");
    uint32_t *pool = mmap(NULL, (size_t)BUFFERS * BYTES, PROT_READ | PROT_WRITE, MAP_SHARED, pool_fd, 0);
    if (pool == MAP_FAILED) fail("pool map");
    struct wl_shm_pool *shm_pool = wl_shm_create_pool(c.shm, pool_fd, BUFFERS * BYTES);
    for (int i = 0; i < BUFFERS; i++) {
        c.buffers[i] = wl_shm_pool_create_buffer(shm_pool, i * BYTES, WIDTH, HEIGHT, WIDTH * 4, WL_SHM_FORMAT_XRGB8888);
        wl_buffer_add_listener(c.buffers[i], &buffer_listener, &c);
        c.pixels[i] = pool + (size_t)i * WIDTH * HEIGHT;
    }
    c.surface = wl_compositor_create_surface(c.compositor);
    struct xdg_surface *xdg = xdg_wm_base_get_xdg_surface(c.shell, c.surface);
    xdg_surface_add_listener(xdg, &xdg_listener, &c);
    struct xdg_toplevel *top = xdg_surface_get_toplevel(xdg);
    xdg_toplevel_add_listener(top, &top_listener, &c);
    wl_surface_commit(c.surface);
    while (!c.configured) if (wl_display_dispatch(display) < 0) fail("configure");

    c.callback_done = true;
    uint64_t start = now_ns(), end = start + (uint64_t)SECONDS * 1000000000u;
    int committed = 0;
    while (now_ns() < end) {
        if (c.callback_done) {
            int free_buffer = -1;
            for (int i = 0; i < BUFFERS; i++) if (!c.busy[i]) { free_buffer = i; break; }
            if (free_buffer >= 0) {
                uint32_t number = c.committed + 1;
                uint32_t *p = c.pixels[free_buffer];
                for (size_t k = 0; k < (size_t)WIDTH * HEIGHT; k += 997) p[k] = 0x00336699u;
                p[0] = number;
                p[(size_t)(HEIGHT - 1) * WIDTH + WIDTH - 1] = number;
                c.busy[free_buffer] = true;
                c.callback_done = false;
                wl_surface_attach(c.surface, c.buffers[free_buffer], 0, 0);
                wl_surface_damage_buffer(c.surface, 0, 0, WIDTH, HEIGHT);
                struct wl_callback *callback = wl_surface_frame(c.surface);
                wl_callback_add_listener(callback, &frame_listener, &c);
                if (c.presentation)
                    wp_presentation_feedback_add_listener(wp_presentation_feedback(c.presentation, c.surface), &feedback_listener, &c);
                c.committed = number;
                wl_surface_commit(c.surface);
                committed++;
            }
        }
        wl_display_flush(display);
        struct pollfd p[3] = {
            { .fd = wl_display_get_fd(display), .events = POLLIN },
            { .fd = u.frames_fd, .events = POLLIN },
            { .fd = control[0], .events = POLLIN },
        };
        if (wl_display_prepare_read(display) != 0) { wl_display_dispatch_pending(display); continue; }
        if (poll(p, direct ? 3 : 2, 20) < 0 && errno != EINTR) fail("poll");
        if (p[0].revents & POLLIN) wl_display_read_events(display); else wl_display_cancel_read(display);
        wl_display_dispatch_pending(display);
        if (p[1].revents & POLLIN) ui_take(&u, u.frames_fd, &c);
        if (direct && (p[2].revents & POLLIN)) ui_take(&u, control[0], &c);
        if ((p[1].revents | p[2].revents) & (POLLHUP | POLLERR)) fail("hangup");
    }
    double seconds = (double)(now_ns() - start) / 1e9;
    printf("{\"mode\":\"%s\",\"committed\":%d,\"shown\":%d,\"fps\":%.1f,\"wrong\":%d,\"stray_on_control\":%d,"
           "\"presented\":%d,\"discarded\":%d}\n",
           argv[2], committed, u.frames, u.frames / seconds, u.wrong, u.stray, c.presented, c.discarded);
    if (!c.presentation || c.bad_refresh || c.presented < 60 * SECONDS || c.presented + c.discarded + 2 < committed)
        fail("presentation feedback");
    wl_display_disconnect(display);
    kill(pid, SIGTERM);
    waitpid(pid, NULL, 0);
    rmdir(runtime);
    if (u.wrong || u.stray || u.frames < 60 * SECONDS) fail("frames");
    return 0;
}
