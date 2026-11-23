/* Off-screen Wayland compositor for the recovery browser. The shared frame
 * stays valid until the native UI acknowledges it. The browser sees no DRM master.
 *
 * 2026-11-20 (the owner: about 90 FPS while browsing): a GPU frame is copied as
 * soon as its rendering fence signals, not at the next 90 Hz tick (a frame whose
 * GPU work ended just after a tick waited a whole period, so frames came 11 and
 * 22 ms apart: ~55 FPS). With a second descriptor (argv[2]) the frame messages
 * F/A go straight to the native UI instead of through the Python session. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>
#include <wayland-server.h>
#include "xdg-shell-server-protocol.h"
#include "presentation-time-server-protocol.h"

/* The page's size (WIDTH x HEIGHT) unless the session asks for another (S<w> <h>: a video in full screen,
 * 1080 x 2400 upright or 2400 x 1080 on its side, 2026-11-20). A slot holds the largest. */
enum { WIDTH = 1080, HEIGHT = 2058, SCALE = 3, RATE = 90, MAX_PIXELS = 1080 * 2400, BYTES = MAX_PIXELS * 4 };
static const uint64_t frame_period = 1000000000 / RATE;  /* also the refresh presentation feedback reports */

struct compositor {
    struct wl_display *display;
    struct wl_event_loop *loop;
    struct wl_resource *output;
    struct surface *current;
    struct wl_list surfaces;
    uint32_t *frame;
    int control, frames;   /* frames: where F/A travel (the UI's own socket, or control) */
    unsigned slots, busy;
    uint64_t next_publish, presented;
    int width, height;   /* the size the session asked for */
};

struct surface {
    struct compositor *server;
    struct wl_resource *resource, *xdg, *role, *buffer;
    struct wl_event_source *fence;   /* waits for the GPU to finish the attached buffer */
    struct wl_listener buffer_destroy;
    struct wl_list link, callbacks;
    /* wp_presentation (2026-11-21): asked for the next commit, and for the commit waiting to be shown. */
    struct wl_list feedback_pending, feedback_queued;
    bool configured, attached, queued, popup;
    int32_t popup_width, popup_height;
};

/* Chromium asks for popups (download bubble, <select>, menus). Input reaches
 * the page only through DevTools, so a popup could never be operated here:
 * accept it, configure it and dismiss it at once instead of drawing it. */
struct positioner {
    int32_t width, height;
};

struct frame_callback {
    struct wl_resource *resource;
    struct wl_list link;
};

/* Presentation feedback (2026-11-21): Chromium paces its frames by what this says of each one, the
 * time and the refresh period, 90 Hz here. Without it Chromium kept to its own 60 Hz pace, and with
 * its frame limit switched off instead it drew without pause (two cores busy over a paused video). */
struct feedback {
    struct wl_resource *resource;
    struct wl_list link;
};

static void feedback_destroy(struct wl_resource *res) {
    struct feedback *feedback = wl_resource_get_user_data(res);
    wl_list_remove(&feedback->link);
    free(feedback);
}

static uint64_t monotonic_ns(void);

/* Each feedback of LIST answered and gone: presented as frame SEQ now, or discarded. */
static void feedback_finish(struct wl_list *list, bool shown, uint64_t seq) {
    uint64_t now = monotonic_ns(), seconds = now / 1000000000;
    struct feedback *feedback, *next;
    wl_list_for_each_safe(feedback, next, list, link) {
        if (shown)
            wp_presentation_feedback_send_presented(feedback->resource, (uint32_t)(seconds >> 32), (uint32_t)seconds,
                                                    (uint32_t)(now % 1000000000), (uint32_t)frame_period,
                                                    (uint32_t)(seq >> 32), (uint32_t)seq,
                                                    WP_PRESENTATION_FEEDBACK_KIND_VSYNC);
        else wp_presentation_feedback_send_discarded(feedback->resource);
        wl_resource_destroy(feedback->resource);
    }
}

static void frame_callback_destroy(struct wl_resource *res) {
    struct frame_callback *callback = wl_resource_get_user_data(res);
    wl_list_remove(&callback->link);
    free(callback);
}

static void fence_cancel(struct surface *surface) {
    if (surface->fence) {
        wl_event_source_remove(surface->fence);
        surface->fence = NULL;
    }
}

static void release_buffer(struct surface *surface, bool send_release) {
    fence_cancel(surface);
    if (!surface->buffer) return;
    if (send_release) wl_buffer_send_release(surface->buffer);
    wl_list_remove(&surface->buffer_destroy.link);
    surface->buffer = NULL;
    surface->attached = surface->queued = false;
}

static void buffer_destroyed(struct wl_listener *listener, void *data) {
    (void)data;
    struct surface *surface = wl_container_of(listener, surface, buffer_destroy);
    release_buffer(surface, false);
}

static uint64_t monotonic_ns(void) {
    struct timespec time;
    clock_gettime(CLOCK_MONOTONIC, &time);
    return (uint64_t)time.tv_sec * 1000000000 + time.tv_nsec;
}

static void destroy(struct wl_client *, struct wl_resource *);
#include "web_dmabuf.h"

static void publish_frame(struct compositor *server, struct surface *surface);

/* The GPU finished the buffer: publish it now rather than at the next tick. */
static int fence_signalled(int fd, uint32_t mask, void *data) {
    (void)fd; (void)mask;
    struct surface *surface = data;
    fence_cancel(surface);
    if (surface == surface->server->current && surface->queued) publish_frame(surface->server, surface);
    return 0;
}

static void publish_frame(struct compositor *server, struct surface *surface) {
    unsigned free_slots = ((1U << server->slots) - 1U) & ~server->busy;
    uint64_t now = monotonic_ns();
    if (!surface->queued || !free_slots || now + 500000 < server->next_publish) return;
    unsigned slot = free_slots & 1U ? 0 : 1;
    struct wl_shm_buffer *buffer = wl_shm_buffer_get(surface->buffer);
    int width = 0, height = 0, stride = 0;
    const unsigned char *source = NULL;
    if (buffer) {
        width = wl_shm_buffer_get_width(buffer);
        height = wl_shm_buffer_get_height(buffer);
        stride = wl_shm_buffer_get_stride(buffer);
        uint32_t format = wl_shm_buffer_get_format(buffer);
        if (format == WL_SHM_FORMAT_ARGB8888 || format == WL_SHM_FORMAT_XRGB8888) {
            wl_shm_buffer_begin_access(buffer);
            source = wl_shm_buffer_get_data(buffer);
        }
    } else {
        source = dma_read(surface->buffer, &width, &height, &stride);
        if (!source) {
            /* Still being rendered: wake up when its fence signals (a dma-buf polls
             * readable then). The tick retries anyway if this cannot be watched. */
            int fd = dma_pending_fd(surface->buffer);
            if (fd >= 0 && !surface->fence)
                surface->fence = wl_event_loop_add_fd(server->loop, fd, WL_EVENT_READABLE, fence_signalled, surface);
            return;
        }
    }
    int fw = server->width, fh = server->height;
    if (source && width >= fw && height >= fh && stride >= fw * 4) {
        uint32_t *target = server->frame + slot * MAX_PIXELS;
        if (stride == fw * 4) memcpy(target, source, (size_t)fw * fh * 4);
        else {
            for (int y = 0; y < fh; y++)
                memcpy(target + (size_t)y * fw, source + (size_t)y * stride, (size_t)fw * 4);
        }
        /* F<slot>:<w>x<h>: the frame's size travels with it (F:<w>x<h> with one slot). */
        char message[32];
        int length = server->slots == 2 ? snprintf(message, sizeof(message), "F%u:%dx%d", slot, fw, fh)
                                        : snprintf(message, sizeof(message), "F:%dx%d", fw, fh);
        if (send(server->frames, message, (size_t)length, MSG_DONTWAIT | MSG_NOSIGNAL) == length) {
            server->busy |= 1U << slot;
            feedback_finish(&surface->feedback_queued, true, ++server->presented);
            /* Keep the phase across small scheduling slips. A slow frame
             * cannot make the next one wait for an entire extra period. */
            if (server->next_publish && now < server->next_publish + frame_period)
                server->next_publish += frame_period;
            else
                server->next_publish = now + frame_period;
        } else wl_display_terminate(server->display);
    } else if (source) {
        /* A frame of the size before a resize (full screen, 2026-11-21): the picture stays as it was,
         * and the frame counts as shown. Told "discarded" during the resize, Chromium left a page's full
         * screen 1.5 s after entering it (#6, YouTube); with no presentation feedback it stayed. */
        feedback_finish(&surface->feedback_queued, true, ++server->presented);
    }
    if (source) {
        if (buffer) wl_shm_buffer_end_access(buffer);
        else dma_read_end(surface->buffer);
    }
    feedback_finish(&surface->feedback_queued, false, 0);  /* what was not shown above */
    release_buffer(surface, true);
}

static int tick(int fd, uint32_t mask, void *data) {
    (void)mask;
    uint64_t ticks;
    if (read(fd, &ticks, sizeof(ticks)) != sizeof(ticks)) return 0;
    struct compositor *server = data;
    uint32_t now = (uint32_t)(monotonic_ns() / 1000000);
    struct surface *surface;
    wl_list_for_each(surface, &server->surfaces, link) {
        if (surface == server->current) publish_frame(server, surface);
        else if (surface->queued) release_buffer(surface, true);
        struct frame_callback *callback, *next;
        wl_list_for_each_safe(callback, next, &surface->callbacks, link) {
            wl_callback_send_done(callback->resource, now);
            wl_resource_destroy(callback->resource);
        }
    }
    return 0;
}

static void configure(struct surface *surface);
/* S<w> <h> from the session: the toplevel is configured to that size (in pixels, a multiple of SCALE). */
static bool resize(struct compositor *server, const char *message, ssize_t size) {
    char text[32];
    if (size < 4 || size >= (ssize_t)sizeof(text) || message[0] != 'S') return false;
    memcpy(text, message + 1, (size_t)size - 1);
    text[size - 1] = 0;
    int w = 0, h = 0;
    if (sscanf(text, "%d %d", &w, &h) != 2 || w < 300 || h < 300 || w % SCALE || h % SCALE ||
        (long)w * h > MAX_PIXELS) return false;
    server->width = w;
    server->height = h;
    struct surface *surface;
    wl_list_for_each(surface, &server->surfaces, link)
        if (surface->role && surface->xdg && !surface->popup && surface->configured) configure(surface);
    return true;
}

/* The session's control socket, when frames travel on the UI's own socket: its end, and sizes. */
static int control_event(int fd, uint32_t mask, void *data) {
    struct compositor *server = data;
    char message[32];
    ssize_t size = recv(fd, message, sizeof(message), MSG_DONTWAIT);
    if ((mask & (WL_EVENT_HANGUP | WL_EVENT_ERROR)) || size == 0 ||
        (size < 0 && errno != EAGAIN && errno != EINTR) || (size > 0 && !resize(server, message, size)))
        wl_display_terminate(server->display);
    return 0;
}

static int acknowledge(int fd, uint32_t mask, void *data) {
    struct compositor *server = data;
    char message[32] = {0};
    ssize_t size = recv(fd, message, sizeof(message), MSG_DONTWAIT);
    if (size > 0 && message[0] == 'S') {   /* a size from the session, on the one socket of relay mode */
        if (!resize(server, message, size)) wl_display_terminate(server->display);
        return 0;
    }
    int slot = server->slots == 1 ? 0 : message[1] - '0';
    if ((mask & (WL_EVENT_HANGUP | WL_EVENT_ERROR)) || size != server->slots || message[0] != 'A' ||
        slot < 0 || (unsigned)slot >= server->slots || !(server->busy & (1U << slot)))
        wl_display_terminate(server->display);
    else {
        server->busy &= ~(1U << slot);
        if (server->current) publish_frame(server, server->current);
    }
    return 0;
}

static void destroy(struct wl_client *client, struct wl_resource *res) {
    (void)client;
    wl_resource_destroy(res);
}

static void configure(struct surface *surface) {
    struct wl_array states;
    wl_array_init(&states);
    uint32_t *flags = wl_array_add(&states, 2 * sizeof(*flags));
    if (!flags) {
        wl_client_post_no_memory(wl_resource_get_client(surface->resource));
        return;
    }
    flags[0] = XDG_TOPLEVEL_STATE_FULLSCREEN;
    flags[1] = XDG_TOPLEVEL_STATE_ACTIVATED;
    xdg_toplevel_send_configure(surface->role, surface->server->width / SCALE, surface->server->height / SCALE, &states);
    xdg_surface_send_configure(surface->xdg, wl_display_next_serial(surface->server->display));
    wl_array_release(&states);
}

static void attach(struct wl_client *client, struct wl_resource *res,
                   struct wl_resource *buffer, int32_t dx, int32_t dy) {
    (void)client; (void)dx; (void)dy;
    struct surface *surface = wl_resource_get_user_data(res);
    release_buffer(surface, true);
    if (!buffer) return;
    surface->buffer = buffer;
    surface->attached = true;
    wl_resource_add_destroy_listener(buffer, &surface->buffer_destroy);
}

static void damage(struct wl_client *client, struct wl_resource *res, int32_t x, int32_t y, int32_t w, int32_t h) {
    (void)client; (void)res; (void)x; (void)y; (void)w; (void)h;
}

static void noop_object(struct wl_client *client, struct wl_resource *res, struct wl_resource *object) {
    (void)client; (void)res; (void)object;
}

static void noop_int(struct wl_client *client, struct wl_resource *res, int32_t value) {
    (void)client; (void)res; (void)value;
}

static void frame(struct wl_client *client, struct wl_resource *res, uint32_t id) {
    struct surface *surface = wl_resource_get_user_data(res);
    struct frame_callback *callback = calloc(1, sizeof(*callback));
    if (!callback) { wl_client_post_no_memory(client); return; }
    callback->resource = wl_resource_create(client, &wl_callback_interface, 1, id);
    if (!callback->resource) {
        free(callback);
        wl_client_post_no_memory(client);
        return;
    }
    wl_resource_set_implementation(callback->resource, NULL, callback, frame_callback_destroy);
    wl_list_insert(surface->callbacks.prev, &callback->link);
}

static void commit(struct wl_client *client, struct wl_resource *res) {
    struct surface *surface = wl_resource_get_user_data(res);
    if (!surface->role || !surface->xdg) {
        /* Subsurfaces (Chromium bubbles) are never drawn: hand their buffers back. Their frames count as
         * shown: told "discarded" for its full screen notice, Chromium left a page's full screen 1.5 s
         * after entering it (2026-11-21, #6, YouTube), as it must when the notice cannot be seen. */
        feedback_finish(&surface->feedback_pending, true, surface->server->presented);
        if (surface->attached) release_buffer(surface, true);
        return;
    }
    if (surface->popup) {
        feedback_finish(&surface->feedback_pending, true, surface->server->presented);
        if (!surface->configured) {
            surface->configured = true;
            xdg_popup_send_configure(surface->role, 0, 0, surface->popup_width, surface->popup_height);
            xdg_surface_send_configure(surface->xdg, wl_display_next_serial(surface->server->display));
            xdg_popup_send_popup_done(surface->role);
        }
        if (surface->attached) release_buffer(surface, true);
        return;
    }
    if (!surface->configured) {
        surface->configured = true;
        configure(surface);
        if (surface->server->output &&
            wl_resource_get_client(surface->server->output) == client)
            wl_surface_send_enter(res, surface->server->output);
    }
    /* A newer commit replaces the one still waiting: its feedback is discarded. */
    if (surface->attached) feedback_finish(&surface->feedback_queued, false, 0);
    wl_list_insert_list(surface->feedback_queued.prev, &surface->feedback_pending);
    wl_list_init(&surface->feedback_pending);
    if (surface->attached) {
        surface->queued = true;
        surface->attached = false;
        surface->server->current = surface;
        publish_frame(surface->server, surface);
    }
}

static const struct wl_surface_interface surface_requests = {
    .destroy = destroy, .attach = attach, .damage = damage, .frame = frame,
    .set_opaque_region = noop_object, .set_input_region = noop_object, .commit = commit,
    .set_buffer_transform = noop_int, .set_buffer_scale = noop_int, .damage_buffer = damage,
};

static void finalize_surface(struct wl_resource *res) {
    struct surface *surface = wl_resource_get_user_data(res);
    if (surface->server->current == surface) surface->server->current = NULL;
    wl_list_remove(&surface->link);
    if (surface->role) wl_resource_set_user_data(surface->role, NULL);
    if (surface->xdg) wl_resource_set_user_data(surface->xdg, NULL);
    release_buffer(surface, false);
    feedback_finish(&surface->feedback_pending, false, 0);
    feedback_finish(&surface->feedback_queued, false, 0);
    struct frame_callback *callback, *next;
    wl_list_for_each_safe(callback, next, &surface->callbacks, link)
        wl_resource_destroy(callback->resource);
    free(surface);
}

static void new_surface(struct wl_client *client, struct wl_resource *res, uint32_t id) {
    struct surface *surface = calloc(1, sizeof(*surface));
    if (!surface) { wl_client_post_no_memory(client); return; }
    surface->resource = wl_resource_create(client, &wl_surface_interface, wl_resource_get_version(res), id);
    if (!surface->resource) { free(surface); wl_client_post_no_memory(client); return; }
    surface->buffer_destroy.notify = buffer_destroyed;
    surface->server = wl_resource_get_user_data(res);
    wl_list_insert(&surface->server->surfaces, &surface->link);
    wl_list_init(&surface->callbacks);
    wl_list_init(&surface->feedback_pending);
    wl_list_init(&surface->feedback_queued);
    wl_resource_set_implementation(surface->resource, &surface_requests, surface, finalize_surface);
}

static const struct wl_region_interface region_requests = {
    .destroy = destroy, .add = damage, .subtract = damage,
};

static void new_region(struct wl_client *client, struct wl_resource *res, uint32_t id) {
    (void)res;
    struct wl_resource *region = wl_resource_create(client, &wl_region_interface, 1, id);
    if (!region) { wl_client_post_no_memory(client); return; }
    wl_resource_set_implementation(region, &region_requests, NULL, NULL);
}

static const struct wl_compositor_interface compositor_requests = {
    .create_surface = new_surface, .create_region = new_region,
};

static void bind_compositor(struct wl_client *client, void *data, uint32_t version, uint32_t id) {
    struct wl_resource *res = wl_resource_create(client, &wl_compositor_interface, version, id);
    if (!res) { wl_client_post_no_memory(client); return; }
    wl_resource_set_implementation(res, &compositor_requests, data, NULL);
}

static void finalize_output(struct wl_resource *res) {
    struct compositor *server = wl_resource_get_user_data(res);
    if (server->output == res) server->output = NULL;
}

static const struct wl_output_interface output_requests = { .release = destroy };

static void presentation_feedback(struct wl_client *client, struct wl_resource *res,
                                  struct wl_resource *surface_resource, uint32_t id) {
    (void)res;
    struct surface *surface = wl_resource_get_user_data(surface_resource);
    struct feedback *feedback = calloc(1, sizeof(*feedback));
    if (!feedback) { wl_client_post_no_memory(client); return; }
    feedback->resource = wl_resource_create(client, &wp_presentation_feedback_interface, 1, id);
    if (!feedback->resource) { free(feedback); wl_client_post_no_memory(client); return; }
    wl_resource_set_implementation(feedback->resource, NULL, feedback, feedback_destroy);
    wl_list_insert(surface->feedback_pending.prev, &feedback->link);
}

static const struct wp_presentation_interface presentation_requests = {
    .destroy = destroy, .feedback = presentation_feedback,
};

static void bind_presentation(struct wl_client *client, void *data, uint32_t version, uint32_t id) {
    (void)version;
    struct wl_resource *res = wl_resource_create(client, &wp_presentation_interface, 1, id);
    if (!res) { wl_client_post_no_memory(client); return; }
    wl_resource_set_implementation(res, &presentation_requests, data, NULL);
    wp_presentation_send_clock_id(res, CLOCK_MONOTONIC);
}

static void bind_output(struct wl_client *client, void *data, uint32_t version, uint32_t id) {
    struct compositor *server = data;
    struct wl_resource *res = wl_resource_create(client, &wl_output_interface, version, id);
    if (!res) { wl_client_post_no_memory(client); return; }
    wl_resource_set_implementation(res, &output_requests, data, finalize_output);
    server->output = res;
    wl_output_send_geometry(res, 0, 0, 63, 94, WL_OUTPUT_SUBPIXEL_UNKNOWN,
                            "A22x", "Recovery", WL_OUTPUT_TRANSFORM_NORMAL);
    wl_output_send_mode(res, WL_OUTPUT_MODE_CURRENT | WL_OUTPUT_MODE_PREFERRED, WIDTH, HEIGHT, RATE * 1000);
    if (version >= 2) {
        wl_output_send_scale(res, SCALE);
        wl_output_send_done(res);
    }
}

static void noop_text(struct wl_client *client, struct wl_resource *res, const char *text) {
    (void)client; (void)res; (void)text;
}

static void noop_size(struct wl_client *client, struct wl_resource *res, int32_t w, int32_t h) {
    (void)client; (void)res; (void)w; (void)h;
}

static void noop_serial(struct wl_client *client, struct wl_resource *res, uint32_t serial) {
    (void)client; (void)res; (void)serial;
}

static void noop(struct wl_client *client, struct wl_resource *res) {
    (void)client; (void)res;
}

static void noop_menu(struct wl_client *client, struct wl_resource *res, struct wl_resource *seat,
                      uint32_t serial, int32_t x, int32_t y) {
    (void)client; (void)res; (void)seat; (void)serial; (void)x; (void)y;
}

static void noop_move(struct wl_client *client, struct wl_resource *res, struct wl_resource *seat, uint32_t serial) {
    (void)client; (void)res; (void)seat; (void)serial;
}

static void noop_resize(struct wl_client *client, struct wl_resource *res, struct wl_resource *seat,
                        uint32_t serial, uint32_t edges) {
    (void)client; (void)res; (void)seat; (void)serial; (void)edges;
}

/* A request for full screen, or to leave it, is answered with a configure, as xdg-shell asks: the
 * window stays full screen (it always is), and Chromium sees its request taken. Unanswered, it left
 * a page's full screen again 1.5 s after entering it (2026-11-21, #6: YouTube's full screen closed
 * by itself; the page never called exitFullscreen). */
static void toplevel_fullscreen(struct wl_client *client, struct wl_resource *res, struct wl_resource *output) {
    (void)client; (void)output;
    struct surface *surface = wl_resource_get_user_data(res);
    if (surface && surface->configured) configure(surface);
}

static void toplevel_windowed(struct wl_client *client, struct wl_resource *res) {
    toplevel_fullscreen(client, res, NULL);
}

static const struct xdg_toplevel_interface toplevel_requests = {
    .destroy = destroy, .set_parent = noop_object, .set_title = noop_text, .set_app_id = noop_text,
    .show_window_menu = noop_menu, .move = noop_move, .resize = noop_resize,
    .set_min_size = noop_size, .set_max_size = noop_size, .set_maximized = noop,
    .unset_maximized = noop, .set_minimized = noop, .set_fullscreen = toplevel_fullscreen, .unset_fullscreen = toplevel_windowed,
};

static void finalize_role(struct wl_resource *res) {
    struct surface *surface = wl_resource_get_user_data(res);
    if (surface) surface->role = NULL;
}

static void new_toplevel(struct wl_client *client, struct wl_resource *res, uint32_t id) {
    struct surface *surface = wl_resource_get_user_data(res);
    if (!surface || surface->role) {
        wl_resource_post_error(res, XDG_SURFACE_ERROR_ALREADY_CONSTRUCTED, "Invalid toplevel");
        return;
    }
    surface->role = wl_resource_create(client, &xdg_toplevel_interface, wl_resource_get_version(res), id);
    if (!surface->role) { wl_client_post_no_memory(client); return; }
    wl_resource_set_implementation(surface->role, &toplevel_requests, surface, finalize_role);
}

static void popup_grab(struct wl_client *client, struct wl_resource *res, struct wl_resource *seat, uint32_t serial) {
    (void)client; (void)res; (void)seat; (void)serial;
}

static void popup_reposition(struct wl_client *client, struct wl_resource *res,
                             struct wl_resource *positioner, uint32_t token) {
    (void)client; (void)res; (void)positioner; (void)token;
}

static const struct xdg_popup_interface popup_requests = {
    .destroy = destroy, .grab = popup_grab, .reposition = popup_reposition,
};

static void new_popup(struct wl_client *client, struct wl_resource *res, uint32_t id,
                      struct wl_resource *parent, struct wl_resource *positioner) {
    (void)parent;
    struct surface *surface = wl_resource_get_user_data(res);
    if (!surface || surface->role) {
        wl_resource_post_error(res, XDG_SURFACE_ERROR_ALREADY_CONSTRUCTED, "Invalid popup");
        return;
    }
    struct positioner *place = wl_resource_get_user_data(positioner);
    surface->role = wl_resource_create(client, &xdg_popup_interface, wl_resource_get_version(res), id);
    if (!surface->role) { wl_client_post_no_memory(client); return; }
    surface->popup = true;
    surface->popup_width = place ? place->width : 1;
    surface->popup_height = place ? place->height : 1;
    wl_resource_set_implementation(surface->role, &popup_requests, surface, finalize_role);
}

static const struct xdg_surface_interface xdg_surface_requests = {
    .destroy = destroy, .get_toplevel = new_toplevel, .get_popup = new_popup,
    .set_window_geometry = damage, .ack_configure = noop_serial,
};

static void positioner_size(struct wl_client *client, struct wl_resource *res, int32_t width, int32_t height) {
    (void)client;
    struct positioner *place = wl_resource_get_user_data(res);
    if (width < 1 || height < 1) {
        wl_resource_post_error(res, XDG_POSITIONER_ERROR_INVALID_INPUT, "Invalid popup size");
        return;
    }
    place->width = width;
    place->height = height;
}

static void positioner_rect(struct wl_client *client, struct wl_resource *res,
                            int32_t x, int32_t y, int32_t w, int32_t h) {
    (void)client; (void)res; (void)x; (void)y; (void)w; (void)h;
}

static void positioner_value(struct wl_client *client, struct wl_resource *res, uint32_t value) {
    (void)client; (void)res; (void)value;
}

static void positioner_offset(struct wl_client *client, struct wl_resource *res, int32_t x, int32_t y) {
    (void)client; (void)res; (void)x; (void)y;
}

static const struct xdg_positioner_interface positioner_requests = {
    .destroy = destroy, .set_size = positioner_size, .set_anchor_rect = positioner_rect,
    .set_anchor = positioner_value, .set_gravity = positioner_value,
    .set_constraint_adjustment = positioner_value, .set_offset = positioner_offset,
    .set_reactive = noop, .set_parent_size = noop_size, .set_parent_configure = noop_serial,
};

static void finalize_positioner(struct wl_resource *res) {
    free(wl_resource_get_user_data(res));
}

static void new_positioner(struct wl_client *client, struct wl_resource *res, uint32_t id) {
    struct positioner *place = calloc(1, sizeof(*place));
    if (!place) { wl_client_post_no_memory(client); return; }
    place->width = place->height = 1;
    struct wl_resource *resource = wl_resource_create(client, &xdg_positioner_interface, wl_resource_get_version(res), id);
    if (!resource) { free(place); wl_client_post_no_memory(client); return; }
    wl_resource_set_implementation(resource, &positioner_requests, place, finalize_positioner);
}

static void finalize_xdg(struct wl_resource *res) {
    struct surface *surface = wl_resource_get_user_data(res);
    if (surface) surface->xdg = NULL;
}

static void new_xdg_surface(struct wl_client *client, struct wl_resource *res, uint32_t id, struct wl_resource *object) {
    struct surface *surface = wl_resource_get_user_data(object);
    if (surface->xdg) {
        wl_resource_post_error(res, XDG_WM_BASE_ERROR_ROLE, "Surface already has a shell role");
        return;
    }
    surface->xdg = wl_resource_create(client, &xdg_surface_interface, wl_resource_get_version(res), id);
    if (!surface->xdg) { wl_client_post_no_memory(client); return; }
    wl_resource_set_implementation(surface->xdg, &xdg_surface_requests, surface, finalize_xdg);
}

static const struct xdg_wm_base_interface shell_requests = {
    .destroy = destroy, .create_positioner = new_positioner, .get_xdg_surface = new_xdg_surface, .pong = noop_serial,
};

/* Chromium draws bubbles (the download bubble among them) into subsurfaces and
 * dereferences the subcompositor without a check. Subsurfaces are accepted and
 * stay invisible; only the fullscreen toplevel becomes a frame. */
static void subsurface_position(struct wl_client *client, struct wl_resource *res, int32_t x, int32_t y) {
    (void)client; (void)res; (void)x; (void)y;
}

static const struct wl_subsurface_interface subsurface_requests = {
    .destroy = destroy, .set_position = subsurface_position, .place_above = noop_object,
    .place_below = noop_object, .set_sync = noop, .set_desync = noop,
};

static void new_subsurface(struct wl_client *client, struct wl_resource *res, uint32_t id,
                           struct wl_resource *surface, struct wl_resource *parent) {
    if (surface == parent) {
        wl_resource_post_error(res, WL_SUBCOMPOSITOR_ERROR_BAD_PARENT, "Surface cannot be its own parent");
        return;
    }
    struct wl_resource *child = wl_resource_create(client, &wl_subsurface_interface, wl_resource_get_version(res), id);
    if (!child) { wl_client_post_no_memory(client); return; }
    wl_resource_set_implementation(child, &subsurface_requests, NULL, NULL);
}

static const struct wl_subcompositor_interface subcompositor_requests = {
    .destroy = destroy, .get_subsurface = new_subsurface,
};

static void bind_subcompositor(struct wl_client *client, void *data, uint32_t version, uint32_t id) {
    (void)data;
    struct wl_resource *res = wl_resource_create(client, &wl_subcompositor_interface, version, id);
    if (!res) { wl_client_post_no_memory(client); return; }
    wl_resource_set_implementation(res, &subcompositor_requests, NULL, NULL);
}

/* A seat without devices. Chromium and GTK expect one; touch is delivered
 * through DevTools, so no pointer, keyboard or touch capability is offered. */
static void set_cursor(struct wl_client *client, struct wl_resource *res, uint32_t serial,
                       struct wl_resource *surface, int32_t x, int32_t y) {
    (void)client; (void)res; (void)serial; (void)surface; (void)x; (void)y;
}

static const struct wl_pointer_interface pointer_requests = { .set_cursor = set_cursor, .release = destroy };
static const struct wl_keyboard_interface keyboard_requests = { .release = destroy };
static const struct wl_touch_interface touch_requests = { .release = destroy };

static void seat_device(struct wl_client *client, struct wl_resource *res, uint32_t id,
                        const struct wl_interface *interface, const void *requests) {
    struct wl_resource *device = wl_resource_create(client, interface, wl_resource_get_version(res), id);
    if (!device) { wl_client_post_no_memory(client); return; }
    wl_resource_set_implementation(device, requests, NULL, NULL);
}

static void get_pointer(struct wl_client *client, struct wl_resource *res, uint32_t id) {
    seat_device(client, res, id, &wl_pointer_interface, &pointer_requests);
}

static void get_keyboard(struct wl_client *client, struct wl_resource *res, uint32_t id) {
    seat_device(client, res, id, &wl_keyboard_interface, &keyboard_requests);
}

static void get_touch(struct wl_client *client, struct wl_resource *res, uint32_t id) {
    seat_device(client, res, id, &wl_touch_interface, &touch_requests);
}

static const struct wl_seat_interface seat_requests = {
    .get_pointer = get_pointer, .get_keyboard = get_keyboard, .get_touch = get_touch, .release = destroy,
};

static void bind_seat(struct wl_client *client, void *data, uint32_t version, uint32_t id) {
    (void)data;
    struct wl_resource *res = wl_resource_create(client, &wl_seat_interface, version, id);
    if (!res) { wl_client_post_no_memory(client); return; }
    wl_resource_set_implementation(res, &seat_requests, NULL, NULL);
    wl_seat_send_capabilities(res, 0);
    if (version >= 2) wl_seat_send_name(res, "recovery");
}

static void bind_shell(struct wl_client *client, void *data, uint32_t version, uint32_t id) {
    struct wl_resource *res = wl_resource_create(client, &xdg_wm_base_interface, version, id);
    if (!res) { wl_client_post_no_memory(client); return; }
    wl_resource_set_implementation(res, &shell_requests, data, NULL);
}

int main(int argc, char **argv) {
    if (argc != 2 && argc != 3) return 64;
    struct compositor server = { .control = atoi(argv[1]), .width = WIDTH, .height = HEIGHT };
    server.frames = argc == 3 ? atoi(argv[2]) : server.control;
    wl_list_init(&server.surfaces);
    struct stat st;
    if (server.control < 3 || server.control == 5 || server.frames < 3 || server.frames == 5 ||
        (server.frames != server.control && fstat(server.frames, &st)) || fstat(5, &st) ||
        (st.st_size != BYTES && st.st_size != 2 * BYTES)) return 65;
    server.slots = st.st_size / BYTES;
    server.frame = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, 5, 0);
    if (server.frame == MAP_FAILED) return 66;
    server.display = wl_display_create();
    if (!server.display || wl_display_init_shm(server.display) ||
        !wl_global_create(server.display, &wl_compositor_interface, 4, &server, bind_compositor) ||
        !wl_global_create(server.display, &wl_output_interface, 3, &server, bind_output) ||
        !wl_global_create(server.display, &xdg_wm_base_interface, 1, &server, bind_shell) ||
        !wl_global_create(server.display, &wl_seat_interface, 5, &server, bind_seat) ||
        !wl_global_create(server.display, &wl_subcompositor_interface, 1, &server, bind_subcompositor) ||
        !wl_global_create(server.display, &wp_presentation_interface, 1, &server, bind_presentation) ||
        (getenv("A22X_WEB_GPU") && !wl_global_create(server.display, &zwp_linux_dmabuf_v1_interface, 3, &server, dma_bind)) ||
        wl_display_add_socket(server.display, "recovery-wayland")) return 67;
    struct wl_event_loop *loop = server.loop = wl_display_get_event_loop(server.display);
    int timer = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
    struct itimerspec period = { .it_interval.tv_nsec = frame_period, .it_value.tv_nsec = frame_period };
    if (timer < 0 || timerfd_settime(timer, 0, &period, NULL) ||
        !wl_event_loop_add_fd(loop, timer, WL_EVENT_READABLE, tick, &server) ||
        !wl_event_loop_add_fd(loop, server.frames, WL_EVENT_READABLE, acknowledge, &server) ||
        (server.frames != server.control &&
         !wl_event_loop_add_fd(loop, server.control, WL_EVENT_READABLE, control_event, &server))) return 68;
    if (send(server.control, "S", 1, MSG_NOSIGNAL) != 1) return 69;
    wl_display_run(server.display);
    wl_display_destroy_clients(server.display);
    wl_display_destroy(server.display);
    close(timer);
    munmap(server.frame, st.st_size);
    return 0;
}
