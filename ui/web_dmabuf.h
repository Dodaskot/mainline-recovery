/* Only packed RGB, one linear plane, with a readable implicit fence. */
#include "linux-dmabuf-server-protocol.h"
#include <poll.h>
#include <sys/ioctl.h>

#define XRGB8888 0x34325258u
#define ARGB8888 0x34325241u

struct dma_buffer {
    void *map;
    size_t length;
    uint32_t width, height, stride, offset;
    int fd;
};

/* linux/dma-buf.h defines this ABI. The recovery cross sysroot only has libc headers. */
enum { DMA_SYNC_READ = 1, DMA_SYNC_END = 4 };

static int dma_sync(const struct dma_buffer *buffer, bool end) {
    uint64_t mode = DMA_SYNC_READ | (end ? DMA_SYNC_END : 0);
    int rc;
    do rc = ioctl(buffer->fd, _IOW('b', 0, uint64_t), &mode);
    while (rc < 0 && errno == EINTR);
    return rc;
}

static void dma_buffer_destroy(struct wl_resource *res) {
    struct dma_buffer *buffer = wl_resource_get_user_data(res);
    munmap(buffer->map, buffer->length);
    close(buffer->fd);
    free(buffer);
}

static const struct wl_buffer_interface dma_buffer_requests = { .destroy = destroy };

static void dma_params_destroy(struct wl_resource *res) {
    struct dma_buffer *buffer = wl_resource_get_user_data(res);
    if (buffer->fd >= 0) close(buffer->fd);
    free(buffer);
}

static void dma_add(struct wl_client *client, struct wl_resource *res, int32_t fd, uint32_t plane,
                    uint32_t offset, uint32_t stride, uint32_t hi, uint32_t lo) {
    (void)client;
    struct dma_buffer *params = wl_resource_get_user_data(res);
    if (plane != 0 || hi || lo || params->fd != -1) {
        close(fd);
        wl_resource_post_error(res, ZWP_LINUX_BUFFER_PARAMS_V1_ERROR_PLANE_IDX, "Expected one linear plane");
        return;
    }
    params->fd = fd;
    params->stride = stride;
    params->offset = offset;
}

static struct wl_resource *dma_create_buffer(struct wl_client *client, struct wl_resource *res, uint32_t id,
                                            int32_t w, int32_t h, uint32_t format, uint32_t flags) {
    struct dma_buffer *params = wl_resource_get_user_data(res);
    if (params->fd < 0 || w < 1 || w > 4096 || h < 1 || h > 4096 || flags ||
        params->stride < (uint32_t)w * 4 || params->stride > 16384 ||
        (format != XRGB8888 && format != ARGB8888)) return NULL;
    size_t length = (size_t)params->offset + (size_t)params->stride * h;
    off_t bytes = lseek(params->fd, 0, SEEK_END);
    if (bytes < 0 || length > (uint64_t)bytes || length > (64u << 20)) return NULL;
    void *map = mmap(NULL, length, PROT_READ, MAP_SHARED, params->fd, 0);
    if (map == MAP_FAILED) return NULL;
    struct dma_buffer *buffer = calloc(1, sizeof(*buffer));
    struct wl_resource *resource = buffer ? wl_resource_create(client, &wl_buffer_interface, 1, id) : NULL;
    if (!resource) {
        free(buffer);
        munmap(map, length);
        wl_client_post_no_memory(client);
        return NULL;
    }
    *buffer = *params;
    buffer->map = map;
    buffer->width = w;
    buffer->height = h;
    buffer->length = length;
    params->fd = -2;
    wl_resource_set_implementation(resource, &dma_buffer_requests, buffer, dma_buffer_destroy);
    return resource;
}

static void dma_create(struct wl_client *client, struct wl_resource *res,
                       int32_t w, int32_t h, uint32_t format, uint32_t flags) {
    struct wl_resource *buffer = dma_create_buffer(client, res, 0, w, h, format, flags);
    if (buffer) zwp_linux_buffer_params_v1_send_created(res, buffer);
    else zwp_linux_buffer_params_v1_send_failed(res);
}

static void dma_create_immediate(struct wl_client *client, struct wl_resource *res, uint32_t id,
                                 int32_t w, int32_t h, uint32_t format, uint32_t flags) {
    if (!dma_create_buffer(client, res, id, w, h, format, flags))
        wl_resource_post_error(res, ZWP_LINUX_BUFFER_PARAMS_V1_ERROR_INVALID_WL_BUFFER, "Invalid GPU buffer");
}

static const struct zwp_linux_buffer_params_v1_interface dma_params_requests = {
    .destroy = destroy, .add = dma_add, .create = dma_create, .create_immed = dma_create_immediate
};

static void dma_new_params(struct wl_client *client, struct wl_resource *res, uint32_t id) {
    struct dma_buffer *params = calloc(1, sizeof(*params));
    struct wl_resource *resource = params ? wl_resource_create(client, &zwp_linux_buffer_params_v1_interface,
                                                               wl_resource_get_version(res), id) : NULL;
    if (!resource) {
        free(params);
        wl_client_post_no_memory(client);
        return;
    }
    params->fd = -1;
    wl_resource_set_implementation(resource, &dma_params_requests, params, dma_params_destroy);
}

static const struct zwp_linux_dmabuf_v1_interface dma_requests = { .destroy = destroy, .create_params = dma_new_params };

static void dma_bind(struct wl_client *client, void *data, uint32_t version, uint32_t id) {
    (void)data;
    struct wl_resource *res = wl_resource_create(client, &zwp_linux_dmabuf_v1_interface, version, id);
    if (!res) { wl_client_post_no_memory(client); return; }
    wl_resource_set_implementation(res, &dma_requests, NULL, NULL);
    if (version >= 3) {
        zwp_linux_dmabuf_v1_send_modifier(res, XRGB8888, 0, 0);
        zwp_linux_dmabuf_v1_send_modifier(res, ARGB8888, 0, 0);
    } else {
        zwp_linux_dmabuf_v1_send_format(res, XRGB8888);
        zwp_linux_dmabuf_v1_send_format(res, ARGB8888);
    }
}

static const unsigned char *dma_read(struct wl_resource *res, int *w, int *h, int *stride) {
    if (!wl_resource_instance_of(res, &wl_buffer_interface, &dma_buffer_requests)) return NULL;
    struct dma_buffer *buffer = wl_resource_get_user_data(res);
    struct pollfd fence = { .fd = buffer->fd, .events = POLLIN };
    if (poll(&fence, 1, 0) != 1 || !(fence.revents & POLLIN) || dma_sync(buffer, false)) return NULL;
    *w = buffer->width; *h = buffer->height; *stride = buffer->stride;
    return (const unsigned char*)buffer->map + buffer->offset;
}

static void dma_read_end(struct wl_resource *res) {
    dma_sync(wl_resource_get_user_data(res), true);
}

/* The descriptor of a GPU buffer whose rendering fence has not signalled yet, to wait for it;
 * -1 for another kind of buffer or one that is ready (a failure then is not worth a watch:
 * it would fire at once, again and again). wl_event_loop_add_fd keeps its own duplicate. */
static int dma_pending_fd(struct wl_resource *res) {
    if (!wl_resource_instance_of(res, &wl_buffer_interface, &dma_buffer_requests)) return -1;
    struct dma_buffer *buffer = wl_resource_get_user_data(res);
    struct pollfd fence = { .fd = buffer->fd, .events = POLLIN };
    return poll(&fence, 1, 0) == 0 ? buffer->fd : -1;
}
