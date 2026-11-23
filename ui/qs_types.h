/* SPDX-License-Identifier: MIT — state of the quick settings shade, the media player and Bluetooth
 * (2026-11-22, the owner: a shade pulled from the status bar, a player for local music and video, and
 * Bluetooth; the pictures of the request are the reference). Kept apart from App so the three parts can
 * be read on their own. */
#ifndef A22X_QS_TYPES_H
#define A22X_QS_TYPES_H
#include <stdbool.h>
#include <stdint.h>

/* The shade: drawn over a blurred picture of the page under it, from the top down to `height`. */
typedef struct {
    bool visible;          /* drawn: pulled, open, or settling back */
    bool dragging;         /* a finger moves the panel's edge */
    bool armed;            /* a finger went down on the status bar; moving down pulls the shade */
    bool expanded;         /* where it settles when open: compact or with every control */
    float height;          /* the panel's bottom edge, in layout pixels */
    float target;          /* where it settles; 0 closes it */
    float settle_from;     /* the height when it began to settle */
    uint64_t settle_at;    /* when it began to settle */
    int arm_x, arm_y;      /* where the finger went down on the status bar */
    int down_x, down_y;    /* where a finger went down on the open shade */
    float down_height;     /* the panel's height then */
    uint64_t down_at;      /* when */
    float velocity;        /* px per ms, of the last moves, positive downwards */
    int last_y;uint64_t last_at;
    int slider;            /* 0, or the slider under the finger: QS_SLIDER_* */
    bool moved;            /* the finger moved far enough not to be a tap */
    bool held;             /* a hold on a tile already acted */
    int press;             /* the action under the finger, for the pressed look */
    uint32_t *backdrop;    /* the page under it, blurred, at the panel's resolution */
    uint32_t mute_restore; /* the volume a tap on Sound brings back */
} Shade;
enum { QS_SLIDER_NONE, QS_SLIDER_BRIGHTNESS, QS_SLIDER_TORCH, QS_SLIDER_VOLUME, QS_SLIDER_SEEK };

/* What plays, for the shade's card and the player's page: a local file of the player, or a page of the
 * browser (its media session). */
enum { MEDIA_NONE, MEDIA_LOCAL, MEDIA_BROWSER };
typedef struct {
    int source;            /* MEDIA_* */
    bool playing, video;
    char title[160], subtitle[160];
    uint32_t position_ms, duration_ms;
    uint64_t position_at;  /* when position_ms was read: it moves on while playing */
    char output[64];       /* where the sound goes: "Speaker", a Bluetooth device's name */
} MediaCard;

/* Bluetooth as the helper reports it. */
#define BT_DEVICES_MAX 24
typedef struct {
    char address[18], name[64], kind[16];  /* kind: audio, keyboard, mouse, phone, other */
    bool paired, connected, trusted;
    int battery;           /* percent, -1 when the device tells none */
    int rssi;
} BtDevice;
typedef struct {
    bool known, available, powered, scanning;
    char reason[256];
    unsigned int count;
    BtDevice devices[BT_DEVICES_MAX];
    char pairing_address[18], pairing_name[64], pairing_passkey[12];
    int pairing_kind;      /* 0 none, 1 confirm a number, 2 type a number on the device, 3 waiting */
    int power_wanted;      /* the switch as last set, until a report agrees: 0 none, 1 off, 2 on */
    uint64_t power_until;  /* when a report that does not agree is believed again */
} BtState;

/* The player and the link to the media service, as the interface keeps them (media_client.h). */
#define MEDIA_QUEUE_MAX 96
typedef struct { char name[192], volume[64], path[1024]; bool video; } MediaItem;
typedef struct {
    int svc_fd, player_fd;          /* -1 when not connected (initialize sets them) */
    uint8_t *shm;                   /* the player's pictures (shared memory it sent) */
    bool spawned; int spawns; uint64_t spawned_at, retry_at;
    char svc_in[32768]; size_t svc_len;
    char pl_in[16384]; size_t pl_len;
    bool known, available; char reason[256], progress[160];
    bool video; int src_w, src_h; uint32_t frame_seq; int frame_w, frame_h; int asked_w, asked_h;
    char output[96], output_name[64];
    MediaItem queue[MEDIA_QUEUE_MAX]; int count, at; bool shuffle, repeat; int volume;
    int tab;                        /* the player's page: 0 music, 1 video */
    bool pip, full, pip_drag, pip_moved, controls; int pip_x, pip_y, pip_w, drag_dx, drag_dy; uint64_t controls_until;
    char error[200]; uint64_t error_until;
    bool output_sheet, device_sheet; int device_index;
    bool pending_play;              /* a file is to start once the player is there */
    bool ended;                     /* the queue's last file played to its end: the player closed it */
    bool pip_resize; int resize_from_w, resize_from_x;  /* the window's corner grip in hand */
    uint64_t local_started_at;      /* when the owner last started the player (one sound at a time) */
    bool frame_wanted;              /* a view of this frame asked for pictures */
    MediaCard local, web;           /* the player's and the browser's own; the shade shows one (media_choose) */
    bool web_changed;
} MediaUi;

/* The browser in a window over the other pages (web_ui.h; 2026-11-22, the owner: as Android's freeform
 * windows). Its height follows the page's shape from its width. */
typedef struct {
    bool open;             /* the browser floats over the other pages */
    bool bubble;           /* folded into a round bubble at an edge; a tap brings the window back */
    int x, y, w;           /* the window, layout pixels */
    int bx, by;            /* the bubble's centre */
    bool drag, resize, moved;  /* a finger moves it (its bar, or the bubble), grows it (its corner) */
    int dx, dy, from_w, from_x;
    int press;             /* the button of its bar under the finger, for the pressed look */
} WebFloat;

/* The shell after the owner's mock-ups (shell_ui.h): the tab in use and the page each tab keeps, the
 * operation folded into its indicator, and what is installed on the phone (systems_overview.py). */
enum { TAB_OVERVIEW, TAB_SYSTEMS, TAB_FILES, TAB_TOOLS, TAB_COUNT };
#define OVERVIEW_LINUX_MAX 4
typedef struct {
    int tab;                        /* TAB_* */
    int tab_page[TAB_COUNT];        /* the page each tab shows again (an enum Screen) */
    bool collapsed;                 /* the operation runs on behind its indicator */
    bool result_waiting;            /* it ended while folded: its result opens from the indicator */
    bool details;                   /* the operation page shows its details */
    /* what is installed */
    bool ov_known, ov_spawned;
    uint64_t ov_at, ov_mtime;
    bool android_data;
    char boot_kind[16], android_version[8], android_patch[12], boot_kernel[48], boot_root[16];
    int linux_count;
    char linux_names[OVERVIEW_LINUX_MAX][96];
    bool linux_active[OVERVIEW_LINUX_MAX];
    uint32_t *glass;                /* the theme's backdrop, frosted once, behind the floating bars */
    const void *glass_theme;
} ShellState;
#endif
