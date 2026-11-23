/* SPDX-License-Identifier: MIT — what plays, as the shade and the player see it, and Bluetooth's tile
 * (2026-11-22, the owner). The player's own page and the Bluetooth page build on these. */
#ifndef A22X_MEDIA_UI_H
#define A22X_MEDIA_UI_H

static bool media_card_shown(const App*a){return a->media.source!=MEDIA_NONE&&(a->media.title[0]||a->media.duration_ms);}
/* The position moves on by itself while it plays, between the reports of the player. */
static uint32_t media_position_of(const App*a,const MediaCard*m){
    uint32_t p=m->position_ms;
    if(m->playing&&m->position_at&&a->now>m->position_at)p+=(uint32_t)(a->now-m->position_at);
    if(m->duration_ms&&p>m->duration_ms)p=m->duration_ms;
    return p;
}
static uint32_t media_card_position(const App*a){return media_position_of(a,&a->media);}
/* The shade's card: what plays; when nothing does, what played last. The player and the browser
   keep their own (a->mu.local, a->mu.web). */
static void media_choose(App*a){
    const MediaCard*l=&a->mu.local,*w=&a->mu.web,*pick;
    if(l->source&&l->playing)pick=l;
    else if(w->source&&w->playing)pick=w;
    else if(a->media.source==MEDIA_BROWSER&&w->source)pick=w;
    else if(l->source)pick=l;
    else pick=w;
    if(memcmp(&a->media,pick,sizeof(a->media))){a->media=*pick;a->dirty=true;}
}
static void player_command(App*a,const char*command,uint32_t value);
static void media_card_control(App*a,int action){
    if(a->media.source==MEDIA_NONE)return;
    if(action==A_QS_MEDIA_PLAY){a->media.position_ms=media_card_position(a);a->media.position_at=a->now;a->media.playing=!a->media.playing;
        player_command(a,a->media.playing?"play":"pause",0);}
    else if(action==A_QS_MEDIA_PREV)player_command(a,"previous",0);
    else if(action==A_QS_MEDIA_NEXT)player_command(a,"next",0);
    else if(action==A_QS_MEDIA_SEEK){a->media.position_ms=a->media_seek_ms;a->media.position_at=a->now;player_command(a,"seek",a->media_seek_ms);}
    a->dirty=true;
}
/* Once a second while something plays and a page shows its position. */
static void media_tick(App*a){
    static uint64_t last;
    if(!a->media.playing||a->now-last<500)return;
    last=a->now;
    if(a->qs.visible||a->screen==PLAYER)a->dirty=true;
}

static bool bt_tile_on(const App*a){return a->bt.known&&a->bt.available&&a->bt.powered;}
static bool bt_connected(const App*a){for(unsigned int n=0;n<a->bt.count;n++)if(a->bt.devices[n].connected)return true;return false;}
/* 0 off, 1 on, 2 a device connected: the shade's tile and the status bar tell the three apart. */
static int bt_tile_level(const App*a){return !bt_tile_on(a)?0:(bt_connected(a)?2:1);}
static void bt_tile_status(const App*a,char*out,size_t size){
    if(!a->bt.known){copy(out,size,tr("Tap and hold to open"));return;}
    if(!a->bt.available){copy(out,size,tr("Unavailable"));return;}
    if(!a->bt.powered){copy(out,size,tr("Off"));return;}
    for(unsigned int n=0;n<a->bt.count;n++)if(a->bt.devices[n].connected){
        if(a->bt.devices[n].battery>=0)snprintf(out,size,"%s · %d%%",a->bt.devices[n].name,a->bt.devices[n].battery);
        else copy(out,size,a->bt.devices[n].name);
        return;}
    copy(out,size,tr("On, not connected"));
}
static void bt_power(App*a,bool on);
static void bt_tile_toggle(App*a){
    if(!a->bt.known||!a->bt.available){qs_close(a);tap_action(a,A_BLUETOOTH);return;}
    bt_power(a,!a->bt.powered);
}
#endif
