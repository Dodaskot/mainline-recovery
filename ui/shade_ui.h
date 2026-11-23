/* SPDX-License-Identifier: MIT — the quick settings shade (2026-11-22, the owner; the pictures of the
 * request are the reference: "Aurora · compact", "Aurora · expanded", "Daylight · expanded").
 *
 * A finger that goes down on the status bar and moves down pulls the shade over the page; the page
 * stays as it was under a blurred, darkened picture of itself. Let go past the middle of the compact
 * panel it stays open, compact; pulled further, or pulled down again on the open shade, it shows every
 * control. Swiped up it folds back, a tap beside it closes it. Its controls are the recovery's own:
 * Wi-Fi's page, Bluetooth, the flashlight, the sound, the brightness of Display, the media that plays,
 * and the work that runs. */
#ifndef A22X_SHADE_UI_H
#define A22X_SHADE_UI_H

#define QS_PULL_START 22      /* px a finger moves down from the status bar before the shade follows */
#define QS_TAP_SLOP 22
#define QS_SETTLE_MS 240
#define QS_HOLD_MS 520
#define QS_TOP 184            /* first row of tiles */

static bool bt_tile_on(const App*a);
static const char*player_output_label(const App*a);
static int bt_tile_level(const App*a);
static void bt_tile_status(const App*a,char*out,size_t size);
static void bt_tile_toggle(App*a);
static bool media_card_shown(const App*a);
static void media_card_control(App*a,int action);
static uint32_t media_card_position(const App*a);

static bool shade_media(const App*a){return media_card_shown(a);}
static bool shade_job(const App*a){return a->job.pid&&job_long(a->job.kind);}
/* Layout: rows from QS_TOP down; the compact panel ends after the brightness and the media card. */
static int qs_row_brightness(void){return QS_TOP+148+144;}
static int qs_compact_height(const App*a){return qs_row_brightness()+148+(shade_media(a)?196:0)+52;}
static int qs_expanded_height(const App*a){
    int y=qs_row_brightness()+148;
    if(torch_ready((App*)a))y+=148;
    y+=148;                              /* volume */
    if(shade_media(a))y+=236;
    if(shade_job(a))y+=166;
    return y+52;
}
static int qs_height_max(const App*a){int h=qs_expanded_height(a);return h>CH-40?CH-40:h;}

static bool qs_can_open(const App*a){
    /* Over a video in full screen too (2026-11-22, the owner), but not over one on its side: the status bar
       is not at the top for the eye then. */
    return !a->locked&&a->screen!=SPLASH&&a->screen!=LOCKSCREEN&&a->screen!=POWER_MENU&&a->screen!=ANIMATIONS&&
           !(a->screen==WEB_BROWSER&&a->web_fullscreen=='L')&&!a->soft_blanked;
}
/* The page under the shade, blurred once when the shade starts to come down. */
static bool qs_capture(App*a){
    if(!a->qs.backdrop)a->qs.backdrop=malloc((size_t)NW*NH*sizeof(uint32_t));
    if(!a->qs.backdrop)return false;
    /* The browser's last frames went straight to the panel: the picture is made whole first. */
    web_sync_pixels(a);
    canvas_blur(a->qs.backdrop,a->pixels);
    return true;
}
static void qs_settle(App*a,float target){a->qs.target=target;a->qs.settle_from=a->qs.height;a->qs.settle_at=a->now?a->now:1;a->qs.dragging=false;a->dirty=true;}
static void qs_close(App*a){if(a->qs.visible)qs_settle(a,0);}
static void __attribute__((unused)) qs_open(App*a,bool expanded){
    if(!a->qs.visible){if(!qs_can_open(a)||!qs_capture(a))return;cancel_pointer(a);a->pointer_requires_release=false;a->qs.visible=true;a->qs.height=0;}
    a->qs.expanded=expanded;qs_settle(a,(float)(expanded?qs_height_max(a):qs_compact_height(a)));
}
/* One frame of settling: an ease-out over QS_SETTLE_MS. Returns whether it still moves. */
static bool qs_tick(App*a){
    if(!a->qs.visible||a->qs.dragging||!a->qs.settle_at)return false;
    float t=(float)(a->now-a->qs.settle_at)/(float)QS_SETTLE_MS;if(t>1.f)t=1.f;
    float e=1.f-(1.f-t)*(1.f-t)*(1.f-t);
    a->qs.height=a->qs.settle_from+(a->qs.target-a->qs.settle_from)*e;a->dirty=true;
    if(t>=1.f){a->qs.settle_at=0;a->qs.height=a->qs.target;if(a->qs.target<=0){a->qs.visible=false;a->qs.expanded=false;}return false;}
    return true;
}
/* Where a finger let go decides where the shade settles: its speed first, then how far it came. */
static void qs_release(App*a){
    float h=a->qs.height,v=a->qs.velocity,compact=(float)qs_compact_height(a),full=(float)qs_height_max(a);
    if(v<-0.6f){qs_settle(a,h>compact+40&&a->qs.expanded?compact:0);if(h>compact+40&&a->qs.expanded)a->qs.expanded=false;return;}
    if(v>0.6f){bool more=h>compact*0.6f;a->qs.expanded=more;qs_settle(a,more?full:compact);return;}
    if(h<compact*0.45f){qs_settle(a,0);return;}
    bool more=h>(compact+full)/2.f;a->qs.expanded=more;qs_settle(a,more?full:compact);
}

/* --- drawing ---------------------------------------------------------------------------------------- */
static void qs_status_line(App*a){
    icon(a,A_OS,30,28,30,ORANGE);text(a,70,32,0,MUTED,"Mainline Recovery");bt_status(a,70+text_width("Mainline Recovery",0));
    char now[16],date[96];clock_text(a,now,sizeof(now),date,sizeof(date));int clock_w=text_width(now,1);text(a,CW-32-clock_w,27,1,TEXT,now);
    (void)wifi_status(a,battery_status(a,CW-32-clock_w-20));
}
static void qs_slider(App*a,Rect card,unsigned int percent,bool usable,int action){
    int track=card.y+card.h-44,knob=76+(int)(percent>100?100:percent)*568/100;
    rounded(a,(Rect){76,track,568,16},8,PANEL2);
    if(usable&&knob>84)rounded(a,(Rect){76,track,knob-76,16},8,ORANGE);
    if(usable){vector_circle(a,knob,track+8,18,18,ORANGE);vector_circle(a,knob,track+8,13,13,ui_theme->knob);}
    register_button(a,(Rect){52,track-36,616,88},action,usable,0);
}
/* LEVEL 0 off, 1 on but joined to nothing, 2 connected: "on" and "connected" looked the same (2026-11-22,
   the owner), so only a connection fills the tile; on alone lights the sign's disc. */
static void qs_big_tile(App*a,Rect r,int glyph,int level,const char*title,const char*status,int action){
    bool full=level>=2;
    surface(a,r,30,full?ORANGE_DARK:PANEL,action);
    uint32_t disc=full?ORANGE:(level==1?ORANGE_DARK:PANEL2);
    gradient(a,(Rect){r.x+20,r.y+(r.h-84)/2,84,84},42,disc,disc);
    icon(a,glyph,r.x+40,r.y+(r.h-44)/2,44,full?ui_theme->on_accent:(level==1?ORANGE:TEXT));
    ellipsis(a,r.x+120,r.y+r.h/2-40,r.w-136,1,TEXT,title);
    raw_text(true);ellipsis(a,r.x+120,r.y+r.h/2+4,r.w-136,0,MUTED,status);raw_text(false);
    register_button(a,r,action,true,0);
}
static void qs_small_tile(App*a,Rect r,int glyph,bool on,const char*label,int action){
    surface(a,r,28,on?ORANGE:PANEL,action);
    icon(a,glyph,r.x+(r.w-44)/2,r.y+22,44,on?ui_theme->on_accent:TEXT);
    int w=text_width(label,0);ellipsis(a,r.x+(w<r.w-24?(r.w-w)/2:12),r.y+r.h-50,r.w-24,0,on?ui_theme->on_accent:TEXT,label);
    register_button(a,r,action,true,0);
}
static void qs_time(char*out,size_t size,uint32_t ms){unsigned int s=ms/1000u;if(s>=3600)snprintf(out,size,"%u:%02u:%02u",s/3600,s/60%60,s%60);else snprintf(out,size,"%u:%02u",s/60,s%60);}
static void qs_media_card(App*a,int y,bool full){
    const MediaCard*m=&a->media;int h=full?220:180;Rect card={28,y,664,h};rounded(a,card,28,PANEL);
    /* No cover art is read from files: a tile of the theme with the kind of media. */
    gradient(a,(Rect){48,y+22,120,120},22,ui_theme->tile_fill[3],ui_theme->tile_fill[0]);
    icon(a,m->video?ICON_VIDEO:ICON_MUSIC,48+34,y+22+34,52,ui_theme->tile_ink[3]);
    const char*title=m->title[0]?m->title:tr("Nothing plays");  /* tr() keeps raw text as it is */
    raw_text(true);ellipsis(a,188,y+40,250,1,TEXT,title);ellipsis(a,188,y+86,250,0,MUTED,m->subtitle);raw_text(false);
    int cx=560;
    surface(a,(Rect){452,y+44,72,72},36,PANEL,A_QS_MEDIA_PREV);icon(a,ICON_PREV,466,y+58,44,TEXT);register_button(a,(Rect){446,y+38,84,84},A_QS_MEDIA_PREV,true,0);
    gradient(a,(Rect){cx-36,y+44,72,72},36,ORANGE,ORANGE);if(pressed(a,A_QS_MEDIA_PLAY))veil(a,(Rect){cx-36,y+44,72,72},36,0xffffffu,30);
    icon(a,m->playing?ICON_PAUSE:ICON_PLAY,cx-22,y+58,44,ui_theme->on_accent);register_button(a,(Rect){cx-42,y+38,84,84},A_QS_MEDIA_PLAY,true,0);
    surface(a,(Rect){604,y+44,72,72},36,PANEL,A_QS_MEDIA_NEXT);icon(a,ICON_NEXT,618,y+58,44,TEXT);register_button(a,(Rect){598,y+38,84,84},A_QS_MEDIA_NEXT,true,0);
    register_button(a,(Rect){28,y,400,h-(full?60:0)},A_QS_MEDIA_OPEN,true,0);
    if(full){
        uint32_t position=media_card_position(a);char left[24],right[24];qs_time(left,sizeof(left),position);qs_time(right,sizeof(right),m->duration_ms);
        text(a,48,y+h-56,0,MUTED,left);text(a,672-text_width(right,0),y+h-56,0,MUTED,right);
        int x0=128,x1=592-text_width(right,0)+80;if(x1>600)x1=600;
        rounded(a,(Rect){x0,y+h-46,x1-x0,10},5,PANEL2);
        if(m->duration_ms){int k=x0+(int)((uint64_t)position*(uint64_t)(x1-x0)/m->duration_ms);if(k>x1)k=x1;rounded(a,(Rect){x0,y+h-46,k-x0,10},5,ORANGE);vector_circle(a,k,y+h-41,13,13,ORANGE);}
        register_button(a,(Rect){x0-20,y+h-76,x1-x0+40,64},A_QS_MEDIA_SEEK,m->duration_ms>0,0);
    }
}
static void qs_job_card(App*a,int y){
    Rect card={28,y,664,150};surface(a,card,28,PANEL,A_QS_JOB);
    gradient(a,(Rect){48,y+26,64,64},32,PANEL2,PANEL2);icon(a,A_BACKUP,58,y+36,44,ORANGE);
    ellipsis(a,132,y+24,500,1,TEXT,a->job_cancelled?"Cancelling...":(a->progress_phase[0]?phase_label(a,a->progress_phase):"Working"));
    char line[160]="",left[64];
    if(a->progress_total){uint64_t done=a->progress_done>a->progress_total?a->progress_total:a->progress_done;snprintf(line,sizeof(line),"%u%%",(unsigned int)(done*100/a->progress_total));}
    if(progress_left(a,left,sizeof(left))){if(line[0])append(line,sizeof(line),"  ·  ");append(line,sizeof(line),left);}
    const char*shown=line[0]?line:tr("Please wait");
    raw_text(true);ellipsis(a,132,y+68,500,0,MUTED,shown);raw_text(false);
    icon(a,ICON_CHEVRON,640,y+40,32,MUTED);
    Rect track={52,y+112,616,12};rounded(a,track,6,PANEL2);
    if(a->progress_total){uint64_t done=a->progress_done>a->progress_total?a->progress_total:a->progress_done;rounded(a,(Rect){track.x,track.y,(int)((double)done/(double)a->progress_total*track.w),track.h},6,ORANGE);}
    else rounded(a,(Rect){track.x+(int)((a->now/8)%480),track.y,136,track.h},6,ORANGE);
    register_button(a,card,A_QS_JOB,true,0);
}
static void render_shade(App*a){
    float progress=a->qs.height/(float)qs_compact_height(a);if(progress>1.f)progress=1.f;if(progress<0.f)progress=0.f;
    memcpy(a->pixels,a->qs.backdrop,(size_t)NW*NH*sizeof(uint32_t));
    veil(a,(Rect){0,0,CW,CH},0,BG,(unsigned int)(150.f*progress));
    int h=(int)(a->qs.height+.5f);if(h<1)return;
    /* The panel and what it holds are drawn where they stand when open; the edge only shows more of them. */
    a->clip_active=true;a->clip=(Rect){0,0,CW,h};
    rounded(a,(Rect){0,-60,CW,h+60},44,PANEL2);veil(a,(Rect){0,-60,CW,h+60},44,BG,90);
    qs_status_line(a);
    text(a,32,100,3,TEXT,"Quick settings");
    surface(a,(Rect){CW-98,96,66,66},33,PANEL,A_QS_GEAR);icon(a,ICON_GEAR,CW-86,108,42,TEXT);register_button(a,(Rect){CW-104,90,78,78},A_QS_GEAR,true,0);
    char status[96];
    const char*wifi=!a->wifi_known?"Wi-Fi":(a->wifi_connected&&a->wifi_ssid[0]?a->wifi_ssid:(a->wifi_on?tr("Not connected"):tr("Off")));
    qs_big_tile(a,(Rect){28,QS_TOP,324,132},ICON_WIFI,a->wifi_connected?2:(a->wifi_known&&a->wifi_on?1:0),"Wi-Fi",wifi,A_QS_WIFI);
    bt_tile_status(a,status,sizeof(status));
    qs_big_tile(a,(Rect){368,QS_TOP,324,132},ICON_BLUETOOTH,bt_tile_level(a),"Bluetooth",status,A_QS_BT);
    int y=QS_TOP+148;
    /* Four in the row: the browser joined them (2026-11-22, the owner), lit while its engine runs. */
    qs_small_tile(a,(Rect){28,y,154,128},ICON_TORCH,a->torch_on,"Flashlight",A_QS_TORCH);
    qs_small_tile(a,(Rect){198,y,154,128},a->sound_available&&a->sound_volume==0?ICON_MUTE:ICON_SPEAKER,false,"Sound",A_QS_SOUND);
    qs_small_tile(a,(Rect){368,y,154,128},ICON_BROWSER,a->web_fd>=0,"Browser",A_QS_BROWSER);
    qs_small_tile(a,(Rect){538,y,154,128},ICON_GEAR,false,"Settings",A_QS_SETTINGS);
    y=qs_row_brightness();
    {Rect card={28,y,664,132};rounded(a,card,28,PANEL);icon(a,ICON_SUN,50,y+18,42,TEXT);text(a,108,y+22,1,TEXT,"Brightness");
     /* The brightness is the panel's own: it answers while any work runs (its helper is not the job's). */
     bool usable=display_slider_ready(a);unsigned int percent=a->display_brightness_drag?a->display_preview_percent:(a->display_wanted_percent?a->display_wanted_percent:a->display_percent);
     char p[16];if(usable)snprintf(p,sizeof(p),"%u%%",percent);else copy(p,sizeof(p),"—");text(a,668-text_width(p,1),y+22,1,TEXT,p);
     qs_slider(a,card,percent,usable,A_QS_BRIGHTNESS);}
    y+=148;
    if(a->qs.expanded||a->qs.height>qs_compact_height(a)+8){
        if(torch_ready(a)){
            Rect card={28,y,664,132};rounded(a,card,28,PANEL);icon(a,ICON_TORCH,50,y+18,42,TEXT);text(a,108,y+22,1,TEXT,"Flashlight");
            char level[24];snprintf(level,sizeof(level),"%u / %u",a->torch_level,a->torch_max);text(a,668-text_width(level,1),y+22,1,TEXT,level);
            unsigned int percent=a->torch_max>1?(a->torch_level-1)*100u/(a->torch_max-1):100u;qs_slider(a,card,percent,true,A_QS_TORCH_BAR);y+=148;
        }
        {Rect card={28,y,664,132};rounded(a,card,28,PANEL);icon(a,a->sound_volume==0?ICON_MUTE:ICON_SPEAKER,50,y+18,42,TEXT);text(a,108,y+22,1,TEXT,"Sound volume");
         char p[16];if(a->sound_available)snprintf(p,sizeof(p),"%d%%",a->sound_volume);else copy(p,sizeof(p),"—");text(a,668-text_width(p,1),y+22,1,TEXT,p);
         /* Where the sound goes, as Android's output switcher (2026-11-22, the owner: a choice of the device the
            sound plays on, for Bluetooth headsets): the speaker or a connected audio device, for the player and
            the browser alike. The pill names the output now and opens the list. */
         {const char*out=player_output_label(a);bool bt=!strncmp(a->mu.output,"bluealsa",8);
          int left=108+text_width("Sound volume",1)+20,right=668-text_width(p,1)-20,w=right-left;
          if(w>=140){int tw=text_width(out,0);int pw=tw+96;if(pw>w)pw=w;Rect pill={right-pw,y+12,pw,52};
           surface(a,pill,26,bt?ORANGE_DARK:PANEL2,A_QS_OUTPUT);icon(a,bt?ICON_HEADPHONES:ICON_SPEAKER,pill.x+14,pill.y+11,30,bt?ORANGE:TEXT);
           raw_text(true);ellipsis(a,pill.x+52,pill.y+12,pill.w-88,0,TEXT,out);raw_text(false);icon(a,ICON_CHEVRON,pill.x+pill.w-36,pill.y+14,24,MUTED);
           register_button(a,pill,A_QS_OUTPUT,true,0);}}
         qs_slider(a,card,a->sound_available?(unsigned int)a->sound_volume:0u,a->sound_available,A_QS_VOLUME);y+=148;}
        if(shade_media(a)){qs_media_card(a,y,true);y+=236;}
        if(shade_job(a)){qs_job_card(a,y);y+=166;}
    }else if(shade_media(a)){qs_media_card(a,y,false);y+=196;}
    rounded(a,(Rect){CW/2-48,h-30,96,10},5,MUTED);
    a->clip_active=false;
}

/* --- touch ------------------------------------------------------------------------------------------ */
static int qs_button_at(const App*a,int x,int y){
    for(int n=a->button_count-1;n>=0;n--)if(a->buttons[n].enabled&&inside(a->buttons[n].r,x,y))return a->buttons[n].action;
    return 0;
}
static unsigned int qs_slider_percent(int x){if(x<=76)return 0;if(x>=644)return 100;return (unsigned int)((x-76)*100+284)/568u;}
static void qs_slide(App*a,int x,bool done){
    unsigned int p=qs_slider_percent(x);
    switch(a->qs.slider){
    case QS_SLIDER_BRIGHTNESS:{unsigned int percent=p<1?1:p;a->display_preview_percent=percent;
        if(a->now-a->display_live_at>=24||done){a->display_live_at=a->now;a->display_live_percent=percent;(void)brightness_direct(a,percent);}
        if(done){a->saved_brightness=percent;settings_changed(a);if(a->display_control.pid)a->display_wanted_percent=percent;else if(percent!=a->display_percent)(void)start_display_control(a,DC_BRIGHTNESS,percent);}
        break;}
    case QS_SLIDER_TORCH:if(torch_ready(a)&&a->torch_max)torch_choose(a,1u+p*(a->torch_max-1u)/100u);break;
    case QS_SLIDER_VOLUME:if(a->sound_available)sound_set(a,(int)p);break;
    case QS_SLIDER_SEEK:if(done&&a->media.duration_ms){a->media_seek_ms=(uint32_t)((uint64_t)a->media.duration_ms*qs_slider_percent((x-128)*568/472+76)/100u);media_card_control(a,A_QS_MEDIA_SEEK);}break;
    }
    a->dirty=true;
}
static void qs_tap(App*a,int id){
    switch(id){
    case A_QS_WIFI:qs_close(a);if(nav_page(a)!=WIFI)tap_action(a,A_WIFI);break;
    case A_QS_BT:bt_tile_toggle(a);break;
    case A_QS_TORCH:if(torch_ready(a))torch_set(a,!a->torch_on,a->torch_level);break;
    case A_QS_SOUND:if(a->sound_available){if(a->sound_volume){a->qs.mute_restore=(uint32_t)a->sound_volume;sound_set(a,0);}else sound_set(a,a->qs.mute_restore?(int)a->qs.mute_restore:30);}break;
    case A_QS_GEAR:case A_QS_SETTINGS:qs_close(a);if(nav_page(a)!=TOOLS)tap_action(a,A_TOOLS);break;
    case A_QS_JOB:qs_close(a);if(a->job.pid&&a->screen!=PROGRESS)screen(a,PROGRESS);break;
    /* Where the sound goes: the list over the page the shade was pulled over (2026-11-22). */
    case A_QS_OUTPUT:qs_close(a);action(a,A_PL_OUTPUT);break;
    /* The browser, from anywhere the shade opens, an operation running or not (it needs no storage). */
    case A_QS_BROWSER:qs_close(a);
        /* Its window, when it floats: brought back from its bubble, over the page in use. */
        if(a->wf.open&&a->web_fd>=0&&a->screen!=WEB_BROWSER)a->wf.bubble=false;
        else if(a->screen!=WEB_BROWSER)screen(a,WEB_BROWSER);
        break;
    case A_QS_MEDIA_OPEN:qs_close(a);if(a->media.source==MEDIA_BROWSER)screen(a,WEB_BROWSER);else tap_action(a,A_PLAYER);break;
    case A_QS_MEDIA_PREV:case A_QS_MEDIA_PLAY:case A_QS_MEDIA_NEXT:media_card_control(a,id);break;
    }
    haptic(a,1);a->dirty=true;
}
static void qs_hold(App*a,int id){
    if(id==A_QS_BT){qs_close(a);tap_action(a,A_BLUETOOTH);haptic(a,2);}
    else if(id==A_QS_WIFI){qs_close(a);tap_action(a,A_WIFI);haptic(a,2);}
}
/* Every touch while the shade shows, and the pull from the status bar. Returns whether it took the touch. */
static bool shade_pointer(App*a,bool down,int x,int y){
    Shade*s=&a->qs;
    if(!s->visible){
        if(!qs_can_open(a))return false;
        if(down&&!a->pointer_down&&!s->armed&&y<STATUS_ZONE_Y){s->armed=true;s->arm_x=x;s->arm_y=y;return false;}
        if(!s->armed)return false;
        if(!down){s->armed=false;return false;}
        if(y-s->arm_y<QS_PULL_START)return false;
        /* The finger came down from the status bar: the shade follows it from now on. */
        s->armed=false;a->status_down=false;a->status_tap_at=0;
        if(!qs_capture(a))return false;
        /* The page lets go of the finger; the shade keeps it (cancel_pointer would have the rest of this
           touch swallowed until it lifts, and the shade stayed a few pixels open: 2026-11-22, on the phone). */
        cancel_pointer(a);a->pointer_requires_release=false;a->pointer_down=true;
        s->visible=true;s->dragging=true;s->expanded=false;s->height=(float)y;s->down_height=0;s->down_y=s->arm_y;s->settle_at=0;
        s->last_y=y;s->last_at=a->now;s->velocity=0;s->slider=QS_SLIDER_NONE;s->moved=true;a->dirty=true;return true;
    }
    if(down&&!a->pointer_down){
        a->pointer_down=true;s->down_x=x;s->down_y=y;s->down_at=a->now;s->down_height=s->height;s->moved=false;s->held=false;
        s->last_y=y;s->last_at=a->now;s->velocity=0;s->slider=QS_SLIDER_NONE;s->settle_at=0;s->target=s->height;
        s->press=y<s->height?qs_button_at(a,x,y):0;a->pressed_action=s->press;
        if(s->press==A_QS_BRIGHTNESS&&display_slider_ready(a)){s->slider=QS_SLIDER_BRIGHTNESS;a->display_brightness_drag=true;a->display_drag_x=x;}
        else if(s->press==A_QS_TORCH_BAR)s->slider=QS_SLIDER_TORCH;
        else if(s->press==A_QS_VOLUME)s->slider=QS_SLIDER_VOLUME;
        else if(s->press==A_QS_MEDIA_SEEK)s->slider=QS_SLIDER_SEEK;
        if(s->slider){qs_slide(a,x,false);s->moved=true;}
        a->dirty=true;return true;
    }
    if(!a->pointer_down)return true;
    if(down){
        if(a->now>s->last_at){float v=(float)(y-s->last_y)/(float)(a->now-s->last_at);s->velocity=s->velocity*0.4f+v*0.6f;s->last_y=y;s->last_at=a->now;}
        if(s->slider){qs_slide(a,x,false);return true;}
        if(!s->moved&&(abs(x-s->down_x)>QS_TAP_SLOP||abs(y-s->down_y)>QS_TAP_SLOP)){s->moved=true;a->pressed_action=0;s->press=0;
            if(abs(y-s->down_y)>=abs(x-s->down_x)){s->dragging=true;s->down_y=y;}}
        if(s->dragging){
            float h=s->down_height+(float)(y-s->down_y),top=(float)qs_height_max(a);
            if(h>top)h=top+(h-top)*0.25f;
            if(h<0)h=0;
            s->height=h;if(h>qs_compact_height(a)+24)s->expanded=true;a->dirty=true;
        }
        else if(!s->moved&&!s->held&&s->press&&a->now-s->down_at>=QS_HOLD_MS&&(s->press==A_QS_BT||s->press==A_QS_WIFI)){s->held=true;a->pressed_action=0;qs_hold(a,s->press);}
        return true;
    }
    /* The finger let go. */
    a->pointer_down=false;a->pressed_action=0;
    if(s->slider){qs_slide(a,x,true);if(s->slider==QS_SLIDER_BRIGHTNESS)a->display_brightness_drag=false;s->slider=QS_SLIDER_NONE;a->dirty=true;return true;}
    if(s->dragging){qs_release(a);return true;}
    if(s->held){s->held=false;return true;}
    if(!s->moved){
        if(s->down_y>=s->height)qs_close(a);  /* beside the panel */
        else{
            int id=qs_button_at(a,x,y);
            if(id&&id==s->press)qs_tap(a,id);
            else if(!id&&s->down_y>s->height-70){a->qs.expanded=!a->qs.expanded;qs_settle(a,(float)(a->qs.expanded?qs_height_max(a):qs_compact_height(a)));}
        }
    }
    s->press=0;a->dirty=true;return true;
}
#endif
