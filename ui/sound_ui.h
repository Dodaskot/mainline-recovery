/* Sound volume (2026-11-20, the owner: sound with the aux jack and a volume setting).
 *
 * sound.py (started by init) loads the card, routes the speaker or the headphones and creates the
 * user control "Recovery Playback Volume", the softvol that the browser's ALSA configuration plays
 * through. The interface reads and writes that control itself, with the ALSA control ioctls: a key
 * press changes the level at once, without starting a helper. Settings shows it with − and +; in
 * the browser the volume keys change it and show Android's panel at the right edge, which a finger
 * can drag. While the panel shows, the page goes through the interface's full frame (the main loop
 * leaves the direct page path), so the panel lies over the video; then frames go direct again. */
#include <sound/asound.h>

#define SOUND_CONTROL "Recovery Playback Volume"
#define SOUND_STEP 5
#define SOUND_SHOW_MS 3000u
/* A held key keeps stepping, as on Android: after SOUND_REPEAT_DELAY_MS, every SOUND_REPEAT_MS. */
#define SOUND_REPEAT_DELAY_MS 400u
#define SOUND_REPEAT_MS 90u
/* Android's panel slides in from the right edge and back out (2026-11-20, the owner's video):
 * in over SOUND_IN_MS, slowing at the end; out over SOUND_OUT_MS once SOUND_SHOW_MS have passed. */
#define SOUND_IN_MS 260u
#define SOUND_OUT_MS 220u
static void sound_show(App*a);
/* Android's volume panel: a pill at the right edge, over the page, that a finger can drag. */
static Rect sound_panel_rect(void){return (Rect){628,420,76,440};}
/* A video full screen on its side (its top along the panel's right edge): the panel stands upright for
   the one who holds the phone, at their right, which is the panel's bottom edge, and rises toward its
   top, the panel's right (2026-11-21, #6: it stayed upright for the panel and went the wrong way). */
static bool sound_sideways(const App*a){return a->screen==WEB_BROWSER&&a->web_fullscreen=='L';}
static Rect sound_rect(const App*a){return sound_sideways(a)?(Rect){140,CH-16-76,440,76}:sound_panel_rect();}

/* 0..100 from the control (count 1 or 2, integer); false without the card or the control. */
static bool sound_control_io(App*a,bool write,int*percent){
    if(!a->device){if(write)a->sound_fixture_volume=*percent;else *percent=a->sound_fixture_volume;return a->sound_fixture_volume>=0;}
    int fd=open("/dev/snd/controlC0",O_RDWR|O_CLOEXEC);if(fd<0)return false;
    struct snd_ctl_elem_info info;memset(&info,0,sizeof(info));
    info.id.iface=SNDRV_CTL_ELEM_IFACE_MIXER;copy((char*)info.id.name,sizeof(info.id.name),SOUND_CONTROL);
    bool ok=ioctl(fd,SNDRV_CTL_IOCTL_ELEM_INFO,&info)==0&&info.type==SNDRV_CTL_ELEM_TYPE_INTEGER&&
            info.count>=1&&info.count<=2&&info.value.integer.max>info.value.integer.min;
    if(ok){
        long lo=info.value.integer.min,hi=info.value.integer.max;
        struct snd_ctl_elem_value value;memset(&value,0,sizeof(value));value.id=info.id;
        if(write){
            int p=*percent<0?0:*percent>100?100:*percent;long level=lo+((hi-lo)*p+50)/100;
            for(unsigned int c=0;c<info.count;c++)value.value.integer.value[c]=level;
            ok=ioctl(fd,SNDRV_CTL_IOCTL_ELEM_WRITE,&value)==0;
        }else{
            ok=ioctl(fd,SNDRV_CTL_IOCTL_ELEM_READ,&value)==0;
            if(ok){long level=value.value.integer.value[0];*percent=(int)(((level-lo)*100+(hi-lo)/2)/(hi-lo));}
        }
    }
    close(fd);return ok;
}

/* The jack's state, from the card's "Headphone Jack" control. */
static bool sound_headphones_in(App*a){
    if(!a->device)return a->sound_fixture_headphones;
    int fd=open("/dev/snd/controlC0",O_RDWR|O_CLOEXEC);if(fd<0)return false;
    struct snd_ctl_elem_value value;memset(&value,0,sizeof(value));
    value.id.iface=SNDRV_CTL_ELEM_IFACE_CARD;copy((char*)value.id.name,sizeof(value.id.name),"Headphone Jack");
    bool in=ioctl(fd,SNDRV_CTL_IOCTL_ELEM_READ,&value)==0&&value.value.integer.value[0];
    close(fd);return in;
}

static void sound_refresh(App*a){
    int percent=0;a->sound_available=sound_control_io(a,false,&percent);
    if(a->sound_available){a->sound_volume=percent;a->sound_headphones=sound_headphones_in(a);}
    a->sound_checked_at=a->now;
}

static void sound_set(App*a,int percent){
    percent=percent<0?0:percent>100?100:percent;
    if(sound_control_io(a,true,&percent)){
        a->sound_volume=percent;a->sound_available=true;
        /* Kept in the settings and set again at the next start (2026-11-22: it came back at 60 % after every
           restart). settings_changed gathers the steps of a key or a finger into one save. */
        if(a->sound_restored&&a->sound_saved!=percent){a->sound_saved=percent;settings_changed(a);}
    }
    else{
        /* A level that cannot be written (the control held by another, 2026-11-20 on YouTube) keeps the
           panel up with the level as it is, instead of hiding it at every step. */
        int now=0;a->sound_available=sound_control_io(a,false,&now);if(a->sound_available)a->sound_volume=now;
    }
    a->dirty=true;
}

/* The volume keys, on every screen as on Android (2026-11-20, the owner: "everywhere"); true when
 * the key was taken. On a phone without a touchscreen (no driver for its touch part) they keep moving
 * the focus until a touch is seen, as they are the only way around there; without a sound card too. */
static bool sound_key(App*a,unsigned code,int value){
    if(code!=KEY_VOLUMEUP&&code!=KEY_VOLUMEDOWN)return false;
    if(!a->touch_seen||a->screen==LOCKSCREEN||a->screen==SPLASH)return false;
    if(!a->sound_available||a->now-a->sound_checked_at>5000u)sound_refresh(a);
    if(!a->sound_available)return false;
    if(value==1){
        a->sound_key_from=a->sound_volume;
        sound_set(a,a->sound_volume+(code==KEY_VOLUMEUP?SOUND_STEP:-SOUND_STEP));
        sound_show(a);
        a->sound_key_held=code;a->sound_key_next=a->now+SOUND_REPEAT_DELAY_MS;
    }else if(value==0&&a->sound_key_held==code)a->sound_key_held=0;
    /* The kernel's own repeats (value 2) are left out: sound_tick repeats at its own pace, the same
       with keys that never repeat. */
    return true;
}

static float sound_ease(float t){float u=1.f-t;return 1.f-u*u*u;}
/* 0: hidden, 1: in place; the panel's way in and out. */
static float sound_visibility(const App*a){
    if(!a->sound_available||!a->sound_shown_until)return 0.f;
    if(a->now>=a->sound_shown_until){uint64_t d=a->now-a->sound_shown_until;return d>=SOUND_OUT_MS?0.f:1.f-sound_ease((float)d/(float)SOUND_OUT_MS);}
    uint64_t d=a->now>a->sound_shown_at?a->now-a->sound_shown_at:0;return d>=SOUND_IN_MS?1.f:sound_ease((float)d/(float)SOUND_IN_MS);
}
/* Drawn (also while it slides), and open for a finger (only before it starts to leave). */
static bool sound_overlay_active(const App*a){return a->sound_available&&a->sound_shown_until&&a->now<a->sound_shown_until+SOUND_OUT_MS;}
static bool sound_panel_open(const App*a){return a->sound_available&&a->now<a->sound_shown_until;}
static bool sound_animating(const App*a){if(!sound_overlay_active(a))return false;float v=sound_visibility(a);return v<1.f;}
/* Shown, or kept: a panel that is on its way out comes back from where it is. */
static void sound_show(App*a){
    if(!sound_panel_open(a))a->sound_shown_at=a->now-(uint64_t)(sound_visibility(a)*(float)SOUND_IN_MS*.5f);
    a->sound_shown_until=a->now+SOUND_SHOW_MS;a->dirty=true;
}

/* The main loop: a held key steps on until it is released; the level disappears SOUND_SHOW_MS
 * after the last change. */
static void sound_tick(App*a){
    /* The saved volume, once the settings are read and the card is there: sound.py starts the card at its own
       level before the settings are known. Until then a change is not saved over the setting. */
    if(a->sound_settings_read&&!a->sound_restored){
        if(!a->sound_restore_until)a->sound_restore_until=a->now+30000u;
        if(!a->sound_checked_at||a->now-a->sound_checked_at>1000u)sound_refresh(a);
        if(a->sound_available){
            a->sound_restored=true;
            if(a->sound_saved>=0&&a->sound_saved<=100&&a->sound_saved!=a->sound_volume)sound_set(a,a->sound_saved);
        }else if(a->now>=a->sound_restore_until)a->sound_restored=true;  /* no card: given up, changes are saved */
        else a->dirty=true;  /* the loop comes back for the card */
    }
    if(a->sound_key_held&&a->now>=a->sound_key_next){
        int target=a->sound_volume+(a->sound_key_held==KEY_VOLUMEUP?SOUND_STEP:-SOUND_STEP);
        sound_set(a,target);  /* clamped to 0..100 */
        a->sound_key_next=a->now+SOUND_REPEAT_MS;sound_show(a);
    }
    if(sound_animating(a))a->dirty=true;
    if(a->sound_shown_until&&a->now>=a->sound_shown_until+SOUND_OUT_MS){a->sound_shown_until=0;a->dirty=true;}
}


/* The level on the sideways panel, upright for the one who holds the phone (2026-11-21, the owner: the
   percent was missing on its side). The number is drawn as usual into a scratch strip of the frame on the
   fill's colour, read back, the strip put back, and its text pixels laid on the fill turned a quarter:
   the glyphs' rows run along the panel (canvas +y is the holder's right, canvas -x their down). */
static void sound_sideways_label(App*a,Rect r,const char*label){
    Rect strip={r.x+8,r.y,r.h,56};              /* as the holder reads it: as wide as the panel is thick */
    if(strip.x<0||strip.y<0||strip.x+strip.w>CW||strip.y+strip.h>CH||strip.h+8>r.w)return;
    int x0=nx(strip.x),y0=nx(strip.y),w=nx(strip.x+strip.w)-x0,h=nx(strip.y+strip.h)-y0;
    if(w<=0||h<=0||x0+w>NW||y0+h>NH||x0+h>NW||y0+w>NH)return;
    uint32_t*saved=malloc((size_t)w*(size_t)h*sizeof(uint32_t)),*glyph=malloc((size_t)w*(size_t)h*sizeof(uint32_t));
    if(!saved||!glyph){free(saved);free(glyph);return;}
    for(int y=0;y<h;y++)memcpy(saved+(size_t)y*(size_t)w,a->pixels+(size_t)(y0+y)*NW+(size_t)x0,(size_t)w*sizeof(uint32_t));
    rounded(a,strip,0,ORANGE);uint32_t fill=a->pixels[(size_t)y0*NW+(size_t)x0];
    raw_text(true);centered(a,strip,0,ON_ORANGE,label);raw_text(false);
    for(int y=0;y<h;y++){
        memcpy(glyph+(size_t)y*(size_t)w,a->pixels+(size_t)(y0+y)*NW+(size_t)x0,(size_t)w*sizeof(uint32_t));
        memcpy(a->pixels+(size_t)(y0+y)*NW+(size_t)x0,saved+(size_t)y*(size_t)w,(size_t)w*sizeof(uint32_t));
    }
    /* Glyph (gx,gy) to the frame: x from the strip's left by h-1-gy, y down by gx. */
    for(int gy=0;gy<h;gy++)for(int gx=0;gx<w;gx++){
        uint32_t c=glyph[(size_t)gy*(size_t)w+(size_t)gx];
        if(c!=fill)a->pixels[(size_t)(y0+gx)*NW+(size_t)(x0+h-1-gy)]=c;
    }
    free(saved);free(glyph);
}

/* Over every screen: the panel at the right edge (drawn last, with the toast). */
static void render_sound_overlay(App*a){
    if(!sound_overlay_active(a))return;
    bool clipped=a->clip_active;a->clip_active=false;
    bool sideways=sound_sideways(a);Rect r=sound_rect(a);
    /* Slides in from beyond its edge and narrows a little as it leaves, as Android's does. No shadow: on a
       light page it showed as a pale rounded band under the panel (2026-11-21, #7). */
    float v=sound_visibility(a);
    if(sideways){
        r.y+=(int)((1.f-v)*(float)(CH-r.y+24));
        if(a->now>=a->sound_shown_until){int narrow=(int)((1.f-v)*(float)(r.h-20));r.y+=narrow/2;r.h-=narrow;}
        if(r.y>=CH){a->clip_active=clipped;return;}
        rounded(a,(Rect){r.x-6,r.y-6,r.w+12,r.h+12},(r.h+12)/2,PANEL);
        rounded(a,r,r.h/2,PANEL2);
        int fill=(r.w-8)*a->sound_volume/100;if(fill<r.h-8)fill=r.h-8;
        rounded(a,(Rect){r.x+4,r.y+4,fill,r.h-8},(r.h-8)/2,ORANGE);
        /* The number on the filled end, as upright (portrait) shows it at its bottom; only while in place. */
        if(v>=1.f&&a->now<a->sound_shown_until){char label[8];snprintf(label,sizeof(label),"%d",a->sound_volume);sound_sideways_label(a,r,label);}
        a->clip_active=clipped;return;
    }
    r.x+=(int)((1.f-v)*(float)(CW-r.x+24));
    if(a->now>=a->sound_shown_until){int narrow=(int)((1.f-v)*(float)(r.w-20));r.x+=narrow/2;r.w-=narrow;}
    if(r.x>=CW){a->clip_active=clipped;return;}
    rounded(a,(Rect){r.x-6,r.y-6,r.w+12,r.h+12},(r.w+12)/2,PANEL);
    rounded(a,r,r.w/2,PANEL2);
    int fill=(r.h-8)*a->sound_volume/100;if(fill<r.w-8)fill=r.w-8;
    rounded(a,(Rect){r.x+4,r.y+r.h-4-fill,r.w-8,fill},(r.w-8)/2,ORANGE);
    char label[8];snprintf(label,sizeof(label),"%d",a->sound_volume);
    /* The number sits on the filled part: the theme's colour for text on the accent (#7). */
    raw_text(true);centered(a,(Rect){r.x,r.y+r.h-64,r.w,56},0,ON_ORANGE,label);raw_text(false);
    a->clip_active=clipped;
}

static void sound_from_point(App*a,int x,int y){
    Rect r=sound_rect(a);
    int percent=sound_sideways(a)?(x-r.x-4)*100/(r.w-8):(r.y+r.h-4-y)*100/(r.h-8);
    sound_set(a,percent);
}

/* A finger on the panel sets the level by its height; the page never sees that touch. A touch beside the
   open panel puts it away, as on Android (2026-11-21, the owner); that touch too reaches nothing under it
   (a video does not pause), up to its release. */
static bool sound_pointer(App*a,bool down,int x,int y){
    if(a->sound_swallow){if(!down){a->sound_swallow=false;a->pointer_down=false;a->pressed_action=0;}return true;}
    if(a->sound_drag){
        if(down)sound_from_point(a,x,y);
        else{a->sound_drag=false;a->pointer_down=false;}
        sound_show(a);return true;
    }
    Rect r=sound_rect(a);
    if(down&&!a->pointer_down&&sound_panel_open(a)&&x>=r.x-24&&x<r.x+r.w+16&&y>=r.y-24&&y<r.y+r.h+24){
        a->sound_drag=a->pointer_down=true;a->pressed_action=0;sound_from_point(a,x,y);
        sound_show(a);return true;
    }
    if(down&&!a->pointer_down&&sound_panel_open(a)){
        a->sound_shown_until=a->now;a->sound_key_held=0;a->sound_swallow=a->pointer_down=true;a->pressed_action=0;a->dirty=true;
        return true;
    }
    return false;
}

/* Settings: the level as the brightness slider shows its own (2026-11-21, the owner: the same behaviour as
   brightness; a tester, #7: the bar answered only − and +). A track with a handle; a finger anywhere on
   it takes the level under it, and while it drags the handle stays under the finger. Where the sound
   goes beside the title, the level at the right. Returns the height it took. */
static int sound_slider_percent(int x){if(x<=76)return 0;if(x>=644)return 100;return ((x-76)*100+284)/568;}
static int render_sound_card(App*a,int y,bool free_ui){
    (void)free_ui;
    if(!a->sound_checked_at||a->now-a->sound_checked_at>2000u)sound_refresh(a);
    rounded(a,(Rect){28,y,664,212},24,PANEL);icon_tile(a,ICON_TUNE,46,y+16,56,ICON_FILL);text(a,120,y+14,1,TEXT,"Sound");
    ellipsis(a,120,y+52,420,0,MUTED,!a->sound_available?"No sound card":(a->sound_headphones?"Headphones":"Speaker"));
    bool ready=a->sound_available;int percent=ready?a->sound_volume:0;
    char level[16];if(ready)snprintf(level,sizeof(level),"%d%%",percent);else copy(level,sizeof(level),"—");
    text(a,668-text_width(level,1),y+14,1,ready?TEXT:MUTED,level);
    int track=y+128,knob=a->sound_bar_drag?(a->sound_drag_x<76?76:(a->sound_drag_x>644?644:a->sound_drag_x)):76+percent*568/100;
    rounded(a,(Rect){76,track-8,568,16},8,PANEL2);
    if(ready&&knob>=92)rounded(a,(Rect){76,track-8,knob-76,16},8,ORANGE);
    if(a->sound_bar_drag)veil(a,(Rect){knob-40,track-40,80,80},40,ORANGE,50);
    int thumb=a->sound_bar_drag?24:20;
    vector_circle(a,knob,track,thumb,thumb,ready?ORANGE:MUTED);
    vector_circle(a,knob,track,thumb-5,thumb-5,ui_theme->knob);
    text(a,52,y+164,0,MUTED,"0%");text(a,668-text_width("100%",0),y+164,0,MUTED,"100%");
    a->sound_bar_rect=(Rect){52,y+80,616,100};
    return 224;
}

static bool sound_action(App*a,int id){
    if(id!=A_SOUND_DOWN&&id!=A_SOUND_UP)return false;
    sound_refresh(a);
    if(a->sound_available)sound_set(a,a->sound_volume+(id==A_SOUND_UP?SOUND_STEP:-SOUND_STEP));
    return true;
}
