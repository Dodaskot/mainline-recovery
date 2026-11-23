/* Recent screens, as Android's overview (2026-11-20, the owner's video): a swipe up that holds, or the
 * third navigation button, shows a card for each page left behind (the browser, files, the terminal,
 * settings...) with its picture as it was left. A tap opens it as it was, a card swiped up is closed,
 * Clear all closes them all. Cards are side by side, the latest in the middle and older ones to the
 * left, and a finger moves them sideways. The browser's card goes, its session stays (2026-11-22, the
 * owner: its tabs, page and video were gone with the card); the browser quits from its own menu.
 *
 * Only pages that can be opened again as they were (nav_stays) get a card; one per app, so Files is
 * one card whichever folder it shows. The browser keeps running behind the other pages (screen()). */
#define RECENTS_MAX 8
/* Half the screen's pixels each, averaged 2x2, drawn smooth (2026-11-20, the owner: sharper cards). */
#define RECENT_W (NW/2)
#define RECENT_H (NH/2)
#define RECENT_CARD_W 440
#define RECENT_CARD_H (RECENT_CARD_W*CH/CW)
#define RECENT_CARD_Y 236
#define RECENT_GAP 40
#define RECENTS_IN_MS 240u
#define RECENTS_SNAP_MS 200u
#define RECENTS_CLOSE_DRAG 260

static bool nav_stays(enum Screen s);
static void terminal_leave(App*a);

static const char*recents_title(enum Screen s,const char*heading){
    switch(s){
    case WEB_BROWSER:return "Browser";
    case FILE_VOLUMES:case FILE_VOLUME:case FILE_BROWSER:return "Files";
    case TERMINAL:return "Terminal";
    case TOOLS:case DISPLAY_SETTINGS:case AUTOMOUNT_SETTINGS:case ANDROID_PASSWORD_SETTINGS:case WIFI:case THEME:
    case TERMINAL_THEME:case ANIMATIONS:case LANGUAGE:return "Settings";
    case USB_FILES:return "USB files";
    default:return heading&&heading[0]?heading:"Recovery";
    }
}
static bool recents_note_wanted(enum Screen s){return s!=HOME&&s!=RECENTS&&nav_stays(s);}

/* The pictures live in a fixed pool, never freed: an App copied whole (the page walk of the tests)
 * keeps valid pointers, and memory does not fragment. */
static uint32_t recents_pool[RECENTS_MAX+1][RECENT_W*RECENT_H];
static uint32_t*recents_slot(const App*a){
    for(int k=0;k<=RECENTS_MAX;k++){bool used=false;for(int n=0;n<a->recent_count;n++)if(a->recents[n].shot==recents_pool[k])used=true;if(!used)return recents_pool[k];}
    return NULL;
}
static void recents_drop(App*a,int index){
    for(int n=index;n+1<a->recent_count;n++)a->recents[n]=a->recents[n+1];
    a->recent_count--;memset(&a->recents[a->recent_count],0,sizeof(a->recents[0]));
}

/* The page being left becomes the first card, with a picture of it (every 4th pixel). */
static void recents_note(App*a,enum Screen leaving){
    if(!recents_note_wanted(leaving))return;
    const char*title=recents_title(leaving,a->heading_title);
    for(int n=0;n<a->recent_count;n++)if(!strcmp(a->recents[n].title,tr(title))||a->recents[n].screen==leaving){recents_drop(a,n);break;}
    if(a->recent_count==RECENTS_MAX)recents_drop(a,RECENTS_MAX-1);
    for(int n=a->recent_count;n>0;n--)a->recents[n]=a->recents[n-1];
    memset(&a->recents[0],0,sizeof(a->recents[0]));a->recent_count++;
    a->recents[0].screen=leaving;copy(a->recents[0].title,sizeof(a->recents[0].title),tr(title));
    /* The page as it is, drawn again without the navigation, a gesture's hint, a toast or the volume
       panel (2026-11-20: the hold's square and the handle showed in the card). */
    if(a->screen==leaving){enum Screen kept=a->screen;a->recents_capturing=true;render(a);a->recents_capturing=false;a->screen=kept;}
    else if(leaving==WEB_BROWSER)web_sync_pixels(a);
    a->recents[0].shot=NULL;a->recents[0].shot=recents_slot(a);
    if(a->recents[0].shot)for(int y=0;y<RECENT_H;y++){
        const uint32_t*r0=a->pixels+(size_t)(y*2)*NW,*r1=r0+NW;uint32_t*out=a->recents[0].shot+(size_t)y*RECENT_W;
        for(int x=0;x<RECENT_W;x++){
            uint32_t p[4]={r0[2*x],r0[2*x+1],r1[2*x],r1[2*x+1]};uint32_t rb=0,g=0;
            for(int k=0;k<4;k++){rb+=p[k]&0xff00ffu;g+=p[k]&0x00ff00u;}
            out[x]=((rb>>2)&0xff00ffu)|((g>>2)&0x00ff00u)|0xff000000u;
        }
    }
}

static float recents_ease(uint64_t start,uint64_t now,unsigned int ms){
    if(!start||now>=start+ms)return 1.f;
    float t=(float)(now-start)/(float)ms,u=1.f-t;return 1.f-u*u*u;
}
static int64_t recents_max_scroll(const App*a){return a->recent_count>1?(int64_t)(a->recent_count-1)*(RECENT_CARD_W+RECENT_GAP):0;}
static int64_t recents_offset(const App*a){
    if(a->recents_snap_at&&a->now<a->recents_snap_at+RECENTS_SNAP_MS){
        float e=recents_ease(a->recents_snap_at,a->now,RECENTS_SNAP_MS);
        return a->recents_snap_from+(int64_t)((float)(a->recents_snap_to-a->recents_snap_from)*e);
    }
    return a->recents_scroll;
}
static bool recents_animating(const App*a){
    return a->screen==RECENTS&&(recents_ease(a->recents_at,a->now,RECENTS_IN_MS)<1.f||
                                (a->recents_snap_at&&a->now<a->recents_snap_at+RECENTS_SNAP_MS));
}
static Rect recents_card(const App*a,int index){
    int lift=(int)((1.f-recents_ease(a->recents_at,a->now,RECENTS_IN_MS))*240.f);
    Rect r={CW/2-RECENT_CARD_W/2-index*(RECENT_CARD_W+RECENT_GAP)+(int)recents_offset(a),RECENT_CARD_Y+lift,RECENT_CARD_W,RECENT_CARD_H};
    if(index==a->recents_card&&a->recents_dragging&&!a->recents_sideways)r.y+=a->recents_dy;
    return r;
}
static Rect recents_clear_rect(void){return (Rect){CW/2-170,RECENT_CARD_Y+RECENT_CARD_H+56,340,84};}

/* The overview, over a blurred picture of where it was opened. */
static void recents_open(App*a){
    if(a->screen==RECENTS)return;
    recents_note(a,a->screen);
    if(!a->menu_backdrop)a->menu_backdrop=malloc((size_t)NW*NH*sizeof(uint32_t));
    if(a->menu_backdrop){web_sync_pixels(a);canvas_blur(a->menu_backdrop,a->pixels);canvas_rect(a->menu_backdrop,(Bounds){0,0,NW,NH},0,0,NW,NH,BG,110);}
    a->recents_return=a->screen;a->recents_scroll=0;a->recents_snap_at=0;a->recents_dragging=false;a->recents_card=-1;
    a->recents_at=a->now?a->now:1;
    screen(a,RECENTS);
}

/* A card closed: its page is left. The browser's card is only a card: its engine, tabs, page and what
   plays go on (2026-11-22, the owner: a card swiped away, or Clear all, ended the browser's session). */
static void recents_close(App*a,int index){
    if(index<0||index>=a->recent_count)return;
    /* The terminal's card: its session ends, a running command too (as Android ends an app). */
    if(a->recents[index].screen==TERMINAL&&terminal_session_open(a)){if(!a->terminal_left)terminal_leave(a);a->terminal_close_requested=true;}
    recents_drop(a,index);
    if(a->recents_scroll>recents_max_scroll(a))a->recents_scroll=recents_max_scroll(a);
    a->dirty=true;
}
static void recents_clear(App*a){while(a->recent_count)recents_close(a,a->recent_count-1);screen(a,HOME);}

static void recents_snap(App*a,int64_t target){
    target=target<0?0:(target>recents_max_scroll(a)?recents_max_scroll(a):target);
    a->recents_snap_from=a->recents_scroll;a->recents_snap_to=target;a->recents_scroll=target;a->recents_snap_at=a->now?a->now:1;
}

static void recents_go(App*a,int index){
    if(index<0||index>=a->recent_count)return;
    enum Screen target=a->recents[index].screen;
    screen(a,target);
}

static void render_recents(App*a){
    if(a->menu_backdrop)memcpy(a->pixels,a->menu_backdrop,(size_t)NW*NH*sizeof(uint32_t));
    heading(a,"",NULL,false);
    if(!a->recent_count){centered(a,(Rect){0,700,CW,60},1,TEXT,"No recent screens");return;}
    for(int n=0;n<a->recent_count;n++){
        Rect r=recents_card(a,n);
        if(r.x+r.w<0||r.x>CW)continue;
        int cx=r.x+30,cy=r.y-44;
        vector_circle(a,cx,cy,22,44,ORANGE);
        char letter[5]={0};size_t len=1;const char*t=a->recents[n].title;while(t[len]&&((unsigned char)t[len]&0xc0)==0x80)len++;memcpy(letter,t,len<4?len:4);
        raw_text(true);centered(a,(Rect){cx-22,cy-22,44,44},0,0xffffffffu,letter);ellipsis(a,r.x+66,cy-16,r.w-70,0,TEXT,t);raw_text(false);
        canvas_shadow(a->pixels,canvas_bounds(a),nx(r.x),nx(r.y),nx(r.x+r.w),nx(r.y+r.h),40.f,0,100);
        /* The picture is the card, its corners rounded as the card's (2026-11-20, the owner: they stuck out). */
        if(a->recents[n].shot){bool clipped=a->clip_active;a->clip_active=false;web_blit_smooth(a,a->recents[n].shot,RECENT_W,RECENT_H,r,30);a->clip_active=clipped;}
        else rounded(a,r,30,PANEL);
        register_button(a,r,A_RECENT+n,true,0);
    }
    button(a,recents_clear_rect(),"Clear all",A_RECENTS_CLEAR,true,false,0);
}

/* Fingers on the overview: sideways moves the cards, up closes the card, a tap opens it. Edge and
 * bottom gestures come first (nav_gesture). */
static bool recents_pointer(App*a,bool down,int x,int y){
    if(a->screen!=RECENTS)return false;
    if(down&&!a->pointer_down){
        a->pointer_down=true;a->pressed_action=0;a->recents_x0=x;a->recents_y0=y;a->recents_dragging=false;a->recents_dy=0;
        a->recents_scroll0=a->recents_scroll;a->recents_snap_at=0;a->recents_card=-1;
        for(int n=0;n<a->recent_count;n++)if(inside(recents_card(a,n),x,y)){a->recents_card=n;break;}
        return true;
    }
    if(down){
        int dx=x-a->recents_x0,dy=y-a->recents_y0;
        if(!a->recents_dragging&&(abs(dx)>18||abs(dy)>18)){a->recents_dragging=true;a->recents_sideways=abs(dx)>=abs(dy);}
        if(a->recents_dragging){
            if(a->recents_sideways){int64_t v=a->recents_scroll0+dx;a->recents_scroll=v<-80?-80:(v>recents_max_scroll(a)+80?recents_max_scroll(a)+80:v);}
            else a->recents_dy=dy<0?dy:dy/4;
            a->dirty=true;
        }
        return true;
    }
    a->pointer_down=false;
    if(!a->recents_dragging){
        if(inside(recents_clear_rect(),x,y)&&a->recent_count)recents_clear(a);
        else if(a->recents_card>=0)recents_go(a,a->recents_card);
        else screen(a,a->recents_return!=RECENTS&&a->recents_return!=HOME&&recents_note_wanted(a->recents_return)?a->recents_return:HOME);
    }else if(a->recents_sideways){
        int64_t step=RECENT_CARD_W+RECENT_GAP,dx=x-a->recents_x0;
        int64_t target=(a->recents_scroll0+step/2)/step*step;
        /* A short swipe is enough (2026-11-20, the owner): 40 pixels move to the next card. */
        if(dx>40)target=(a->recents_scroll0/step+1)*step;else if(dx<-40)target=(a->recents_scroll0/step-1)*step;
        recents_snap(a,target);
    }else if(a->recents_card>=0&&a->recents_dy<-RECENTS_CLOSE_DRAG){
        recents_close(a,a->recents_card);
        if(!a->recent_count)screen(a,HOME);
    }
    a->recents_dragging=false;a->recents_dy=0;a->recents_card=-1;a->dirty=true;
    return true;
}

static bool recents_action(App*a,int id){
    if(a->screen!=RECENTS)return false;
    if(id==A_RECENTS_CLEAR){recents_clear(a);return true;}
    if(id>=A_RECENT&&id<A_RECENT+RECENTS_MAX){recents_go(a,id-A_RECENT);return true;}
    if(id==A_BACK){screen(a,recents_note_wanted(a->recents_return)?a->recents_return:HOME);return true;}
    return false;
}
