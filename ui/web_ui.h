/* Recovery browser chrome. Page pixels never become native recovery actions.
 *
 * 2026-11-20, the owner: a browser as on Android, with tabs as Chrome shows them. A toolbar under the
 * status row (home, the address, the number of tabs, the menu) and the page down to the navigation
 * row (664 CSS pixels, web_session.py and the compositor agree). Tabs are kept here: each has its
 * address, title and a small picture. The engine keeps recently used tabs live within its RAM budget
 * and reopens a discarded tab from its address. A new tab shows search and shortcuts. */
#define WEB_TOP 186
#define WEB_H 2058
/* A slot holds a whole screen: the page, or a video in full screen (1080 x 2400, or 2400 x 1080 on its side). */
#define WEB_SLOT_PIXELS ((size_t)NW * NH)
#define WEB_BYTES (WEB_SLOT_PIXELS * sizeof(uint32_t))
#define WEB_SLOTS 2
/* Down to just above the gesture handle (2026-11-20, the owner: less room under the page). The bottom
 * strip under NAV_BOTTOM still starts the navigation gestures, as on Android; with navigation buttons
 * the page's last rows lie under them. */
#define WEB_PAGE_BOTTOM (WEB_TOP + 1372)
#define WEB_BUTTONS_BOTTOM 1516
/* The keyboard sits at the navigation row in the browser (2026-11-20, the owner: no empty band under it). */
#define WEB_KB_SHIFT 178
#define WEB_KEYBOARD_TOP (920+WEB_KB_SHIFT)
#define WEB_KB_MS 220u
#define WEB_THUMB_W (NW / 3)
#define WEB_THUMB_H (WEB_H / 3)
#define WEB_GRID_TOP 196
#define WEB_GRID_H (WEB_PAGE_BOTTOM - WEB_GRID_TOP)
#define WEB_CARD_W 324
#define WEB_CARD_H 456
#define WEB_SNACK_MS 2500u

static void web_scan_downloads(App*a);
static bool start_files_job(App*a,int kind);
static int button_at(App*a,int x,int y);
static void tap_action(App*a,int id);static void media_choose(App*a);static enum Screen came_from(const App*a,enum Screen parent);
static bool page_sheet_open(const App*a);
static bool web_page_shown(const App*a);
static bool web_float_visible(const App*a);
static void web_close(App *a){
    if(a->web_fd>=0){close(a->web_fd);a->web_fd=-1;}
    if(a->web_frames_fd>=0){close(a->web_frames_fd);a->web_frames_fd=-1;}
    if(a->web_map){munmap(a->web_map,WEB_BYTES*WEB_SLOTS);a->web_map=NULL;}
    free(a->web_frame);a->web_frame=NULL;
    if(a->web_drag)a->pointer_down=false;
    a->web_visible=a->web_drag=a->web_frame_changed=a->web_pixels_stale=false;a->web_view_sent=false;
    a->web_can_back=a->web_can_forward=false;
    a->web_loading=false;a->web_download=-2;
    a->web_frame_slot=a->web_frame_source=-1;a->web_fullscreen=0;
    a->web_tab_ack=a->web_tab_request;
    if(a->mu.web.source){memset(&a->mu.web,0,sizeof(a->mu.web));a->mu.web_changed=true;}
    a->wf.open=a->wf.drag=a->wf.resize=false;  /* its window shows nothing more */
}

static bool web_send(App *a,const char *s){
    if(a->web_fd<0)return false;
    if(send(a->web_fd,s,strlen(s),MSG_NOSIGNAL|MSG_DONTWAIT)>=0)return true;
    copy(a->web_note,sizeof(a->web_note),"Browser connection busy");a->dirty=true;
    return false;
}

/* A frame acknowledgement goes back the way its frame came: the compositor's own socket
 * (2026-11-20, no Python on the way) or the session's control socket (screencast). */
static void web_send_frames(App *a,int fd,const char *s){
    if(fd<0||fd==a->web_fd){web_send(a,s);return;}
    if(send(fd,s,strlen(s),MSG_NOSIGNAL|MSG_DONTWAIT)<0){
        copy(a->web_note,sizeof(a->web_note),"Browser connection busy");a->dirty=true;
    }
}

static bool web_start(App *a){
    if(a->web_fd>=0)return true;
    if(!a->device||a->web_pid)return false;
    int sockets[2],frames[2]={-1,-1},fd=memfd_create("browser-frame",MFD_CLOEXEC|MFD_ALLOW_SEALING);
    if(fd<0)return false;
    if(ftruncate(fd,WEB_BYTES*WEB_SLOTS)||fcntl(fd,F_ADD_SEALS,F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_SEAL)<0||
       socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,sockets)){
        close(fd);return false;
    }
    /* The compositor's frame messages come on a socket of their own (fd 6 in the session);
     * without it they are relayed by the session, as before. */
    if(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,frames))frames[0]=frames[1]=-1;
    a->web_map=mmap(NULL,WEB_BYTES*WEB_SLOTS,PROT_READ,MAP_SHARED,fd,0);
    if(a->web_map==MAP_FAILED)a->web_map=NULL;
    a->web_frame=malloc(WEB_BYTES);
    pid_t child=a->web_map&&a->web_frame?fork():-1;
    if(child==0){
        if(prctl(PR_SET_PDEATHSIG,SIGTERM)<0)_exit(126);
        int frame=fcntl(fd,F_DUPFD_CLOEXEC,8);
        int direct=frames[1]>=0?fcntl(frames[1],F_DUPFD_CLOEXEC,8):-1;
        if(frame<0||dup2(sockets[1],0)<0||dup2(frame,5)<0)_exit(126);
        if(direct>=0&&dup2(direct,6)<0)_exit(126);
        close(3);close(4);close_range(direct>=0?7:6,~0u,0);
        execl(a->python,a->python,"-B","/opt/a22x-recovery/web_launch.py",(char*)NULL);
        _exit(127);
    }
    close(fd);close(sockets[1]);a->web_fd=sockets[0];
    if(frames[1]>=0)close(frames[1]);
    a->web_frames_fd=frames[0];
    if(child<0){web_close(a);return false;}
    a->web_pid=child;a->web_frame_slot=a->web_frame_source=-1;copy(a->web_note,sizeof(a->web_note),"Starting browser");
    if(a->web_dark)web_send(a,"L1");
    if(a->web_desktop)web_send(a,"Y1");
    return true;
}

/* F (screencast: one frame, copied here) or F0/F1 (the compositor's slot, shown from where it is). */
/* F (screencast: one frame, copied here), F0/F1 (the compositor's slot) and, from the compositor,
 * F0:<w>x<h> with the frame's size (a video in full screen has another one, 2026-11-20). */
static bool web_frame_message(App *a,const char *msg,ssize_t n,int from){
    if(msg[0]!='F'||n<1||n>24)return false;
    int fw=NW,fh=WEB_H,head=n>=2&&msg[1]>='0'&&msg[1]<'0'+WEB_SLOTS?2:1;
    if(n>head){
        char text[24];memcpy(text,msg+head,(size_t)(n-head));text[n-head]=0;
        if(sscanf(text,":%dx%d",&fw,&fh)!=2||fw<=0||fh<=0||(size_t)fw*(size_t)fh>WEB_SLOT_PIXELS)return false;
    }
    if(a->web_tab_ack!=a->web_tab_request){
        const char release[]={'A',head==2?msg[1]:0,0};
        web_send_frames(a,from,release);
        return true;
    }
    a->web_fw=fw;a->web_fh=fh;
    if(head==1&&n==1){
        memcpy(a->web_frame,a->web_map,WEB_BYTES);
        if(a->web_frame_slot>=0){
            const char release[]={'A',(char)('0'+a->web_frame_slot),0};
            web_send_frames(a,a->web_frame_source,release);
        }
        a->web_frame_slot=-1;a->web_frame_source=from;
        web_send_frames(a,from,"A");
    }else{
        int next=head==2?msg[1]-'0':0;
        if(a->web_frame_slot>=0&&(a->web_frame_slot!=next||a->web_frame_source!=from)){
            const char release[]={'A',(char)('0'+a->web_frame_slot),0};
            web_send_frames(a,a->web_frame_source,release);
        }
        a->web_frame_slot=next;a->web_frame_source=from;
    }
    a->web_frame_changed=true;
    if(!a->web_visible){a->web_visible=true;a->dirty=true;}
    return true;
}

/* One message of the session's control socket (frames come first through web_frame_message). */
/* M<json>: what a page plays (web_session.py, 2026-11-22: for the shade's card); M alone: nothing. */
static void web_media_message(App*a,const char*json){
    MediaCard*m=&a->mu.web;
    if(!json[0]){if(m->source){memset(m,0,sizeof(*m));a->mu.web_changed=true;}return;}
    static JsonToken tokens[32];Json j;
    if(json_parse(&j,json,tokens,32)<=0)return;
    m->source=MEDIA_BROWSER;m->playing=json_bool(&j,json_get(&j,0,"p"),0)==1;m->video=json_bool(&j,json_get(&j,0,"v"),0)==1;
    if(json_string(&j,json_get(&j,0,"t"),m->title,sizeof(m->title))<0)m->title[0]=0;
    if(json_string(&j,json_get(&j,0,"a"),m->subtitle,sizeof(m->subtitle))<0)m->subtitle[0]=0;
    m->position_ms=(uint32_t)json_uint(&j,json_get(&j,0,"c"),0);m->duration_ms=(uint32_t)json_uint(&j,json_get(&j,0,"d"),0);m->position_at=a->now;
    a->mu.web_changed=true;
}
static void web_control_message(App *a,char *msg,ssize_t n){
    if(msg[0]=='I'){
        char *end;
        unsigned long ack=strtoul(msg+1,&end,10);
        if(end==msg+n&&ack==a->web_tab_request)a->web_tab_ack=a->web_tab_request;
        return;
    }
    /* The session acknowledges each selection only after leaving the previous
     * target. Downloads and general engine status remain global. */
    if(a->web_tab_ack!=a->web_tab_request&&strchr("UWHKVML",msg[0]))return;
    if(msg[0]=='M'){web_media_message(a,msg+1);return;}
    if(msg[0]=='H'&&n==3){
        bool back=msg[1]=='1',forward=msg[2]=='1';
        if(back!=a->web_can_back||forward!=a->web_can_forward)a->dirty=true;
        a->web_can_back=back;a->web_can_forward=forward;
    }else if(msg[0]=='U'&&strcmp(a->web_url,msg+1)){
        copy(a->web_url,sizeof(a->web_url),msg+1);a->dirty=true;
        if(a->web_tab_count&&strcmp(msg+1,"about:blank"))copy(a->web_tabs[a->web_tab].url,sizeof(a->web_tabs[0].url),msg+1);
    }else if(msg[0]=='V'&&n==2&&(msg[1]=='0'||msg[1]=='P'||msg[1]=='L')){
        /* A video went into full screen (upright or on its side) or left it (2026-11-20). */
        a->web_fullscreen=msg[1]=='0'?0:msg[1];a->web_mode=0;a->web_menu=false;a->dirty=true;
    }else if(msg[0]=='K'&&n==2&&(msg[1]=='0'||msg[1]=='1')){
        /* 2026-11-20, the owner: the keyboard comes by itself when a field of the page is tapped. */
        if(msg[1]=='1'&&!a->web_mode&&web_page_shown(a)){a->web_mode=2;a->dirty=true;}
        else if(msg[1]=='0'&&a->web_mode==2){a->web_mode=0;a->dirty=true;}
    }else if(msg[0]=='Y'){
        /* A download finished (2026-11-20, the owner: show it among the downloads at once). */
        copy(a->web_done_name,sizeof(a->web_done_name),msg+1);a->web_snack_download=a->web_done_follow=true;a->web_snack_until=a->now+WEB_SNACK_MS;
        if(a->screen==WEB_BROWSER&&!a->web_mode&&!a->web_fullscreen&&!a->web_menu&&!a->web_grid){a->web_page=1;a->page_scroll=0;a->web_file_sheet=-1;web_scan_downloads(a);}
        a->dirty=true;
    }else if(msg[0]=='W'){
        copy(a->web_title,sizeof(a->web_title),msg+1);
        if(a->web_tab_count&&strcmp(a->web_url,"about:blank"))copy(a->web_tabs[a->web_tab].title,sizeof(a->web_tabs[0].title),msg+1);
        a->dirty=true;
    }else if(msg[0]=='S'&&(a->web_done_follow||strcmp(a->web_note,msg+1))){
        /* The note right after Y names the folder of that download; any other note is no download's. */
        if(a->web_done_follow)a->web_done_follow=false;else a->web_snack_download=false;
        copy(a->web_note,sizeof(a->web_note),msg+1);a->dirty=true;
        if(strcmp(a->web_note,"Ready")&&strcmp(a->web_note,"Starting browser"))a->web_snack_until=a->now+WEB_SNACK_MS;
        /* 2026-11-20: a tester's log showed nothing of a browser that never opened; its notes
           (errors, engine steps; never an address) go to the log, without each MiB of a download. */
        if(!(strstr(a->web_note," MiB")&&strstr(a->web_note," / ")))fprintf(stderr,"[recovery-ui:web-note] %s\n",a->web_note);
    }else if(msg[0]=='L'&&n==2&&(msg[1]=='0'||msg[1]=='1')){
        bool loading=msg[1]=='1';
        if(loading!=a->web_loading){a->web_loading=loading;a->dirty=true;}
    }else if(msg[0]=='P'&&n<=4){
        /* P: no download, P-: size unknown, P0..P100: the slowest known download. */
        int value=n==1?-2:(n==2&&msg[1]=='-')?-1:-3;
        if(value==-3){value=0;for(ssize_t k=1;k<n;k++){if(msg[k]<'0'||msg[k]>'9'){value=-3;break;}value=value*10+msg[k]-'0';}}
        if(value>=-2&&value<=100&&value!=a->web_download){a->web_download=value;a->dirty=true;}
    }
}

static void web_poll(App *a){
    char msg[2200];
    while(a->web_fd>=0){
        ssize_t n=recv(a->web_fd,msg,sizeof(msg)-1,MSG_DONTWAIT);
        if(n<0&&(errno==EAGAIN||errno==EINTR))break;
        if(n<=0){web_close(a);a->dirty=true;break;}
        msg[n]=0;
        if(!web_frame_message(a,msg,n,a->web_fd))web_control_message(a,msg,n);
    }
    while(a->web_frames_fd>=0){
        ssize_t n=recv(a->web_frames_fd,msg,sizeof(msg)-1,MSG_DONTWAIT);
        if(n<0&&(errno==EAGAIN||errno==EINTR))break;
        /* The session ends this socket when it does not use it (relayed frames, screencast). */
        if(n<=0){close(a->web_frames_fd);a->web_frames_fd=-1;break;}
        msg[n]=0;
        if(!web_frame_message(a,msg,n,a->web_frames_fd)){close(a->web_frames_fd);a->web_frames_fd=-1;break;}
    }
    int web_status=0;
    if(a->web_pid&&waitpid(a->web_pid,&web_status,WNOHANG)==a->web_pid){
        a->web_pid=0;
        fprintf(stderr,"[recovery-ui:web-exit] %s=%d\n",WIFSIGNALED(web_status)?"signal":"code",WIFSIGNALED(web_status)?WTERMSIG(web_status):WEXITSTATUS(web_status));
    }
    if(a->web_catalog_pending&&!a->web_pid){
        a->web_catalog_pending=false;
        if(a->screen==SYSTEMS_CATALOG&&!a->job.pid)start_catalog_job(a);
    }
}

/* A small ring shows that a page or a download is still on its way. It is redrawn on
 * its own rows, so the page keeps its frame rate while it spins. */
static bool web_ring_active(const App *a){
    /* Not under the menu or another page of the browser: it was redrawn over the open menu (2026-11-21, #6). */
    /* Nor under the shade: its own rows were redrawn over the shade's title (2026-11-22). */
    return a->screen==WEB_BROWSER&&a->web_fd>=0&&(a->web_loading||a->web_download>-2)&&
           !a->web_menu&&!a->web_grid&&!a->web_page&&!a->web_fullscreen&&!a->qs.visible;
}

static void web_ring_draw(App *a){
    int x0=nx(WEB_RING_X),y0=nx(WEB_RING_Y),side=nx(WEB_RING_D);
    for(int y=0;y<side;y++)memcpy(a->pixels+(size_t)(y0+y)*NW+x0,a->web_ring_bg+(size_t)y*side,(size_t)side*sizeof(uint32_t));
    a->web_ring_at=a->now;
    if(!web_ring_active(a))return;
    int cx=WEB_RING_X+WEB_RING_D/2,cy=WEB_RING_Y+WEB_RING_D/2,radius=WEB_RING_D/2-6;
    const float turn=6.2831853f;
    vector_circle(a,cx,cy,radius,4,LINE);
    if(a->web_download>=0&&!a->web_loading)
        vector_arc(a,cx,cy,radius,4,-turn/4.f,turn*(float)(a->web_download<3?3:a->web_download)/100.f,ORANGE);
    else vector_arc(a,cx,cy,radius,4,(float)(a->now%1200u)*turn/1200.f,turn*.3f,ORANGE);
}

/* Called after the chrome is drawn: keep what lies under the ring for the redraws. */
static void web_ring_render(App *a){
    int x0=nx(WEB_RING_X),y0=nx(WEB_RING_Y),side=nx(WEB_RING_D);
    for(int y=0;y<side;y++)memcpy(a->web_ring_bg+(size_t)y*side,a->pixels+(size_t)(y0+y)*NW+x0,(size_t)side*sizeof(uint32_t));
    web_ring_draw(a);
}

static bool web_ring_due(const App *a){
    return web_ring_active(a)&&a->now-a->web_ring_at>=40u;
}

static int web_frame_rows(const App *a){
    return a->web_mode?nx(WEB_KEYBOARD_TOP)-nx(WEB_TOP):(a->nav_mode==NAV_BUTTONS?nx(WEB_BUTTONS_BOTTOM)-nx(WEB_TOP):WEB_H);
}
static const uint32_t *web_current_frame(const App *a){
    return a->web_frame_slot<0?a->web_frame:a->web_map+(size_t)a->web_frame_slot*WEB_SLOT_PIXELS;
}
/* The frame drawn over the whole of DST (stride in pixels, ROWS high): the page under the toolbar, a
 * full screen video upright from the top, or on its side turned a quarter clockwise (its top along the
 * panel's right edge, as a phone held in landscape). A frame of another size than the mode waits. */
static bool web_frame_fits(const App*a){
    if(a->web_fullscreen=='L')return a->web_fw==NH&&a->web_fh==NW;
    if(a->web_fullscreen=='P')return a->web_fw==NW&&a->web_fh==NH;
    return a->web_fw==NW&&a->web_fh==WEB_H;
}
static void web_draw_frame(const App*a,uint32_t*dst,size_t stride,int rows,bool opaque){
    const uint32_t*frame=web_current_frame(a);
    if(!web_frame_fits(a))return;
    if(a->web_fullscreen=='L'){
        /* Blocks of 32 x 32 keep both sides in the cache. */
        for(int by=0;by<NH&&by<rows;by+=32)for(int bx=0;bx<NW;bx+=32)
            for(int y=by;y<by+32&&y<NH&&y<rows;y++){
                uint32_t*out=dst+(size_t)y*stride;
                for(int x=bx;x<bx+32&&x<NW;x++){uint32_t v=frame[(size_t)(NW-1-x)*NH+(size_t)y];out[x]=opaque?v|0xff000000u:v;}
            }
        return;
    }
    int top=a->web_fullscreen=='P'?0:nx(WEB_TOP),count=a->web_fullscreen=='P'?NH:web_frame_rows(a);
    for(int r=0;r<count;r++){
        int y=top+r;if(y<0||y>=rows)continue;
        uint32_t*out=dst+(size_t)y*stride;const uint32_t*in=frame+(size_t)r*NW;
        if(opaque)for(int x=0;x<NW;x++)out[x]=in[x]|0xff000000u;else memcpy(out,in,(size_t)NW*sizeof(*in));
    }
}
static void web_render_frame(App *a){
    if(a->web_visible)web_draw_frame(a,a->pixels,NW,NH,false);
    a->web_frame_changed=a->web_pixels_stale=false;
}
/* Page frames go from the shared slot straight to the panel (2026-11-20: one copy of
 * 7 MB less per frame); pixels catch up only when something reads them as a whole. */
static void web_sync_pixels(App *a){
    /* Stale only between page frames and the next full render, so pixels still hold the browser's
     * page, even when a transition away from it is being armed (the screen has changed by then). */
    if(a->web_pixels_stale&&a->web_visible)web_draw_frame(a,a->pixels,NW,NH,false);
    a->web_pixels_stale=false;
}

static bool installer_action(App*a,int id);
/* Tabs ------------------------------------------------------------------------------------- */

static bool web_blank(const char*url){return !url[0]||!strcmp(url,"about:blank");}
/* The active tab shows the engine's page; a new tab shows the interface's own page. */
static bool web_ntp(const App*a){return a->web_tab_count&&web_blank(a->web_tabs[a->web_tab].url)&&web_blank(a->web_url);}
static bool web_page_shown(const App*a){return a->screen==WEB_BROWSER&&!a->web_grid&&!a->web_page&&!web_ntp(a);}
/* Page frames may go to the panel without the interface: nothing of the interface lies over them. */
static bool web_page_direct(const App*a){return (a->web_fullscreen&&a->screen==WEB_BROWSER)||(web_page_shown(a)&&!a->web_menu&&a->now>=a->web_snack_until);}

/* Smoother browser (2026-11-20, the owner): the menu opens from its corner over a blurred picture of the
 * screen, the tab grid's cards rise into place. */
#define WEB_MENU_MS 200u
#define WEB_MENU_OUT_MS 160u
#define WEB_GRID_MS 240u
static float web_ease(uint64_t start,uint64_t now,unsigned int ms){
    if(!start||now>=start+ms)return 1.f;
    float t=(float)(now-start)/(float)ms,u=1.f-t;return 1.f-u*u*u;
}
/* The browser is starting: its engine runs but no page has been shown yet (the ring turns). */
static bool web_starting(const App*a){return a->screen==WEB_BROWSER&&a->web_fd>=0&&!a->web_visible&&!a->web_mode&&!a->web_grid&&!a->web_page&&!web_ntp(a);}
static bool web_animating(const App*a){
    return web_starting(a)||(a->screen==WEB_BROWSER&&((a->web_mode&&web_ease(a->web_kb_at,a->now,WEB_KB_MS)<1.f)||
                                    (a->web_menu&&(a->web_menu_out_at||web_ease(a->web_menu_at,a->now,WEB_MENU_MS)<1.f))||
                                    (a->web_grid&&web_ease(a->web_grid_at,a->now,WEB_GRID_MS)<1.f)));
}
static void render(App*a);
/* The screen as it is under the menu (the page does not move behind it), and a blurred copy of it that
 * only the menu's own panel shows, as frosted glass (2026-11-20, the owner: blur the window, not the page). */
static void web_menu_open(App*a){
    web_sync_pixels(a);a->web_menu=false;render(a);
    if(!a->menu_backdrop)a->menu_backdrop=malloc((size_t)NW*NH*sizeof(uint32_t));
    if(!a->web_menu_plain)a->web_menu_plain=malloc((size_t)NW*NH*sizeof(uint32_t));
    if(a->menu_backdrop&&a->web_menu_plain){
        memcpy(a->web_menu_plain,a->pixels,(size_t)NW*NH*sizeof(uint32_t));
        canvas_blur(a->menu_backdrop,a->pixels);
    }
    a->web_menu=true;a->web_menu_at=a->now?a->now:1;a->web_menu_out_at=0;a->dirty=true;
}
/* The menu leaves as it came, back into its corner (2026-11-20, the owner). */
static void web_menu_close(App*a){if(a->web_menu&&!a->web_menu_out_at){a->web_menu_out_at=a->now?a->now:1;a->dirty=true;}}
/* The main loop: the menu's way out ends; the Downloads page follows files moving from RAM to a card. */
/* The typed address with a blinking caret at its end (2026-11-21, #6: the field had none); a long one
   shows its end, as a field scrolled to the caret. */
#define WEB_CARET_MS 530u
static bool web_caret_on(const App*a){return a->web_mode==1&&((a->now-a->web_caret_at)/WEB_CARET_MS)%2==0;}
static void web_entry_text(App*a,int x,int y,int avail,int font,int caret_y,int caret_h){
    const char*s=a->web_entry;raw_text(true);
    while(*s&&text_width(s,font)>avail-8){const char*p=s;utf8_next(&p);s=p;}
    text(a,x,y,font,TEXT,s);int w=text_width(s,font);raw_text(false);
    if(web_caret_on(a))rectangle(a,(Rect){x+w+2,caret_y,3,caret_h},ORANGE);
}
/* Tell the browser when Recovery stops presenting its surface. The session stays alive for
 * audio, downloads and tab state. A newly connected session always gets an initial value. */
static void web_update_visibility(App*a){
    if(a->web_fd<0)return;
    bool awake=!a->soft_blanked&&!(a->display_blank_known&&a->display_blanked);
    bool page=a->screen==WEB_BROWSER&&(a->web_fullscreen||web_page_shown(a));
    bool visible=awake&&!a->locked&&!a->qs.visible&&!a->mu.full&&!a->recents_capturing&&(page||web_float_visible(a));
    if((!a->web_view_sent||visible!=a->web_view_visible)&&web_send(a,visible?"V1":"V0")){
        a->web_view_sent=true;a->web_view_visible=visible;
    }
}
static void web_tick(App*a){
    web_update_visibility(a);
    if(a->web_menu&&a->web_menu_out_at&&a->now>=a->web_menu_out_at+WEB_MENU_OUT_MS){a->web_menu=false;a->web_menu_out_at=0;a->dirty=true;}
    static bool caret;if(a->screen==WEB_BROWSER&&web_caret_on(a)!=caret){caret=!caret;a->dirty=true;}
    static uint64_t scanned;
    if(a->screen==WEB_BROWSER&&a->web_page==1&&a->web_file_sheet<0&&a->now-scanned>1500u){scanned=a->now;web_scan_downloads(a);a->dirty=true;}
}

static void web_tabs_init(App*a){
    if(a->web_tab_count)return;
    memset(&a->web_tabs[0],0,sizeof(a->web_tabs[0]));
    copy(a->web_tabs[0].url,sizeof(a->web_tabs[0].url),a->web_last_url);
    a->web_tab_count=1;a->web_tab=0;
}

/* A small picture of the page as it is now, for the tab's card (every 6th pixel of the frame). */
static void web_thumb_capture(App*a){
    if(!a->web_tab_count||!a->web_visible||!web_page_shown(a)||a->web_fullscreen||!web_frame_fits(a))return;
    uint32_t**thumb=&a->web_tabs[a->web_tab].thumb;
    if(!*thumb)*thumb=malloc((size_t)WEB_THUMB_W*WEB_THUMB_H*sizeof(uint32_t));
    if(!*thumb)return;
    const uint32_t*frame=web_current_frame(a);
    for(int y=0;y<WEB_THUMB_H;y++)for(int x=0;x<WEB_THUMB_W;x++)(*thumb)[(size_t)y*WEB_THUMB_W+x]=frame[(size_t)(y*3+1)*NW+(size_t)(x*3+1)];
}

/* What the tab is when the browser goes elsewhere: its address, title and picture. */
static void web_tab_store(App*a){
    if(!a->web_tab_count)return;
    web_thumb_capture(a);
    if(!web_blank(a->web_url))copy(a->web_tabs[a->web_tab].url,sizeof(a->web_tabs[0].url),a->web_url);
}

/* I<request> <tab> <fallback address>. The address is used only when the
 * selected ID has no live target (including after an engine restart). */
static bool web_tab_select(App*a,const char *restore){
    if(!web_start(a))return false;
    unsigned int *id=&a->web_tabs[a->web_tab].id;
    if(!*id){
        if(!++a->web_tab_id)++a->web_tab_id;
        *id=a->web_tab_id;
    }
    if(!++a->web_tab_request)++a->web_tab_request;
    if(a->web_frame_slot>=0){
        const char release[]={'A',(char)('0'+a->web_frame_slot),0};
        web_send_frames(a,a->web_frame_source,release);
    }
    a->web_frame_slot=a->web_frame_source=-1;
    a->web_visible=a->web_frame_changed=a->web_pixels_stale=a->web_loading=false;
    a->web_fullscreen=0;
    web_media_message(a,"");
    char cmd[2080];
    snprintf(cmd,sizeof(cmd),"I%u %u %s",a->web_tab_request,*id,restore);
    if(web_send(a,cmd))return true;
    web_close(a);
    return false;
}

static void web_tab_show(App*a,int index){
    if(a->web_drag){web_send(a,"X");a->web_drag=a->pointer_down=false;}
    a->web_tab=index;a->web_grid=a->web_menu=false;a->web_mode=0;a->page_scroll=0;
    const char*url=a->web_tabs[index].url;
    copy(a->web_url,sizeof(a->web_url),url);copy(a->web_title,sizeof(a->web_title),a->web_tabs[index].title);
    a->web_can_back=a->web_can_forward=false;
    if(a->web_fd>=0||!web_blank(url))web_tab_select(a,web_blank(url)?"":url);
    a->dirty=true;
}

static bool web_open_page(App*a){
    return a->web_fd>=0||web_tab_select(a,"");
}

static void web_tab_new(App*a){
    web_tab_store(a);
    if(a->web_tab_count>=WEB_TABS){toast(a,T("Close a tab first: 12 is the most."));return;}
    int n=a->web_tab_count++;memset(&a->web_tabs[n],0,sizeof(a->web_tabs[n]));
    web_tab_show(a,n);
}

static void web_tab_close(App*a,int index){
    if(index<0||index>=a->web_tab_count)return;
    unsigned int closing=a->web_tabs[index].id;
    free(a->web_tabs[index].thumb);
    for(int n=index;n+1<a->web_tab_count;n++)a->web_tabs[n]=a->web_tabs[n+1];
    a->web_tab_count--;memset(&a->web_tabs[a->web_tab_count],0,sizeof(a->web_tabs[0]));
    if(!a->web_tab_count)a->web_tab_count=1;
    if(index<a->web_tab)a->web_tab--;
    else if(index==a->web_tab){
        bool grid=a->web_grid;
        web_tab_show(a,index<a->web_tab_count?index:a->web_tab_count-1);
        a->web_grid=grid;
    }
    if(closing&&a->web_fd>=0){
        char cmd[16];snprintf(cmd,sizeof(cmd),"O%u",closing);web_send(a,cmd);
    }
    a->dirty=true;
}

/* Quitting is the browser's own act (2026-11-22, the owner: the recent screens' card ended its session
   before): the engine stops and lets go of its RAM; the tabs stay, and its next start opens the page. */
static void web_quit(App*a){
    web_tab_store(a);
    const char*url=a->web_tab_count?a->web_tabs[a->web_tab].url:a->web_url;
    if(!strncmp(url,"https://",8)||!strncmp(url,"http://",7))copy(a->web_last_url,sizeof(a->web_last_url),url);
    web_close(a);a->web_url[0]=a->web_note[0]=a->web_entry[0]=0;a->web_menu=a->web_grid=false;a->web_mode=a->web_page=0;
    screen(a,HOME);
}

static void web_tabs_clear(App*a){
    for(int n=0;n<a->web_tab_count;n++)free(a->web_tabs[n].thumb);
    memset(a->web_tabs,0,sizeof(a->web_tabs));a->web_tab_count=1;a->web_tab=0;
    a->web_url[0]=a->web_title[0]=a->web_last_url[0]=0;a->web_grid=a->web_menu=false;
    if(a->web_fd>=0&&web_tab_select(a,""))web_send(a,"O");
    a->dirty=true;
}

/* Drawing ---------------------------------------------------------------------------------- */

/* The host of an address, as Chrome's toolbar shows it ("example.org", no scheme, no "www."). */
static void web_host(const char*url,char*out,size_t size){
    const char*p=strstr(url,"://");p=p?p+3:url;if(!strncmp(p,"www.",4))p+=4;
    size_t n=strcspn(p,"/?#");if(n>=size)n=size-1;memcpy(out,p,n);out[n]=0;
}

/* As web_blit, sampled between the source's pixels (bilinear): no blocks where a small picture is
 * drawn larger (the cards of tabs and of recent screens). */
static void web_blit_smooth(App*a,const uint32_t*src,int sw,int sh,Rect r,int corner){
    int x0=nx(r.x),y0=nx(r.y),w=nx(r.w),h=nx(r.h),radius=nx(corner);if(w<=0||h<=0)return;
    if(radius*2>w)radius=w/2;
    static int ix[NW],fx[NW];
    int64_t step=((int64_t)sw<<16)/w;
    for(int x=0;x<w&&x<NW;x++){int64_t v=(int64_t)x*step+(step>>1)-(1<<15);if(v<0)v=0;ix[x]=(int)(v>>16);fx[x]=(int)((v>>8)&255);if(ix[x]>=sw-1){ix[x]=sw-2;fx[x]=255;}}
    int ytop=a->clip_active?nx(a->clip.y):0,ybottom=a->clip_active?nx(a->clip.y+a->clip.h):NH;
    for(int y=0;y<h;y++){
        int py=y0+y;if(py<0||py>=NH||py<ytop||py>=ybottom)continue;
        int64_t v=(int64_t)y*step+(step>>1)-(1<<15);if(v<0)v=0;int sy=(int)(v>>16),wy=(int)((v>>8)&255);
        if(sy>=sh-1)break;
        const uint32_t*top=src+(size_t)sy*sw,*bottom=top+sw;uint32_t*row=a->pixels+(size_t)py*NW;
        /* Rounded corners: rows near the top and bottom of R start and end inside the arc. */
        int edge=y<radius?radius-y:(h-1-y<radius?radius-(h-1-y):0),inset=0;
        if(edge>0){float d=(float)edge;inset=(int)((float)radius-sqrtf((float)radius*(float)radius-d*d)+.5f);}
        for(int x=inset;x<w-inset;x++){
            int px=x0+x;if(px<0||px>=NW)continue;
            uint32_t a0=top[ix[x]],a1=top[ix[x]+1],b0=bottom[ix[x]],b1=bottom[ix[x]+1];unsigned int wx=(unsigned int)fx[x],vx=256u-wx,wyy=(unsigned int)wy,vy=256u-wyy;
            uint32_t trb=(((a0&0xff00ffu)*vx+(a1&0xff00ffu)*wx)>>8)&0xff00ffu,tg=(((a0&0x00ff00u)*vx+(a1&0x00ff00u)*wx)>>8)&0x00ff00u;
            uint32_t brb=(((b0&0xff00ffu)*vx+(b1&0xff00ffu)*wx)>>8)&0xff00ffu,bg=(((b0&0x00ff00u)*vx+(b1&0x00ff00u)*wx)>>8)&0x00ff00u;
            row[px]=((((trb*vy+brb*wyy)>>8)&0xff00ffu)|(((tg*vy+bg*wyy)>>8)&0x00ff00u))|0xff000000u;
        }
    }
}
static void web_glyph_home(App*a,int cx,int cy,uint32_t c){
    vector_line(a,cx-16,cy-2,cx,cy-16,4,c);vector_line(a,cx,cy-16,cx+16,cy-2,4,c);
    vector_line(a,cx-11,cy-6,cx-11,cy+14,4,c);vector_line(a,cx+11,cy-6,cx+11,cy+14,4,c);vector_line(a,cx-11,cy+14,cx+11,cy+14,4,c);
}
static void web_glyph_menu(App*a,int cx,int cy,uint32_t c){for(int n=-1;n<=1;n++)vector_circle(a,cx,cy+n*12,3,6,c);}
static void web_glyph_close(App*a,int cx,int cy,int r,uint32_t c){vector_line(a,cx-r,cy-r,cx+r,cy+r,4,c);vector_line(a,cx+r,cy-r,cx-r,cy+r,4,c);}
static void web_glyph_plus(App*a,int cx,int cy,int r,uint32_t c){vector_line(a,cx-r,cy,cx+r,cy,4,c);vector_line(a,cx,cy-r,cx,cy+r,4,c);}
static void web_tab_counter(App*a,Rect r,int count){
    Rect box={r.x+(r.w-38)/2,r.y+(r.h-38)/2,38,38};
    rounded(a,box,9,TEXT);rounded(a,(Rect){box.x+3,box.y+3,box.w-6,box.h-6},7,BG);
    char n[8];snprintf(n,sizeof(n),"%d",count);raw_text(true);centered(a,box,0,TEXT,n);raw_text(false);
}
static void web_toolbar_button(App*a,Rect r,int action,bool enabled){
    if(pressed(a,action))veil(a,r,r.h/2,TEXT,30);
    register_button(a,r,action,enabled,0);
}

/* Chrome's toolbar: home, the address, the number of tabs, the menu. */
static void render_web_toolbar(App*a){
    Rect home={12,96,72,72},pill={92,96,452,72},tabs={552,96,72,72},menu={632,96,72,72};
    web_glyph_home(a,home.x+36,home.y+38,TEXT);web_toolbar_button(a,home,A_WEB_HOME,true);
    surface(a,pill,36,PANEL2,A_WEB_ADDRESS);
    /* On a new tab's own page the typed text goes into its search field (2026-11-20, the owner). */
    if(a->web_mode==1&&!web_ntp(a)){
        if(!a->web_entry[0]){ellipsis(a,pill.x+24,pill.y+22,380,0,MUTED,"Search or type an address");if(web_caret_on(a))rectangle(a,(Rect){pill.x+24,pill.y+16,3,40},ORANGE);}
        else{web_entry_text(a,pill.x+24,pill.y+22,330,0,pill.y+16,40);Rect clear={pill.x+pill.w-64,pill.y+4,64,64};web_glyph_close(a,clear.x+32,clear.y+32,9,MUTED);register_button(a,clear,A_WEB_CLEAR,true,0);}
    }else if(web_ntp(a)||!a->web_url[0])ellipsis(a,pill.x+24,pill.y+22,380,0,MUTED,"Search or type an address");
    else{
        char host[160];web_host(a->web_url,host,sizeof(host));bool secure=!strncmp(a->web_url,"https://",8);
        /* Lock and shackle centred on the field's middle, as its text is (2026-11-22, a tester, #6: it sat high). */
        if(secure){Rect lock={pill.x+20,pill.y+pill.h/2-5,20,18};rounded(a,lock,4,MUTED);vector_arc(a,lock.x+10,lock.y,7,3,3.14159f,3.14159f,MUTED);}
        raw_text(true);ellipsis(a,pill.x+(secure?52:24),pill.y+22,330,0,TEXT,host);raw_text(false);
    }
    /* After the clear button inside it: the first button under a finger wins (2026-11-21, on the phone:
       the clear button never cleared, the address field took the tap and put the address back). */
    register_button(a,pill,A_WEB_ADDRESS,true,0);
    web_tab_counter(a,tabs,a->web_tab_count);web_toolbar_button(a,tabs,A_WEB_TABS,true);
    web_glyph_menu(a,menu.x+36,menu.y+36,TEXT);web_toolbar_button(a,menu,A_WEB_MENU,true);
}

/* A new tab's own page: the search field and shortcuts (2026-11-20, as Chrome's new tab). */
static const struct {const char*name,*url;uint32_t color;} web_shortcuts[]={
    {"YouTube","https://m.youtube.com",0xffe62117u},{"Wikipedia","https://www.wikipedia.org",0xff5a5a5au},
    {"GitHub","https://github.com",0xff24292fu},{"Google","https://www.google.com",0xff4285f4u},
    {"Catalog",NULL,0xff7a5af8u}};
static void render_web_ntp(App*a){
    centered(a,(Rect){0,300,CW,80},3,TEXT,"Browser");
    Rect search={40,430,640,96};surface(a,search,48,PANEL2,A_WEB_ADDRESS);register_button(a,search,A_WEB_ADDRESS,true,0);
    vector_circle(a,search.x+52,search.y+44,14,4,MUTED);vector_line(a,search.x+62,search.y+54,search.x+74,search.y+66,4,MUTED);
    if(a->web_mode==1&&a->web_entry[0]){
        web_entry_text(a,search.x+96,search.y+30,440,1,search.y+28,40);
        Rect clear={search.x+search.w-80,search.y+8,72,80};web_glyph_close(a,clear.x+36,clear.y+40,11,MUTED);register_button(a,clear,A_WEB_CLEAR,true,0);
    }else{
        ellipsis(a,search.x+96,search.y+32,520,1,MUTED,"Search or type an address");
        if(web_caret_on(a))rectangle(a,(Rect){search.x+96,search.y+28,3,40},ORANGE);
    }
    int count=(int)(sizeof(web_shortcuts)/sizeof(web_shortcuts[0]));
    for(int n=0;n<count;n++){
        int cx=40+64+n*(640-128)/(count-1),cy=640;Rect r={cx-64,cy-60,128,170};
        vector_circle(a,cx,cy,44,88,PANEL2);vector_circle(a,cx,cy,30,60,web_shortcuts[n].color);
        const char*label=tr(web_shortcuts[n].name);char letter[5]={0};size_t len=1;while(label[len]&&((unsigned char)label[len]&0xc0)==0x80)len++;memcpy(letter,label,len<4?len:4);
        raw_text(true);centered(a,(Rect){cx-30,cy-30,60,60},1,0xffffffffu,letter);raw_text(false);
        centered(a,(Rect){r.x-10,cy+52,r.w+20,40},0,TEXT,web_shortcuts[n].name);
        if(pressed(a,A_WEB_SHORTCUT+n))veil(a,r,24,TEXT,24);
        register_button(a,r,A_WEB_SHORTCUT+n,true,0);
    }
    if(a->web_note[0]&&a->now<a->web_snack_until)wrapped(a,40,820,640,0,MUTED,a->web_note,3);
}

/* The tab switcher: a grid of cards, two in a row, each with its title, a close button and its picture. */
static void render_web_grid(App*a){
    Rect add={12,96,72,72},done={540,104,164,56};
    web_glyph_plus(a,add.x+36,add.y+36,16,TEXT);web_toolbar_button(a,add,A_WEB_NEW_TAB,a->web_tab_count<WEB_TABS);
    char title[48];snprintf(title,sizeof(title),T("Tabs: %d"),a->web_tab_count);centered(a,(Rect){100,104,420,56},1,TEXT,title);
    button(a,done,"Done",A_WEB_GRID_DONE,true,false,0);
    a->clip_active=true;a->clip=page_viewport(a);
    int y0=WEB_GRID_TOP-(int)a->page_scroll+(int)((1.f-web_ease(a->web_grid_at,a->now,WEB_GRID_MS))*120.f);
    for(int n=0;n<a->web_tab_count;n++){
        Rect card={28+(n%2)*(WEB_CARD_W+16),y0+(n/2)*(WEB_CARD_H+20),WEB_CARD_W,WEB_CARD_H};
        if(card.y>=WEB_PAGE_BOTTOM||card.y+card.h<=WEB_GRID_TOP)continue;
        bool active=n==a->web_tab;
        rounded(a,card,28,active?ORANGE:PANEL);
        Rect inner={card.x+6,card.y+64,card.w-12,card.h-70};
        const char*name=a->web_tabs[n].title[0]?a->web_tabs[n].title:(web_blank(a->web_tabs[n].url)?T("New tab"):a->web_tabs[n].url);
        raw_text(a->web_tabs[n].title[0]!=0);ellipsis(a,card.x+24,card.y+16,card.w-96,0,active?ON_ORANGE:TEXT,name);raw_text(false);
        /* On the accent the theme's own text colour for it (2026-11-21, #7: white on cyan was unreadable). */
        Rect close={card.x+card.w-64,card.y+4,60,56};web_glyph_close(a,close.x+30,close.y+28,10,active?ON_ORANGE:TEXT);
        rounded(a,inner,22,BG);
        if(a->web_tabs[n].thumb){
            bool clipped=a->clip_active;Rect saved=a->clip;
            int top=inner.y>saved.y?inner.y:saved.y,bottom=inner.y+inner.h<saved.y+saved.h?inner.y+inner.h:saved.y+saved.h;
            a->clip=(Rect){inner.x,top,inner.w,bottom-top};a->clip_active=true;
            web_blit_smooth(a,a->web_tabs[n].thumb,WEB_THUMB_W,WEB_THUMB_H,(Rect){inner.x,inner.y,inner.w,inner.h},22);
            a->clip=saved;a->clip_active=clipped;
        }else centered(a,inner,0,MUTED,web_blank(a->web_tabs[n].url)?T("New tab"):"");
        if(pressed(a,A_WEB_TAB+n))veil(a,card,28,TEXT,24);
        register_button(a,close,A_WEB_TAB_CLOSE+n,true,0);
        register_button(a,card,A_WEB_TAB+n,true,0);
    }
    a->page_content=((a->web_tab_count+1)/2)*(WEB_CARD_H+20);
    a->clip_active=false;
}

/* The menu, over everything, as Chrome's: back, forward and reload in a row, then the items. */
static void web_glyph_arrow(App*a,int cx,int cy,int dir,uint32_t c){
    vector_line(a,cx-14*dir,cy,cx+14*dir,cy,4,c);vector_line(a,cx-14*dir,cy,cx-4*dir,cy-10,4,c);vector_line(a,cx-14*dir,cy,cx-4*dir,cy+10,4,c);
}
/* An arc with its gap at the top and the arrowhead on the arc's own end, pointing along it into the gap
   (2026-11-22, a tester, #6: the head was drawn apart from where the arc stopped). */
static void web_glyph_reload(App*a,int cx,int cy,uint32_t c){
    const float start=-1.0f,sweep=5.0f,radius=13.f,end=start+sweep;
    vector_arc(a,cx,cy,13,4,start,sweep,c);
    float px=(float)cx+radius*cosf(end)-2.f*cosf(end),py=(float)cy+radius*sinf(end)-2.f*sinf(end);  /* the stroke's middle */
    float tx=-sinf(end),ty=cosf(end),nx_=cosf(end),ny_=sinf(end);
    float tipx=px+tx*6.f,tipy=py+ty*6.f;
    vector_line(a,(int)lroundf(tipx),(int)lroundf(tipy),(int)lroundf(tipx-tx*9.f+nx_*7.f),(int)lroundf(tipy-ty*9.f+ny_*7.f),4,c);
    vector_line(a,(int)lroundf(tipx),(int)lroundf(tipy),(int)lroundf(tipx-tx*9.f-nx_*7.f),(int)lroundf(tipy-ty*9.f-ny_*7.f),4,c);
}
static void render_web_menu(App*a){
    float e=web_ease(a->web_menu_at,a->now,WEB_MENU_MS);
    if(a->web_menu_out_at){float out=1.f-web_ease(a->web_menu_out_at,a->now,WEB_MENU_OUT_MS);if(out<e)e=out;}
    bool frosted=a->menu_backdrop&&a->web_menu_plain;
    if(frosted){a->button_count=0;memcpy(a->pixels,a->web_menu_plain,(size_t)NW*NH*sizeof(uint32_t));}
    else for(int n=0;n<a->button_count;n++)a->buttons[n].enabled=false;
    static const struct {const char*label;int action;} items[]={
        {"New tab",A_WEB_NEW_TAB},{"Desktop site",A_WEB_DESKTOP},{"Dark sites",A_WEB_DARK},{"Keyboard",A_WEB_KEYBOARD},{"Downloads",A_WEB_DOWNLOADS},
        {"Browser settings",A_WEB_SETTINGS},{"Catalog",A_WEB_CATALOG},{"Close all tabs",A_WEB_CLOSE_TABS},{"Floating window",A_WEB_FLOAT},{"Quit browser",A_WEB_QUIT}};
    int count=(int)(sizeof(items)/sizeof(items[0]));
    Rect full={280,96,424,112+count*80+16};
    /* From the corner of the menu button: it grows to the left and down, its items revealed as it opens. */
    Rect panel={full.x+(int)((1.f-e)*(float)full.w*.35f),full.y,full.w-(int)((1.f-e)*(float)full.w*.35f),(int)((float)full.h*(.25f+.75f*e))};
    canvas_shadow(a->pixels,canvas_bounds(a),nx(panel.x),nx(panel.y),nx(panel.x+panel.w),nx(panel.y+panel.h),40.f,0,(unsigned int)(110.f*e));
    if(frosted){
        /* Frosted glass: the blurred page inside the panel's rounded outline, tinted with the panel's colour. */
        int x0=nx(panel.x),x1=nx(panel.x+panel.w),y0=nx(panel.y),y1=nx(panel.y+panel.h),radius=nx(26);
        for(int y=y0;y<y1&&y<NH;y++){
            int edge=y-y0<radius?radius-(y-y0):(y1-1-y<radius?radius-(y1-1-y):0),inset=0;
            if(edge>0){float d=(float)edge;inset=(int)((float)radius-sqrtf((float)radius*(float)radius-d*d)+.5f);}
            int from=x0+inset,to=x1-inset;if(from<0)from=0;if(to>NW)to=NW;
            if(to>from)memcpy(a->pixels+(size_t)y*NW+from,a->menu_backdrop+(size_t)y*NW+from,(size_t)(to-from)*sizeof(uint32_t));
        }
        veil(a,panel,26,PANEL,(unsigned int)(150.f+60.f*e));
    }else rounded(a,panel,26,PANEL);
    bool clipped=a->clip_active;Rect saved=a->clip;a->clip_active=true;a->clip=panel;
    panel=(Rect){full.x+(panel.x-full.x),full.y,full.w,full.h};
    bool page=web_page_shown(a)&&!a->web_page;
    static const int row_actions[3]={A_WEB_HISTORY,A_WEB_FORWARD,A_WEB_RELOAD};
    bool row_enabled[3]={page&&a->web_can_back,page&&a->web_can_forward,page&&a->web_visible};
    for(int n=0;n<3;n++){
        Rect r={panel.x+20+n*132,panel.y+16,124,80};int cx=r.x+r.w/2,cy=r.y+r.h/2;uint32_t ink=row_enabled[n]?TEXT:MUTED;
        vector_circle(a,cx,cy,34,68,PANEL2);if(pressed(a,row_actions[n]))veil(a,r,40,TEXT,24);
        if(n<2)web_glyph_arrow(a,cx,cy,n?-1:1,ink);else web_glyph_reload(a,cx,cy,ink);
        register_button(a,r,row_actions[n],row_enabled[n],0);
    }
    rectangle(a,(Rect){panel.x+20,panel.y+108,panel.w-40,2},LINE);
    for(int n=0;n<count;n++){
        Rect r={panel.x+8,panel.y+116+n*80,panel.w-16,80};
        bool enabled=(items[n].action==A_WEB_KEYBOARD||items[n].action==A_WEB_DESKTOP||items[n].action==A_WEB_FLOAT)?page:
                     items[n].action==A_WEB_NEW_TAB?a->web_tab_count<WEB_TABS:true;
        if(pressed(a,items[n].action))veil(a,r,18,TEXT,24);
        text(a,r.x+24,r.y+22,1,enabled?TEXT:MUTED,items[n].label);
        if(items[n].action==A_WEB_DESKTOP||items[n].action==A_WEB_DARK){
            bool on=items[n].action==A_WEB_DARK?a->web_dark:a->web_desktop;
            Rect box={r.x+r.w-60,r.y+22,36,36};rounded(a,box,8,on?ORANGE:LINE);
            if(on){vector_line(a,box.x+8,box.y+19,box.x+15,box.y+26,4,ON_ORANGE);vector_line(a,box.x+15,box.y+26,box.x+28,box.y+10,4,ON_ORANGE);}
            else rounded(a,(Rect){box.x+3,box.y+3,box.w-6,box.h-6},6,PANEL);
        }
        register_button(a,r,items[n].action,enabled,0);
    }
    a->clip=saved;a->clip_active=clipped;
    register_button(a,(Rect){0,0,CW,CH},A_WEB_MENU_CLOSE,true,0);
}

/* Downloads -------------------------------------------------------------------------------- */

static int web_file_newer(const void*x,const void*y){
    int64_t a=((const struct WebFile*)x)->mtime,b=((const struct WebFile*)y)->mtime;
    return a<b?1:(a>b?-1:0);
}
/* The Download folders of the mounted cards and drives, newest first (only read; nothing changes). */
static void web_scan_downloads(App*a){
    a->web_file_count=0;
    if(!a->device)return;
    DIR*volumes=opendir("/mnt/volumes");if(!volumes)return;
    struct dirent*v;
    while((v=readdir(volumes))&&a->web_file_count<64){
        if(v->d_name[0]=='.'||strlen(v->d_name)>=40)continue;
        char path[96];snprintf(path,sizeof(path),"/mnt/volumes/%s/Download",v->d_name);
        int dfd=open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(dfd<0)continue;
        DIR*d=fdopendir(dfd);if(!d){close(dfd);continue;}
        struct dirent*e;
        while((e=readdir(d))&&a->web_file_count<64){
            struct stat st;if(e->d_name[0]=='.'||fstatat(dfd,e->d_name,&st,AT_SYMLINK_NOFOLLOW)||!S_ISREG(st.st_mode))continue;
            struct WebFile*f=&a->web_files[a->web_file_count++];
            copy(f->name,sizeof(f->name),e->d_name);copy(f->where,sizeof(f->where),v->d_name);f->size=(uint64_t)st.st_size;f->mtime=st.st_mtime;
        }
        closedir(d);
    }
    closedir(volumes);
    /* Finished downloads still in RAM: they wait there until a card can take them (storage busy, or
       none mounted for writing; 2026-11-20, the owner saw an empty page while two files waited). */
    DIR*sessions=opendir("/run/a22x-recovery/web-cache/downloads");
    if(sessions){
        struct dirent*session;
        while((session=readdir(sessions))&&a->web_file_count<64){
            if(strncmp(session->d_name,"Browser-downloads-",18)||strlen(session->d_name)>=64)continue;
            char path[128];snprintf(path,sizeof(path),"/run/a22x-recovery/web-cache/downloads/%s",session->d_name);
            int dfd=open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(dfd<0)continue;
            DIR*d=fdopendir(dfd);if(!d){close(dfd);continue;}
            struct dirent*e;
            while((e=readdir(d))&&a->web_file_count<64){
                size_t len=strlen(e->d_name);struct stat st;
                if(e->d_name[0]=='.'||(len>11&&!strcmp(e->d_name+len-11,".crdownload"))||fstatat(dfd,e->d_name,&st,AT_SYMLINK_NOFOLLOW)||!S_ISREG(st.st_mode))continue;
                struct WebFile*f=&a->web_files[a->web_file_count++];
                copy(f->name,sizeof(f->name),e->d_name);copy(f->where,sizeof(f->where),"ram");f->size=(uint64_t)st.st_size;f->mtime=st.st_mtime;
            }
            closedir(d);
        }
        closedir(sessions);
    }
    qsort(a->web_files,(size_t)a->web_file_count,sizeof(a->web_files[0]),web_file_newer);
}
static const char*web_place(const char*volume){return !strcmp(volume,"ram")?"In RAM, waiting for the card":(!strncmp(volume,"sdcard",6)?"SD card":(!strncmp(volume,"usb",3)?"USB drive":volume));}

static void web_page_header(App*a,const char*title){
    vector_circle(a,54,132,32,32,pressed(a,A_WEB_PAGE_BACK)?LINE:PANEL2);icon(a,ICON_BACK,36,114,36,TEXT);
    register_button(a,(Rect){16,92,76,84},A_WEB_PAGE_BACK,true,0);
    text(a,108,108,2,TEXT,title);
}

/* A file's sheet: where it is and what to do with it (2026-11-20, the owner). */
static void render_web_file_sheet(App*a){
    if(a->web_file_sheet<0||a->web_file_sheet>=a->web_file_count)return;
    struct WebFile*f=&a->web_files[a->web_file_sheet];
    for(int n=0;n<a->button_count;n++)a->buttons[n].enabled=false;
    veil(a,(Rect){0,0,CW,CH},0,0,90);
    Rect sheet={0,1040,CW,CH-1040};canvas_shadow(a->pixels,canvas_bounds(a),0,nx(sheet.y),NW,NH,40.f,0,110);
    rounded(a,(Rect){sheet.x,sheet.y,sheet.w,sheet.h+40},36,BG);rounded(a,(Rect){sheet.x,sheet.y,sheet.w,sheet.h+40},36,PANEL);
    raw_text(true);ellipsis(a,40,sheet.y+40,640,2,TEXT,f->name);raw_text(false);
    char size[24],meta[160];human_bytes(f->size,size,sizeof(size));snprintf(meta,sizeof(meta),"%s  ·  %s  ·  Download/",size,T(web_place(f->where)));
    ellipsis(a,40,sheet.y+104,640,0,MUTED,meta);
    bool on_card=strcmp(f->where,"ram")!=0;
    /* Its own page in Files: install, flash or run it from there (2026-11-21, the owner). */
    if(on_card){button(a,(Rect){28,sheet.y+170,320,88},"Open it",A_WEB_FILE_OPEN,true,true,0);button(a,(Rect){372,sheet.y+170,320,88},"Show in Files",A_WEB_FILE_SHOW,true,false,0);}
    else button(a,(Rect){28,sheet.y+170,664,88},"Show in Files",A_WEB_FILE_SHOW,false,true,0);
    if(!on_card)wrapped(a,40,sheet.y+272,640,0,MUTED,"It moves to Download/ on a card mounted for writing as soon as storage is free.",3);
    button(a,(Rect){28,sheet.y+(on_card?276:350),664,84},"Close",A_WEB_FILE_CLOSE,true,false,0);
    register_button(a,(Rect){0,0,CW,sheet.y},A_WEB_FILE_CLOSE,true,0);
}

/* A download's own page in Files, where it is installed, flashed or run (2026-11-21, the owner). */
static bool web_open_file(App*a,const struct WebFile*f){
    if(!strcmp(f->where,"ram"))return false;
    for(int i=0;i<a->volume_count;i++)if(!strcmp(a->volumes[i].id,f->where)&&a->volumes[i].mounted){
        a->volume_index=i;copy(a->volume_id,sizeof(a->volume_id),f->where);copy(a->fs_path,sizeof(a->fs_path),"/Download");copy(a->fs_open_root,sizeof(a->fs_open_root),"/Download");a->fs_back_to_web=true;
        reset_browser(a);memset(&a->fs_selected,0,sizeof(a->fs_selected));copy(a->fs_selected.name,sizeof(a->fs_selected.name),f->name);
        snprintf(a->fs_selected.path,sizeof(a->fs_selected.path),"/Download/%.250s",f->name);copy(a->fs_selected.type,sizeof(a->fs_selected.type),"file");
        a->web_file_sheet=-1;a->web_page=0;a->fs_link_resolved=false;screen(a,FILE_INFO);start_files_job(a,J_FS_STAT);return true;
    }
    copy(a->web_show_where,sizeof(a->web_show_where),f->where);copy(a->web_show_file,sizeof(a->web_show_file),f->name);
    a->web_file_sheet=-1;a->web_page=0;screen(a,FILE_VOLUMES);start_files_job(a,J_FS_INVENTORY);return true;
}
/* Files, open at the folder of a download on its card (the volume as Files lists it). */
static bool web_show_in_files(App*a,const struct WebFile*f){
    for(int i=0;i<a->volume_count;i++)if(!strcmp(a->volumes[i].id,f->where)&&a->volumes[i].mounted){
        /* Opened at Download: Back there returns to the browser's Downloads (2026-11-21, #6: it went
           through the volume's page and the list of volumes first). */
        a->volume_index=i;copy(a->volume_id,sizeof(a->volume_id),f->where);copy(a->fs_path,sizeof(a->fs_path),"/Download");copy(a->fs_open_root,sizeof(a->fs_open_root),"/Download");a->fs_back_to_web=true;
        reset_browser(a);memset(&a->fs_selected,0,sizeof(a->fs_selected));a->web_file_sheet=-1;a->web_page=0;
        screen(a,FILE_BROWSER);start_files_job(a,J_FS_LIST);return true;
    }
    /* The volumes are not read yet: Files reads them and then opens the file's Download. */
    copy(a->web_show_where,sizeof(a->web_show_where),f->where);
    a->web_file_sheet=-1;a->web_page=0;screen(a,FILE_VOLUMES);start_files_job(a,J_FS_INVENTORY);return true;
}

static void render_web_downloads(App*a){
    web_page_header(a,"Downloads");
    button(a,(Rect){452,100,252,64},"Open in Files",A_WEB_OPEN_FILES,true,false,0);
    a->clip_active=true;a->clip=page_viewport(a);
    int y=WEB_GRID_TOP-(int)a->page_scroll;
    struct statvfs fs;
    for(int n=0;n<2;n++){
        const char*where=n?"usb-sda1":"sdcard-p1";char path[64];snprintf(path,sizeof(path),"/mnt/volumes/%s/Download",where);
        if(a->device&&!statvfs(path,&fs)){
            char free_s[24],total_s[24],line[128];human_bytes((uint64_t)fs.f_bavail*fs.f_frsize,free_s,sizeof(free_s));human_bytes((uint64_t)fs.f_blocks*fs.f_frsize,total_s,sizeof(total_s));
            snprintf(line,sizeof(line),T("%s: %s free of %s"),T(web_place(where)),free_s,total_s);text(a,40,y,0,MUTED,line);y+=44;
        }
    }
    static const char*const where_names[4]={"SD card, then a USB drive","SD card","USB drive","RAM only (lost at restart)"};
    char saving[160];snprintf(saving,sizeof(saving),T("New downloads: %s"),T(where_names[a->web_downloads&3]));text(a,40,y,0,MUTED,saving);y+=56;
    if(!a->web_file_count){wrapped(a,40,y+40,640,1,MUTED,"No downloads yet. Finished downloads are moved to Download/ on the card or drive.",4);}
    char last_day[32]="";
    for(int n=0;n<a->web_file_count;n++){
        time_t when=(time_t)(a->web_files[n].mtime+(int64_t)recovery_offset_now(a)*60);struct tm tm;gmtime_r(&when,&tm);
        char day[32];strftime(day,sizeof(day),"%d.%m.%Y",&tm);
        if(strcmp(day,last_day)){copy(last_day,sizeof(last_day),day);y+=12;raw_text(true);text(a,40,y,1,TEXT,day);raw_text(false);y+=56;}
        Rect row={28,y,664,92};
        vector_circle(a,row.x+44,row.y+46,30,60,PANEL2);rounded(a,(Rect){row.x+32,row.y+30,24,32},4,MUTED);
        raw_text(true);ellipsis(a,row.x+92,row.y+10,560,1,TEXT,a->web_files[n].name);raw_text(false);
        char size[24],meta[96];human_bytes(a->web_files[n].size,size,sizeof(size));snprintf(meta,sizeof(meta),"%s  ·  %s",size,T(web_place(a->web_files[n].where)));
        text(a,row.x+92,row.y+54,0,MUTED,meta);
        if(pressed(a,A_WEB_FILE+n))veil(a,row,20,TEXT,20);
        register_button(a,row,A_WEB_FILE+n,true,0);
        y+=100;
    }
    a->page_content=y+(int)a->page_scroll-WEB_GRID_TOP+20;
    a->clip_active=false;
}

static void render_web_settings(App*a){
    web_page_header(a,"Browser settings");
    a->clip_active=true;a->clip=page_viewport(a);
    int y=WEB_GRID_TOP-(int)a->page_scroll;
    rounded(a,(Rect){28,y,664,448},24,PANEL);text(a,52,y+20,1,TEXT,"Save downloads to");
    static const char*const where_names[4]={"SD card, then a USB drive","SD card","USB drive","RAM only (lost at restart)"};
    for(int n=0;n<4;n++){
        Rect r={40,y+76+n*88,640,80};bool on=a->web_downloads==n;
        if(pressed(a,A_WEB_SAVE_TO+n))veil(a,r,20,TEXT,20);
        vector_circle(a,r.x+36,r.y+40,16,4,on?ORANGE:MUTED);if(on)vector_circle(a,r.x+36,r.y+40,8,16,ORANGE);
        text(a,r.x+72,r.y+22,1,TEXT,where_names[n]);register_button(a,r,A_WEB_SAVE_TO+n,true,0);
    }
    y+=468;
    rounded(a,(Rect){28,y,664,120},24,PANEL);text(a,52,y+20,1,TEXT,"Desktop site");
    ellipsis(a,52,y+66,460,0,MUTED,"Pages as on a computer");
    {Rect sw={572,y+34,96,52};rounded(a,sw,26,a->web_desktop?ORANGE:LINE);vector_circle(a,a->web_desktop?sw.x+70:sw.x+26,sw.y+26,20,40,0xffffffffu);
     register_button(a,(Rect){28,y,664,120},A_WEB_DESKTOP,true,0);}
    y+=140;
    rounded(a,(Rect){28,y,664,120},24,PANEL);text(a,52,y+20,1,TEXT,"Dark sites");
    ellipsis(a,52,y+66,460,0,MUTED,"Their dark version; others darkened");
    {Rect sw={572,y+34,96,52};rounded(a,sw,26,a->web_dark?ORANGE:LINE);vector_circle(a,a->web_dark?sw.x+70:sw.x+26,sw.y+26,20,40,0xffffffffu);
     register_button(a,(Rect){28,y,664,120},A_WEB_DARK,true,0);}
    y+=140;
    button(a,(Rect){28,y,664,84},"Clear browsing data",A_WEB_CLEAR_DATA,a->web_fd>=0,false,0);y+=100;
    wrapped(a,40,y,640,0,MUTED,"Cookies, logins and the page cache live in RAM and are gone when the recovery restarts. Clearing removes them now.",4);
    y+=120;button(a,(Rect){28,y,664,84},"Close all tabs",A_WEB_CLOSE_TABS,true,false,0);y+=100;
    a->page_content=y+(int)a->page_scroll-WEB_GRID_TOP+20;
    a->clip_active=false;
}

/* The engine's own progress, from its note ("... 120 / 480 MiB"), or -1 when it gives none. */
static int web_note_percent(const App*a){
    const char*slash=strstr(a->web_note," / ");if(!slash||!strstr(slash,"MiB"))return -1;
    const char*p=slash;while(p>a->web_note&&p[-1]>='0'&&p[-1]<='9')p--;
    long done=strtol(p,NULL,10),total=strtol(slash+3,NULL,10);
    return total>0&&done>=0&&done<=total?(int)(done*100/total):-1;
}
/* Starting: the ring of the installer and the flashing pages, turning, or filling as the engine loads. */
static void render_web_starting(App*a){
    const int cx=CW/2,cy=640,radius=110;const float turn=6.2831853f;
    vector_circle(a,cx,cy,radius,14,LINE);
    /* The engine stopped: no ring that turns only when something else redraws (2026-11-21, #7: "1 frame
       every 5 seconds" over "Web engine stopped"), but the reason and a way to start it again. */
    if(a->web_fd<0){
        icon(a,ICON_BROWSER,cx-36,cy-36,72,MUTED);
        centered(a,(Rect){0,cy+radius+50,CW,50},1,TEXT,"Browser");
        if(a->web_note[0])centered(a,(Rect){0,cy+radius+110,CW,40},0,MUTED,a->web_note);
        button(a,(Rect){CW/2-180,cy+radius+180,360,88},"Try again",A_WEB_RELOAD,!a->web_pid,true,0);
        return;
    }
    int percent=web_note_percent(a);
    if(percent>=0){
        vector_arc(a,cx,cy,radius,14,-turn/4.f,turn*(float)(percent<2?2:percent)/100.f,ORANGE);
        char value[8];snprintf(value,sizeof(value),"%d%%",percent);raw_text(true);centered(a,(Rect){cx-100,cy-40,200,80},2,TEXT,value);raw_text(false);
    }else{
        vector_arc(a,cx,cy,radius,14,(float)(a->now%1100u)*turn/1100.f,turn*.28f,ORANGE);
        icon(a,ICON_BROWSER,cx-36,cy-36,72,ORANGE);
    }
    centered(a,(Rect){0,cy+radius+50,CW,50},1,TEXT,a->web_fd>=0?"Starting browser":"Browser");
    if(a->web_note[0]&&strcmp(a->web_note,"Starting browser"))centered(a,(Rect){0,cy+radius+110,CW,40},0,MUTED,a->web_note);
}

static void render_web(App *a){
    if(a->web_fullscreen&&a->web_visible){
        rectangle(a,(Rect){0,0,CW,CH},0xff000000u);web_render_frame(a);a->web_pixels_stale=false;return;
    }
    heading(a,"",NULL,false);
    if(!a->web_mode)a->web_kb_shown=false;
    web_tabs_init(a);
    if(a->web_menu&&a->menu_backdrop&&a->web_menu_plain){
        /* The page goes on under the menu: a video kept its first picture while the menu was open
           (2026-11-21, #6). New frames go into the picture the menu lies on; its glass stays as it was. */
        if(a->web_frame_changed||a->web_pixels_stale){
            if(web_page_shown(a)&&a->web_visible)web_draw_frame(a,a->web_menu_plain,NW,NH,false);
            a->web_frame_changed=a->web_pixels_stale=false;
        }
        render_web_menu(a);return;
    }
    if(a->web_page==1){render_web_downloads(a);render_web_file_sheet(a);return;}
    if(a->web_page==2){render_web_settings(a);return;}
    if(a->web_grid){render_web_grid(a);if(a->web_menu)render_web_menu(a);return;}
    render_web_toolbar(a);
    web_ring_render(a);
    if(web_ntp(a)&&a->web_mode!=2)render_web_ntp(a);
    else{
        web_render_frame(a);
        if(!a->web_visible&&!a->web_mode)render_web_starting(a);
    }
    if(a->web_mode){
        /* It rises from the bottom edge when it comes. */
        if(!a->web_kb_shown){a->web_kb_shown=true;a->web_kb_at=a->now?a->now:1;}
        a->kb_offset=WEB_KB_SHIFT+(int)((1.f-web_ease(a->web_kb_at,a->now,WEB_KB_MS))*(float)(CH-WEB_KEYBOARD_TOP));
        rounded(a,(Rect){0,WEB_KEYBOARD_TOP+a->kb_offset-WEB_KB_SHIFT,CW,CH},0,BG);
        render_keyboard(a);a->kb_offset=0;
    }
    else if(web_page_shown(a)&&a->web_visible&&a->now<a->web_snack_until&&a->web_note[0]){
        /* Larger, as Android's (2026-11-20, the owner): an icon, the note in the larger type, and Open for downloads. */
        Rect snack={20,1388,680,116};canvas_shadow(a->pixels,canvas_bounds(a),nx(snack.x),nx(snack.y),nx(snack.x+snack.w),nx(snack.y+snack.h),30.f,0,90);
        rounded(a,snack,26,TEXT);vector_line(a,snack.x+44,snack.y+38,snack.x+44,snack.y+70,5,BG);vector_line(a,snack.x+32,snack.y+58,snack.x+44,snack.y+72,5,BG);vector_line(a,snack.x+56,snack.y+58,snack.x+44,snack.y+72,5,BG);vector_line(a,snack.x+30,snack.y+82,snack.x+58,snack.y+82,5,BG);
        bool downloads=a->web_snack_download&&a->web_done_name[0];
        if(downloads){text(a,snack.x+80,snack.y+18,0,BG,"Downloaded");raw_text(true);ellipsis(a,snack.x+80,snack.y+56,400,1,BG,a->web_done_name);raw_text(false);}
        else ellipsis(a,snack.x+80,snack.y+38,570,1,BG,a->web_note);
        if(downloads){Rect open={snack.x+snack.w-176,snack.y+22,160,72};text(a,open.x+28,open.y+18,1,ORANGE,"Open");register_button(a,open,A_WEB_SNACK_OPEN,true,0);}
    }
    if(a->web_menu)render_web_menu(a);
}

/* The browser opened again in this recovery session: its tabs are where they were, and the active
 * tab's page opens again (screen()). */
static void web_resume(App *a){
    web_tabs_init(a);
    const char*url=a->web_tabs[a->web_tab].url[0]?a->web_tabs[a->web_tab].url:a->web_last_url;
    /* Only a web page opens again: the engine's own pages (its new tab page after a failed start,
       2026-11-21) are refused by the session and leave the tab on the interface's new tab page. */
    if(strncmp(url,"https://",8)&&strncmp(url,"http://",7)){if(!web_blank(url)){a->web_tabs[a->web_tab].url[0]=0;a->web_url[0]=0;}return;}
    if(a->web_fd>=0||!web_tab_select(a,url))return;
    copy(a->web_url,sizeof(a->web_url),url);copy(a->web_title,sizeof(a->web_title),a->web_tabs[a->web_tab].title);
}

static bool web_action(App *a,int id){
    if(a->screen!=WEB_BROWSER)return false;
    web_tabs_init(a);
    if(id==A_WEB_MENU_CLOSE){web_menu_close(a);return true;}
    if(a->web_menu&&id!=A_BACK)a->web_menu=false;
    if(id==A_WEB_TYPE&&a->web_mode==1)id=A_KB_ENTER;
    if(id>=A_WEB_FILE&&id<A_WEB_FILE+64){if(id-A_WEB_FILE<a->web_file_count)a->web_file_sheet=id-A_WEB_FILE;}
    else if(id==A_WEB_FILE_CLOSE)a->web_file_sheet=-1;
    else if(id==A_WEB_FILE_SHOW&&a->web_file_sheet>=0&&a->web_file_sheet<a->web_file_count){struct WebFile f=a->web_files[a->web_file_sheet];return web_show_in_files(a,&f);}
    else if(id==A_WEB_FILE_OPEN&&a->web_file_sheet>=0&&a->web_file_sheet<a->web_file_count){struct WebFile f=a->web_files[a->web_file_sheet];return web_open_file(a,&f);}
    else if(id==A_WEB_SNACK_OPEN){a->web_page=1;a->page_scroll=0;a->web_file_sheet=-1;a->web_snack_until=0;web_scan_downloads(a);}
    else if(id==A_WEB_PAGE_BACK){a->web_page=0;a->page_scroll=0;a->web_file_sheet=-1;}
    else if(id==A_WEB_DOWNLOADS){a->web_page=1;a->page_scroll=0;web_scan_downloads(a);}
    else if(id==A_WEB_SETTINGS){a->web_page=2;a->page_scroll=0;}
    else if(id==A_WEB_OPEN_FILES){a->web_page=0;screen(a,FILE_VOLUMES);return true;}
    else if(id==A_WEB_DESKTOP){a->web_desktop=!a->web_desktop;web_send(a,a->web_desktop?"Y1":"Y0");}
    /* Kept in the settings, so it holds after a restart (2026-11-21, the owner: dark versions of sites, in the menu). */
    else if(id==A_WEB_DARK){a->web_dark=!a->web_dark;web_send(a,a->web_dark?"L1":"L0");a->web_settings_dirty=true;settings_save(a,false);}
    else if(id==A_WEB_CLEAR_DATA)web_send(a,"C");
    else if(id>=A_WEB_SAVE_TO&&id<A_WEB_SAVE_TO+4){a->web_downloads=id-A_WEB_SAVE_TO;a->web_settings_dirty=true;settings_save(a,false);}
    else if(id==A_WEB_MENU)web_menu_open(a);
    else if(id==A_WEB_TABS){web_tab_store(a);a->web_grid=true;a->web_grid_at=a->now?a->now:1;a->web_mode=0;a->page_scroll=0;}
    else if(id==A_WEB_GRID_DONE)a->web_grid=false;
    else if(id==A_WEB_NEW_TAB)web_tab_new(a);
    else if(id==A_WEB_CLOSE_TABS)web_tabs_clear(a);
    else if(id==A_WEB_QUIT){web_quit(a);return true;}
    else if(id>=A_WEB_TAB&&id<A_WEB_TAB+WEB_TABS){if(id-A_WEB_TAB<a->web_tab_count){if(id-A_WEB_TAB!=a->web_tab)web_tab_show(a,id-A_WEB_TAB);else a->web_grid=false;}}
    else if(id>=A_WEB_TAB_CLOSE&&id<A_WEB_TAB_CLOSE+WEB_TABS)web_tab_close(a,id-A_WEB_TAB_CLOSE);
    else if(id==A_WEB_HOME){web_thumb_capture(a);a->web_tabs[a->web_tab].url[0]=a->web_tabs[a->web_tab].title[0]=0;a->web_url[0]=a->web_title[0]=0;a->web_mode=0;if(a->web_fd>=0)web_send(a,"Z");}
    else if(id>=A_WEB_SHORTCUT&&id<A_WEB_SHORTCUT+(int)(sizeof(web_shortcuts)/sizeof(web_shortcuts[0]))){
        const char*url=web_shortcuts[id-A_WEB_SHORTCUT].url;
        a->web_mode=0;  /* the keyboard goes away, as when a link is followed (2026-11-21, #6) */
        if(!url){a->web_menu=false;return installer_action(a,A_WEB_CATALOG);}  /* the catalog: its own page */
        if(web_open_page(a)){char cmd[2050];snprintf(cmd,sizeof(cmd),"N%s",url);web_send(a,cmd);copy(a->web_url,sizeof(a->web_url),url);copy(a->web_tabs[a->web_tab].url,sizeof(a->web_tabs[0].url),url);}
        else copy(a->web_note,sizeof(a->web_note),"Web engine unavailable");
    }
    else if(id==A_WEB_KEYBOARD)a->web_mode=2;
    else if(id==A_WEB_CLEAR)a->web_entry[0]=0;
    else if(id==A_WEB_ADDRESS){
        copy(a->web_entry,sizeof(a->web_entry),web_blank(a->web_url)?"":a->web_url);a->web_mode=1;a->web_caret_at=a->now;
    }else if(id==A_WEB_TYPE)a->web_mode=a->web_mode?0:2;
    else if(id==A_WEB_HISTORY||id==A_WEB_FORWARD){
        if(a->web_mode==1)a->web_mode=0;
        web_send(a,id==A_WEB_HISTORY?"B":"G");
    }
    else if(id==A_WEB_RELOAD){if(a->web_fd<0)web_resume(a);else web_send(a,"R");}
    else if(id==A_BACK&&a->web_fullscreen){web_send(a,"F0");}
    else if(id==A_BACK){
        if(a->web_file_sheet>=0)a->web_file_sheet=-1;
        else if(a->web_menu)web_menu_close(a);
        else if(a->web_page){a->web_page=0;a->page_scroll=0;}
        else if(a->web_grid)a->web_grid=false;
        else if(a->web_mode)a->web_mode=0;
        else screen(a,HOME);
    }else if(!a->web_mode)return false;
    else if(id==A_KB_SHIFT)a->kb_shift=!a->kb_shift;
    else if(id==A_KB_LANG)a->kb_uk=!a->kb_uk;
    else if(id==A_KB_SYMBOLS)a->kb_symbols=!a->kb_symbols;
    else if(id==A_KB_ENTER){
        if(a->web_mode==2)web_send(a,"KEnter");
        else if(a->web_entry[0]){
            if(web_open_page(a)){
                char cmd[2050];snprintf(cmd,sizeof(cmd),"N%s",a->web_entry);web_send(a,cmd);
                a->web_mode=0;copy(a->web_tabs[a->web_tab].url,sizeof(a->web_tabs[0].url),a->web_entry);copy(a->web_url,sizeof(a->web_url),a->web_entry);
            }else copy(a->web_note,sizeof(a->web_note),"Web engine unavailable");
        }
    }else if(id==A_KB_BACKSPACE){
        if(a->web_mode==2)web_send(a,"KBackspace");
        else a->web_entry[utf8_previous(a->web_entry,strlen(a->web_entry))]=0;
    }else if(id==A_KB_SPACE||(id>=A_KB_KEY&&id<A_KB_KEY+a->keyboard_count)){
        char item[6]="T";size_t n=utf8_encode(id==A_KB_SPACE?' ':a->keyboard_keys[id-A_KB_KEY],item+1);
        if(a->web_mode==2)web_send(a,item);
        else if(strlen(a->web_entry)+n<sizeof(a->web_entry))strcat(a->web_entry,item+1);
        a->kb_shift=false;
    }else return false;
    a->web_caret_at=a->now;a->dirty=true;return true;
}

static void web_cancel_touch(App *a){
    if(!a->web_drag)return;
    web_send(a,"X");a->web_drag=false;
}

static bool web_pointer(App *a,bool down,int x,int y){
    if(a->screen!=WEB_BROWSER||!a->web_visible||(!web_page_shown(a)&&!a->web_fullscreen)||a->web_menu)return false;
    if(!down){
        if(!a->web_drag)return false;
        web_send(a,"E");a->web_drag=a->pointer_down=false;
        return true;
    }
    int top=a->web_fullscreen?0:WEB_TOP;
    int bottom=a->web_fullscreen?CH:(a->web_mode?WEB_KEYBOARD_TOP:(a->nav_mode==NAV_BUTTONS?WEB_BUTTONS_BOTTOM:WEB_PAGE_BOTTOM));
    bool start=!a->pointer_down;
    if(start&&(x<0||x>=CW||y<top||y>=bottom))return false;
    /* What the interface shows over the page takes its own touches: an operation's indicator, the
       snackbar's Open (2026-11-22: the page took them, and they could not be tapped in the browser). */
    if(start&&!a->web_fullscreen&&button_at(a,x,y)>=0)return false;
    if(!start&&!a->web_drag)return false;
    int cx=x<0?0:x>=CW?CW-1:x,cy=y<top?top:y>=bottom?bottom-1:y;
    int touch_x=cx/2,touch_y=(cy-top)/2;
    if(a->web_fullscreen=='L'){touch_x=cy/2;touch_y=(CW-1-cx)/2;}
    if(start||touch_x!=a->web_x||touch_y!=a->web_y){
        char message[40];snprintf(message,sizeof(message),"%c%d %d",start?'D':'M',touch_x,touch_y);
        web_send(a,message);a->web_x=touch_x;a->web_y=touch_y;
    }
    if(start){a->web_drag=a->pointer_down=true;a->pressed_action=0;}
    return true;
}

/* The browser in a window over the other pages (2026-11-22, the owner: as Android's freeform windows; the video's
 * window of player_ui.h is its pattern). Its bar moves it, its corner grows it (the page keeps its shape), it
 * folds into a round bubble at an edge and comes back with a tap, opens in full, or closes: the session stays,
 * as for a card of the recent screens, and what plays pauses. The window shows the live page, smaller, and a
 * finger on it is the page's. It stays over every page, an operation's included; the keyboard needs the page
 * in full. */
#define WF_HEAD 64
#define WF_GRIP 56
#define WF_MIN_W 300
#define WF_BUBBLE 44
#define WEB_PAGE_H (WEB_PAGE_BOTTOM-WEB_TOP)
static bool web_float_shown(const App*a){
    return a->wf.open&&a->web_fd>=0&&a->screen!=WEB_BROWSER&&a->screen!=RECENTS&&a->screen!=SPLASH&&a->screen!=LOCKSCREEN&&
           a->screen!=POWER_MENU&&!a->locked&&!a->qs.visible&&!a->mu.full&&!a->recents_capturing&&!a->soft_blanked&&!page_sheet_open(a);
}
static bool web_float_visible(const App*a){return web_float_shown(a)&&!a->wf.bubble;}
/* New frames of the page are drawn: on its own page, or in its window. */
static bool web_frame_wanted(const App*a){return a->web_frame_changed&&(a->screen==WEB_BROWSER||web_float_visible(a));}
static Rect web_float_rect(App*a){
    WebFloat*f=&a->wf;if(!f->w)f->w=440;
    if(f->w<WF_MIN_W)f->w=WF_MIN_W;
    if(f->w>CW-16)f->w=CW-16;
    int h=WF_HEAD+f->w*WEB_PAGE_H/CW;
    if(!f->x&&!f->y){f->x=CW-f->w-20;f->y=240;}
    if(f->x>CW-f->w-8)f->x=CW-f->w-8;
    if(f->x<8)f->x=8;
    if(f->y>CH-h-40)f->y=CH-h-40;
    if(f->y<80)f->y=80;
    return (Rect){f->x,f->y,f->w,h};
}
static Rect web_float_body(Rect r){return (Rect){r.x,r.y+WF_HEAD,r.w,r.h-WF_HEAD};}
static void web_float_bubble_place(App*a,int x,int y){
    a->wf.bx=x<CW/2?WF_BUBBLE+12:CW-WF_BUBBLE-12;
    a->wf.by=y<160?160:(y>CH-200?CH-200:y);
}
static void web_float_button(App*a,Rect r,int action,bool enabled){
    if(a->wf.press==action)veil(a,r,r.h/2,TEXT,30);
    register_button(a,r,action,enabled,0);
}
static void render_web_float(App*a){
    if(!web_float_shown(a))return;
    WebFloat*f=&a->wf;bool clipped=a->clip_active;a->clip_active=false;
    if(f->bubble){
        int cx=f->bx,cy=f->by;
        canvas_shadow(a->pixels,canvas_bounds(a),nx(cx-WF_BUBBLE),nx(cy-WF_BUBBLE),nx(cx+WF_BUBBLE),nx(cy+WF_BUBBLE),24.f,0,110);
        vector_circle(a,cx,cy,WF_BUBBLE,2*WF_BUBBLE,PANEL);vector_circle(a,cx,cy,WF_BUBBLE-2,3,ORANGE);
        icon(a,ICON_BROWSER,cx-22,cy-22,44,ORANGE);
        if(a->mu.web.playing)vector_circle(a,cx+WF_BUBBLE-10,cy-WF_BUBBLE+10,9,18,ORANGE);  /* it plays */
        a->clip_active=clipped;return;
    }
    Rect r=web_float_rect(a),body=web_float_body(r);
    canvas_shadow(a->pixels,canvas_bounds(a),nx(r.x),nx(r.y),nx(r.x+r.w),nx(r.y+r.h),30.f,0,120);
    rounded(a,r,28,BG);rounded(a,r,28,PANEL);  /* opaque, as the video's window */
    /* The bar: back, the page's name, fold to a bubble, open in full, close. */
    Rect back={r.x+4,r.y,60,WF_HEAD},fold={r.x+r.w-186,r.y,60,WF_HEAD},full={r.x+r.w-126,r.y,60,WF_HEAD},close={r.x+r.w-66,r.y,62,WF_HEAD};
    icon(a,ICON_BACK,back.x+12,r.y+14,36,a->web_can_back?TEXT:MUTED);web_float_button(a,back,A_WF_BACK,a->web_can_back);
    char host[160];web_host(a->web_url,host,sizeof(host));const char*name=a->web_title[0]?a->web_title:(host[0]?host:tr("Browser"));
    raw_text(true);ellipsis(a,r.x+70,r.y+18,r.w-70-196,0,TEXT,name);raw_text(false);
    vector_line(a,fold.x+18,r.y+40,fold.x+42,r.y+40,4,TEXT);web_float_button(a,fold,A_WF_FOLD,true);
    icon(a,ICON_EXPAND,full.x+12,r.y+14,36,TEXT);web_float_button(a,full,A_WF_FULL,true);
    icon(a,ICON_CLOSE,close.x+13,r.y+14,36,TEXT);web_float_button(a,close,A_WF_CLOSE,true);
    if(a->web_visible&&!a->web_fullscreen&&web_frame_fits(a)&&!web_ntp(a))web_blit_smooth(a,web_current_frame(a),NW,WEB_H,body,22);
    else{
        rounded(a,body,22,BG);icon(a,ICON_BROWSER,body.x+body.w/2-36,body.y+body.h/2-60,72,MUTED);
        centered(a,(Rect){body.x,body.y+body.h/2+28,body.w,44},0,MUTED,web_ntp(a)?"New tab":"Starting browser");
    }
    a->web_frame_changed=false;
    /* The corner grip: dragged, the window grows or shrinks; the page keeps its shape. */
    int gx=r.x+r.w-14,gy=r.y+r.h-14;
    for(int k=1;k<=3;k++)line(a,gx-10*k,gy,gx,gy-10*k,3,f->resize?ORANGE:MUTED);
    a->clip_active=clipped;
}
/* A finger on the page in the window: the page's own touch, at the page's scale (CSS pixels are half
   the layout's, as in web_pointer). */
static void web_float_touch(App*a,bool start,int x,int y,Rect body){
    int px=(x-body.x)*CW/body.w,py=(y-body.y)*CW/body.w;
    if(px<0)px=0;
    if(px>CW-1)px=CW-1;
    if(py<0)py=0;
    if(py>WEB_PAGE_H-1)py=WEB_PAGE_H-1;
    int tx=px/2,ty=py/2;
    if(start||tx!=a->web_x||ty!=a->web_y){char message[40];snprintf(message,sizeof(message),"%c%d %d",start?'D':'M',tx,ty);web_send(a,message);a->web_x=tx;a->web_y=ty;}
}
/* Touches of the window and of its bubble. Returns whether it took the touch. */
static bool web_float_pointer(App*a,bool down,int x,int y){
    WebFloat*f=&a->wf;
    if(!web_float_shown(a)){f->drag=f->resize=false;f->press=0;return false;}
    if(f->bubble){
        if(down&&!a->pointer_down){
            if(x<f->bx-WF_BUBBLE||x>f->bx+WF_BUBBLE||y<f->by-WF_BUBBLE||y>f->by+WF_BUBBLE)return false;
            a->pointer_down=f->drag=true;f->moved=false;f->dx=x-f->bx;f->dy=y-f->by;a->pressed_action=0;a->dirty=true;return true;
        }
        if(!f->drag)return false;
        if(down){if(abs(x-(f->bx+f->dx))>16||abs(y-(f->by+f->dy))>16)f->moved=true;if(f->moved){f->bx=x-f->dx;f->by=y-f->dy;}a->dirty=true;return true;}
        a->pointer_down=f->drag=false;
        if(f->moved)web_float_bubble_place(a,f->bx,f->by);else f->bubble=false;  /* a tap: the window again */
        a->dirty=true;return true;
    }
    Rect r=web_float_rect(a),body=web_float_body(r);
    if(down&&!a->pointer_down){
        if(!inside(r,x,y))return false;
        a->pointer_down=true;f->moved=false;f->dx=x-r.x;f->dy=y-r.y;f->press=0;a->pressed_action=0;
        if(x>=r.x+r.w-WF_GRIP&&y>=r.y+r.h-WF_GRIP){f->resize=true;f->from_w=r.w;f->from_x=x;a->dirty=true;return true;}
        if(y<body.y){
            for(int n=a->button_count-1;n>=0;n--)if(a->buttons[n].enabled&&a->buttons[n].action>=A_WF_BACK&&a->buttons[n].action<=A_WF_CLOSE&&inside(a->buttons[n].r,x,y)){f->press=a->buttons[n].action;break;}
            f->drag=true;a->dirty=true;return true;
        }
        a->web_drag=true;web_float_touch(a,true,x,y,body);return true;
    }
    if(f->resize){
        if(down){int w=f->from_w+(x-f->from_x);f->w=w<WF_MIN_W?WF_MIN_W:(w>CW-16?CW-16:w);}
        else{a->pointer_down=f->resize=false;(void)web_float_rect(a);}
        a->dirty=true;return true;
    }
    if(a->web_drag){
        if(down)web_float_touch(a,false,x,y,body);
        else{web_send(a,"E");a->web_drag=a->pointer_down=false;}
        return true;
    }
    if(!f->drag)return false;
    if(down){
        if(abs(x-(r.x+f->dx))>16||abs(y-(r.y+f->dy))>16){f->moved=true;f->press=0;}
        if(f->moved){f->x=x-f->dx;f->y=y-f->dy;}
        a->dirty=true;return true;
    }
    a->pointer_down=f->drag=false;int id=f->press;f->press=0;
    if(!f->moved&&id)tap_action(a,id);
    a->dirty=true;return true;
}
static bool web_float_action(App*a,int id){
    if(id==A_WEB_FLOAT){
        if(a->screen!=WEB_BROWSER||a->web_fd<0)return true;
        enum Screen back=came_from(a,HOME);
        a->wf.open=true;a->wf.bubble=false;screen(a,back==WEB_BROWSER?HOME:back);return true;
    }
    if(id<A_WF_BACK||id>A_WF_CLOSE||!a->wf.open)return false;
    if(id==A_WF_BACK)web_send(a,"B");
    else if(id==A_WF_FOLD){Rect r=web_float_rect(a);a->wf.bubble=true;web_float_bubble_place(a,r.x+r.w/2,r.y+WF_HEAD/2);}
    else if(id==A_WF_FULL){a->wf.open=false;screen(a,WEB_BROWSER);}
    else{a->wf.open=false;if(a->mu.web.playing){web_send(a,"Jpause");a->mu.web.playing=false;media_choose(a);}}
    a->dirty=true;return true;
}
