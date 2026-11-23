/* SPDX-License-Identifier: MIT — the media player's page, its window over the interface and its full screen
 * (2026-11-22, the owner; the pictures of the request are the reference: "Aurora · music", "Daylight ·
 * music", "Aurora · video over a task"). The queue is the interface's own: files of Files go into it
 * (their page offers Play and Add to the queue), and the player plays one at a time. */
#ifndef A22X_PLAYER_UI_H
#define A22X_PLAYER_UI_H

#define PLAYER_TOP 274
#define PIP_HEAD 64
#define PIP_FOOT 132
#define PIP_GRIP 56   /* the corner a finger grows the window from */
#define PIP_MIN_W 300

static bool player_item_shown(const App*a,int n){return n>=0&&n<a->mu.count&&a->mu.queue[n].video==(a->mu.tab==1);}
static int player_shown_count(const App*a){int c=0;for(int n=0;n<a->mu.count;n++)c+=player_item_shown(a,n);return c;}
static void player_time(char*out,size_t size,uint32_t ms){unsigned int s=ms/1000u;if(s>=3600)snprintf(out,size,"%u:%02u:%02u",s/3600,s/60%60,s%60);else snprintf(out,size,"%u:%02u",s/60,s%60);}
static const char*player_output_label(const App*a){return a->mu.output_name[0]?a->mu.output_name:tr("Phone speaker");}

/* The picture the player sent, at native pixels, with its top left at layout point (x,y), clipped to CLIP. */
static bool player_blit(App*a,int x,int y,int w,int h,Rect clip){
    if(!a->mu.shm||!a->mu.frame_seq)return false;
    const uint32_t*head=(const uint32_t*)a->mu.shm;uint32_t fw=head[1],fh=head[2],stride=head[3];
    if(!fw||!fh||fw>NW||fh>NH||stride<fw*4u)return false;
    int ox=nx(x)+(nx(w)-(int)fw)/2,oy=nx(y)+(nx(h)-(int)fh)/2;
    int cx0=nx(clip.x),cy0=nx(clip.y),cx1=nx(clip.x+clip.w),cy1=nx(clip.y+clip.h);if(cx0<0)cx0=0;if(cy0<0)cy0=0;if(cx1>NW)cx1=NW;if(cy1>NH)cy1=NH;
    const uint8_t*pixels=a->mu.shm+16;
    for(uint32_t row=0;row<fh;row++){
        int py=oy+(int)row;if(py<cy0||py>=cy1)continue;
        int x0=ox,x1=ox+(int)fw;if(x0<cx0)x0=cx0;if(x1>cx1)x1=cx1;if(x1<=x0)continue;
        memcpy(&a->pixels[(size_t)py*NW+(size_t)x0],pixels+(size_t)row*stride+(size_t)(x0-ox)*4u,(size_t)(x1-x0)*4u);
    }
    return true;
}
/* The size a picture fits into W x H (layout points), as native pixels, keeping its shape. */
static void player_fit(const App*a,int w,int h,int*fw,int*fh){
    int sw=a->mu.src_w>0?a->mu.src_w:16,sh=a->mu.src_h>0?a->mu.src_h:9,nw=nx(w),nh=nx(h);
    if((long)nw*sh<=(long)nh*sw){*fw=nw;*fh=(int)((long)nw*sh/sw);}else{*fh=nh;*fw=(int)((long)nh*sw/sh);}
    *fw&=~1;*fh&=~1;
}
static void player_controls(App*a,int y,int size,bool small){
    const MediaCard*m=&a->mu.local;int gap=small?120:136,c=360;
    if(!small){surface(a,(Rect){c-2*gap-38,y+(size-76)/2,76,76},24,a->mu.shuffle?ORANGE_DARK:PANEL2,A_PL_SHUFFLE);icon(a,ICON_SHUFFLE,c-2*gap-20,y+(size-76)/2+18,40,a->mu.shuffle?ORANGE:TEXT);register_button(a,(Rect){c-2*gap-44,y,88,size},A_PL_SHUFFLE,true,0);}
    surface(a,(Rect){c-gap-38,y+(size-76)/2,76,76},24,PANEL2,A_PL_PREV);icon(a,ICON_PREV,c-gap-20,y+(size-76)/2+18,40,TEXT);register_button(a,(Rect){c-gap-44,y,88,size},A_PL_PREV,true,0);
    gradient(a,(Rect){c-size/2,y,size,size},size/2,ORANGE,ORANGE);if(pressed(a,A_PL_PLAY))veil(a,(Rect){c-size/2,y,size,size},size/2,0xffffffu,30);
    icon(a,m->playing?ICON_PAUSE:ICON_PLAY,c-size/4,y+size/4,size/2,ui_theme->on_accent);register_button(a,(Rect){c-size/2,y,size,size},A_PL_PLAY,a->mu.count>0,0);
    surface(a,(Rect){c+gap-38,y+(size-76)/2,76,76},24,PANEL2,A_PL_NEXT);icon(a,ICON_NEXT,c+gap-20,y+(size-76)/2+18,40,TEXT);register_button(a,(Rect){c+gap-44,y,88,size},A_PL_NEXT,true,0);
    if(!small){surface(a,(Rect){c+2*gap-38,y+(size-76)/2,76,76},24,a->mu.repeat?ORANGE_DARK:PANEL2,A_PL_REPEAT);icon(a,ICON_REPEAT,c+2*gap-20,y+(size-76)/2+18,40,a->mu.repeat?ORANGE:TEXT);register_button(a,(Rect){c+2*gap-44,y,88,size},A_PL_REPEAT,true,0);}
}
static void player_seekbar(App*a,int x0,int x1,int y,uint32_t color_text){
    uint32_t position=media_position_of(a,&a->mu.local),duration=a->mu.local.duration_ms;char left[24],right[24];player_time(left,sizeof(left),position);player_time(right,sizeof(right),duration);
    rounded(a,(Rect){x0,y,x1-x0,10},5,PANEL2);
    int k=duration?x0+(int)((uint64_t)position*(uint64_t)(x1-x0)/duration):x0;if(k>x1)k=x1;
    if(duration){rounded(a,(Rect){x0,y,k-x0,10},5,ORANGE);vector_circle(a,k,y+5,14,14,ORANGE);}
    text(a,x0,y+24,0,color_text,left);text(a,x1-text_width(right,0),y+24,0,color_text,right);
    register_button(a,(Rect){x0-16,y-30,x1-x0+32,70},A_PL_SEEK,duration>0,0);
}
static void render_player_outputs(App*a);
static void render_player(App*a){
    heading(a,"Player",NULL,true);
    /* Music and video, as two tabs of one queue. */
    rounded(a,(Rect){28,184,664,72},36,PANEL);
    for(int t=0;t<2;t++){Rect r={34+t*330,190,322,60};if(a->mu.tab==t)rounded(a,r,30,ORANGE);centered(a,r,1,a->mu.tab==t?ui_theme->on_accent:TEXT,t?"Video":"Music");register_button(a,r,A_PL_TAB+t,true,0);}
    int y=PLAYER_TOP-(int)a->page_scroll;
    a->clip_active=true;a->clip=page_viewport(a);
    if(!a->mu.known&&a->mu.progress[0]){wrapped(a,52,y+20,616,0,MUTED,a->mu.progress,3);y+=110;}
    else if(a->mu.known&&!a->mu.available&&a->mu.reason[0]&&a->mu.player_fd<0){y+=text_tile(a,y,0,ORANGE,a->mu.reason,4)+16;}
    bool current=a->mu.count>0&&a->mu.at<a->mu.count&&a->mu.queue[a->mu.at].video==(a->mu.tab==1);
    Rect card={28,y,664,a->mu.tab?970:1022};rounded(a,card,32,PANEL);
    int cy=y+28;
    if(a->mu.tab==0){
        gradient(a,(Rect){164,cy,392,392},40,ui_theme->tile_fill[3],ui_theme->tile_fill[0]);icon(a,ICON_MUSIC,164+136,cy+136,120,ui_theme->tile_ink[3]);cy+=420;
    }else{
        Rect area={52,cy,616,346};rounded(a,area,24,0x000000u);
        if(current&&a->mu.video&&!a->mu.full){int fw,fh;player_fit(a,area.w,area.h,&fw,&fh);media_frame_size(a,fw,fh);
            Rect clip=a->clip;if(clip.y<area.y)clip.h-=area.y-clip.y,clip.y=area.y;if(clip.y+clip.h>area.y+area.h)clip.h=area.y+area.h-clip.y;
            if(!player_blit(a,area.x,area.y,area.w,area.h,clip))icon(a,ICON_VIDEO,area.x+area.w/2-40,area.y+area.h/2-40,80,MUTED);}
        else icon(a,ICON_VIDEO,area.x+area.w/2-40,area.y+area.h/2-40,80,MUTED);
        surface(a,(Rect){area.x+area.w-84,area.y+area.h-84,68,68},34,PANEL,A_PL_FULL);icon(a,ICON_EXPAND,area.x+area.w-70,area.y+area.h-70,40,TEXT);register_button(a,(Rect){area.x+area.w-90,area.y+area.h-90,80,80},A_PL_FULL,current&&a->mu.video,0);
        cy+=370;
    }
    const char*title=current?a->mu.local.title:tr("Nothing plays");  /* tr() keeps raw text as it is */
    raw_text(true);ellipsis(a,52,cy,616,2,TEXT,title);raw_text(false);
    char sub[160];snprintf(sub,sizeof(sub),"%s",current?(a->mu.local.subtitle[0]?a->mu.local.subtitle:tr("Local file")):tr("Add music or videos from Files"));
    raw_text(true);ellipsis(a,52,cy+62,616,0,MUTED,sub);raw_text(false);cy+=124;
    if(current)player_seekbar(a,52,668,cy,MUTED);else rounded(a,(Rect){52,cy,616,10},5,PANEL2);
    cy+=76;player_controls(a,cy,112,false);cy+=140;
    {Rect v={48,cy,624,92};rounded(a,v,26,PANEL2);icon(a,a->mu.volume==0?ICON_MUTE:ICON_SPEAKER,68,cy+24,44,TEXT);text(a,128,cy+28,0,TEXT,"Sound volume");
     int vol=a->mu.volume?a->mu.volume:80;char p[12];snprintf(p,sizeof(p),"%d%%",vol);text(a,652-text_width(p,0),cy+28,0,MUTED,p);
     int x0=332,x1=560,k=x0+(x1-x0)*vol/100;rounded(a,(Rect){x0,cy+40,x1-x0,10},5,PANEL);rounded(a,(Rect){x0,cy+40,k-x0,10},5,ORANGE);vector_circle(a,k,cy+45,13,13,ORANGE);
     register_button(a,(Rect){x0-20,cy,x1-x0+40,92},A_PL_VOLUME,true,0);a->mu.drag_dy=x0;a->mu.drag_dx=x1;}
    cy+=108;
    {Rect o={48,cy,624,96};surface(a,o,26,PANEL2,A_PL_OUTPUT);bool bt=!strncmp(a->mu.output,"bluealsa",8);
     gradient(a,(Rect){64,cy+16,64,64},32,ORANGE_DARK,ORANGE_DARK);icon(a,bt?ICON_HEADPHONES:ICON_SPEAKER,76,cy+28,40,ORANGE);
     const char*label=player_output_label(a);  /* translated before raw text is on: tr() keeps raw text as it is */
     raw_text(true);ellipsis(a,148,cy+16,460,1,TEXT,label);raw_text(false);text(a,148,cy+60,0,MUTED,bt?"Bluetooth":"This phone");
     icon(a,ICON_CHEVRON,622,cy+30,32,MUTED);register_button(a,o,A_PL_OUTPUT,true,0);}
    y=card.y+card.h+20;
    /* The queue: what is shown is this tab's part of it. */
    {char head[64];snprintf(head,sizeof(head),T("Queue (%d)"),player_shown_count(a));raw_text(true);text(a,44,y+24,1,TEXT,head);raw_text(false);
     surface(a,(Rect){430,y+8,262,72},24,PANEL,A_PL_ADD);icon(a,A_FILES,448,y+24,38,ORANGE);ellipsis(a,496,y+26,186,0,TEXT,"Add files");register_button(a,(Rect){430,y+8,262,72},A_PL_ADD,true,0);}
    y+=100;
    int shown=0;
    for(int n=0;n<a->mu.count;n++){
        if(!player_item_shown(a,n))continue;
        Rect r={28,y,664,100};bool now=n==a->mu.at;surface(a,r,24,now?ORANGE_DARK:PANEL,A_PL_ITEM+n);
        icon(a,a->mu.queue[n].video?ICON_VIDEO:ICON_MUSIC,52,y+28,44,now?ORANGE:MUTED);
        raw_text(true);ellipsis(a,116,y+16,470,0,TEXT,a->mu.queue[n].name);ellipsis(a,116,y+56,470,0,MUTED,a->mu.queue[n].volume);raw_text(false);
        surface(a,(Rect){600,y+18,72,64},20,PANEL2,A_PL_REMOVE+n);icon(a,ICON_CLOSE,618,y+32,36,MUTED);
        register_button(a,(Rect){28,y,560,100},A_PL_ITEM+n,true,0);register_button(a,(Rect){592,y,100,100},A_PL_REMOVE+n,true,0);
        y+=112;shown++;
    }
    if(!shown){wrapped(a,52,y+10,616,0,MUTED,a->mu.tab?"Videos you add from Files show here.":"Music you add from Files shows here. Open a file and choose Play.",3);y+=120;}
    a->page_content=y+(int)a->page_scroll-PLAYER_TOP+40;a->clip_active=false;
    if(a->page_scroll>page_max_scroll(a)){a->page_scroll=page_max_scroll(a);a->dirty=true;}
    if(a->mu.output_sheet)render_player_outputs(a);
    if(a->mu.error[0]&&a->now<a->mu.error_until){text_tile(a,1370,0,ORANGE,a->mu.error,2);}
}
/* Where the sound goes: the phone's speaker, or a Bluetooth audio device that is connected. */
static void render_player_outputs(App*a){
    for(int n=0;n<a->button_count;n++)a->buttons[n].enabled=false;
    veil(a,(Rect){0,0,CW,CH},0,0,110);
    int rows=1;for(unsigned int n=0;n<a->bt.count;n++)rows+=a->bt.devices[n].connected&&!strcmp(a->bt.devices[n].kind,"audio");
    int h=150+rows*112+120;Rect sheet={0,CH-h,CW,h};rounded(a,(Rect){0,sheet.y,CW,h+40},36,BG);rounded(a,(Rect){0,sheet.y,CW,h+40},36,PANEL);
    register_button(a,(Rect){0,0,CW,sheet.y},A_PL_OUT_CLOSE,true,0);  /* a touch above it closes it */
    text(a,40,sheet.y+36,1,TEXT,"Sound output");int y=sheet.y+100;
    bool speaker=strncmp(a->mu.output,"bluealsa",8)!=0;
    surface(a,(Rect){28,y,664,100},24,speaker?ORANGE_DARK:PANEL2,A_PL_OUT_ITEM);icon(a,ICON_SPEAKER,52,y+28,44,speaker?ORANGE:TEXT);text(a,116,y+30,1,TEXT,"Phone speaker");register_button(a,(Rect){28,y,664,100},A_PL_OUT_ITEM,true,0);y+=112;
    for(unsigned int n=0;n<a->bt.count;n++){
        const BtDevice*d=&a->bt.devices[n];if(!d->connected||strcmp(d->kind,"audio"))continue;
        bool on=strstr(a->mu.output,d->address)!=NULL;
        surface(a,(Rect){28,y,664,100},24,on?ORANGE_DARK:PANEL2,A_PL_OUT_ITEM+1+(int)n);icon(a,ICON_HEADPHONES,52,y+28,44,on?ORANGE:TEXT);
        raw_text(true);ellipsis(a,116,y+18,540,1,TEXT,d->name);raw_text(false);text(a,116,y+62,0,MUTED,"Bluetooth");
        register_button(a,(Rect){28,y,664,100},A_PL_OUT_ITEM+1+(int)n,true,0);y+=112;
    }
    button(a,(Rect){28,y+8,664,84},"Bluetooth settings",A_BLUETOOTH,true,false,0);
}

/* --- the window over the interface, and the full screen ----------------------------------------------- */
/* Under the shade and under a sheet of the page it gives way (2026-11-22, the owner: they always win). */
static bool pip_shown(const App*a){
    return a->mu.video&&a->mu.pip&&!a->mu.full&&a->screen!=PLAYER&&!a->locked&&a->screen!=SPLASH&&a->screen!=LOCKSCREEN&&
           !(a->screen==WEB_BROWSER&&a->web_fullscreen)&&!a->qs.visible&&!page_sheet_open(a);
}
static Rect pip_rect(App*a){
    if(!a->mu.pip_w)a->mu.pip_w=440;
    int w=a->mu.pip_w,vh=a->mu.src_w>0?w*a->mu.src_h/a->mu.src_w:w*9/16;if(vh>w)vh=w;
    int h=PIP_HEAD+vh+PIP_FOOT;
    if(!a->mu.pip_x&&!a->mu.pip_y){a->mu.pip_x=CW-w-20;a->mu.pip_y=CH-h-200;}
    if(a->mu.pip_x<8)a->mu.pip_x=8;
    if(a->mu.pip_x>CW-w-8)a->mu.pip_x=CW-w-8;
    if(a->mu.pip_y<80)a->mu.pip_y=80;
    if(a->mu.pip_y>CH-h-60)a->mu.pip_y=CH-h-60;
    return (Rect){a->mu.pip_x,a->mu.pip_y,w,h};
}
static void render_pip(App*a){
    if(a->mu.full){
        /* The whole panel: the picture fitted, its controls for a while after a touch. */
        for(int n=0;n<a->button_count;n++)a->buttons[n].enabled=false;  /* the page under it takes no touch */
        rectangle(a,(Rect){0,0,CW,CH},0x000000u);int fw,fh;player_fit(a,CW,CH,&fw,&fh);media_frame_size(a,fw,fh);
        player_blit(a,0,0,CW,CH,(Rect){0,0,CW,CH});
        if(a->mu.controls&&a->now<a->mu.controls_until){
            veil(a,(Rect){0,0,CW,200},0,0,140);veil(a,(Rect){0,CH-330,CW,330},0,0,160);
            raw_text(true);ellipsis(a,100,70,560,1,0xffffffu,a->mu.local.title);raw_text(false);
            surface(a,(Rect){24,56,64,64},32,PANEL,A_PL_EXIT_FULL);icon(a,ICON_CLOSE,38,70,36,0xffffffu);register_button(a,(Rect){16,48,80,80},A_PL_EXIT_FULL,true,0);
            player_seekbar(a,52,668,CH-290,0xddddddu);player_controls(a,CH-210,112,true);
        }else{a->mu.controls=false;register_button(a,(Rect){0,0,CW,CH},A_PL_SHOW_CONTROLS,true,0);}
        return;
    }
    if(!pip_shown(a))return;
    Rect r=pip_rect(a);int vh=r.h-PIP_HEAD-PIP_FOOT;
    canvas_shadow(a->pixels,canvas_bounds(a),nx(r.x),nx(r.y),nx(r.x+r.w),nx(r.y+r.h),30.f,0,120);
    rounded(a,r,28,BG);rounded(a,r,28,PANEL);  /* opaque: a panel of a glass theme lets the page show through */
    const char*title=a->mu.local.title[0]?a->mu.local.title:tr("Video");
    icon(a,ICON_VIDEO,r.x+20,r.y+14,36,TEXT);raw_text(true);ellipsis(a,r.x+66,r.y+18,r.w-200,0,TEXT,title);raw_text(false);
    icon(a,ICON_EXPAND,r.x+r.w-118,r.y+14,36,TEXT);register_button(a,(Rect){r.x+r.w-130,r.y,60,PIP_HEAD},A_PL_FULL,true,0);
    icon(a,ICON_CLOSE,r.x+r.w-56,r.y+14,36,TEXT);register_button(a,(Rect){r.x+r.w-66,r.y,62,PIP_HEAD},A_PL_CLOSE_PIP,true,0);
    Rect area={r.x+8,r.y+PIP_HEAD,r.w-16,vh};rounded(a,area,16,0x000000u);
    int fw,fh;player_fit(a,area.w,area.h,&fw,&fh);media_frame_size(a,fw,fh);player_blit(a,area.x,area.y,area.w,area.h,area);
    player_seekbar(a,r.x+24,r.x+r.w-24,r.y+PIP_HEAD+vh+20,MUTED);
    int c=r.x+r.w/2,y=r.y+PIP_HEAD+vh+64;
    surface(a,(Rect){c-130,y,76,56},20,PANEL2,A_PL_PREV);icon(a,ICON_PREV,c-110,y+10,36,TEXT);register_button(a,(Rect){c-136,y-6,88,68},A_PL_PREV,true,0);
    surface(a,(Rect){c-38,y,76,56},20,PANEL2,A_PL_PLAY);icon(a,a->mu.local.playing?ICON_PAUSE:ICON_PLAY,c-18,y+10,36,TEXT);register_button(a,(Rect){c-44,y-6,88,68},A_PL_PLAY,true,0);
    surface(a,(Rect){c+54,y,76,56},20,PANEL2,A_PL_NEXT);icon(a,ICON_NEXT,c+74,y+10,36,TEXT);register_button(a,(Rect){c+48,y-6,88,68},A_PL_NEXT,true,0);
    /* The corner grip: dragged, the window grows or shrinks; its picture keeps its shape. */
    int gx=r.x+r.w-14,gy=r.y+r.h-14;
    for(int k=1;k<=3;k++)line(a,gx-10*k,gy,gx,gy-10*k,3,a->mu.pip_resize?ORANGE:MUTED);
}
/* Touches of the window and of the full screen. Returns whether it took the touch. */
static bool pip_pointer(App*a,bool down,int x,int y){
    if(a->mu.full){
        if(down&&!a->pointer_down){a->pointer_down=true;a->mu.pip_moved=false;a->mu.drag_dx=x;a->mu.drag_dy=y;a->pressed_action=0;
            for(int n=a->button_count-1;n>=0;n--)if(a->buttons[n].enabled&&inside(a->buttons[n].r,x,y)){a->pressed_action=a->buttons[n].action;break;}}
        else if(!down&&a->pointer_down){a->pointer_down=false;int id=a->pressed_action;a->pressed_action=0;
            if(id==A_PL_SEEK){if(a->mu.local.duration_ms){uint32_t ms=(uint32_t)((uint64_t)a->mu.local.duration_ms*(uint64_t)(x<52?0:x>668?616:x-52)/616u);a->media_seek_ms=ms;player_local_control(a,A_QS_MEDIA_SEEK);}}
            else if(id)tap_action(a,id);
            a->mu.controls=true;a->mu.controls_until=a->now+4000;}
        a->dirty=true;return true;
    }
    if(!pip_shown(a))return false;
    Rect r=pip_rect(a);
    if(down&&!a->pointer_down){
        if(!inside(r,x,y))return false;
        a->pointer_down=true;a->mu.pip_moved=false;a->mu.drag_dx=x-r.x;a->mu.drag_dy=y-r.y;a->pressed_action=0;
        if(x>=r.x+r.w-PIP_GRIP&&y>=r.y+r.h-PIP_GRIP){a->mu.pip_resize=true;a->mu.resize_from_w=r.w;a->mu.resize_from_x=x;a->mu.pip_drag=false;a->dirty=true;return true;}
        for(int n=a->button_count-1;n>=0;n--)if(a->buttons[n].enabled&&inside(a->buttons[n].r,x,y)&&inside(r,x,y)){a->pressed_action=a->buttons[n].action;break;}
        a->mu.pip_drag=a->pressed_action==0||y<r.y+PIP_HEAD;a->dirty=true;return true;
    }
    if(a->mu.pip_resize){
        if(down){int w=a->mu.resize_from_w+(x-a->mu.resize_from_x);a->mu.pip_w=w<PIP_MIN_W?PIP_MIN_W:w>CW-24?CW-24:w;a->mu.asked_w=-1;}
        else{a->pointer_down=false;a->mu.pip_resize=false;Rect now=pip_rect(a);if(now.x+now.w>CW-12)a->mu.pip_x=CW-now.w-12;}
        a->dirty=true;return true;
    }
    if(!a->mu.pip_drag&&!a->pointer_down)return false;
    if(!a->mu.pip_drag&&a->pressed_action==0)return false;
    if(down){
        if(abs(x-(r.x+a->mu.drag_dx))>16||abs(y-(r.y+a->mu.drag_dy))>16)a->mu.pip_moved=true;
        if(a->mu.pip_moved&&a->mu.pip_drag){a->mu.pip_x=x-a->mu.drag_dx;a->mu.pip_y=y-a->mu.drag_dy;a->pressed_action=0;}
        a->dirty=true;return true;
    }
    a->pointer_down=false;int id=a->pressed_action;a->pressed_action=0;bool moved=a->mu.pip_moved;a->mu.pip_drag=false;
    if(!moved&&id){
        if(id==A_PL_SEEK){int x0=r.x+24,x1=r.x+r.w-24;if(a->mu.local.duration_ms){a->media_seek_ms=(uint32_t)((uint64_t)a->mu.local.duration_ms*(uint64_t)(x<x0?0:x>x1?x1-x0:x-x0)/(uint64_t)(x1-x0));player_local_control(a,A_QS_MEDIA_SEEK);}}
        else tap_action(a,id);
    }
    /* Let go near an edge: it snaps to it. */
    if(moved){Rect now=pip_rect(a);if(now.x+now.w/2<CW/2)a->mu.pip_x=12;else a->mu.pip_x=CW-now.w-12;}
    a->dirty=true;return true;
}

static void player_volume(App*a,int x){
    int x0=a->mu.drag_dy,x1=a->mu.drag_dx;if(x1<=x0)return;
    int v=(x-x0)*100/(x1-x0);if(v<0)v=0;if(v>100)v=100;a->mu.volume=v?v:1;
    char line[24];snprintf(line,sizeof(line),"volume %d\n",v);media_player_send(a,line);a->dirty=true;
}
static bool player_action(App*a,int id){
    if(id==A_PLAYER){a->page_scroll=0;media_link(a,true);screen(a,PLAYER);return true;}
    if(id==A_BACK&&a->screen==PLAYER){if(a->mu.output_sheet){a->mu.output_sheet=false;a->dirty=true;return true;}if(a->mu.video&&a->mu.local.playing)a->mu.pip=true;screen(a,came_from(a,HOME));return true;}
    if(id==A_PL_TAB||id==A_PL_TAB+1){a->mu.tab=id-A_PL_TAB;a->page_scroll=0;a->dirty=true;return true;}
    if(id==A_PL_PLAY){player_local_control(a,A_QS_MEDIA_PLAY);return true;}
    if(id==A_PL_PREV){player_local_control(a,A_QS_MEDIA_PREV);return true;}
    if(id==A_PL_NEXT){player_local_control(a,A_QS_MEDIA_NEXT);return true;}
    if(id==A_PL_SHUFFLE){a->mu.shuffle=!a->mu.shuffle;a->dirty=true;return true;}
    if(id==A_PL_REPEAT){a->mu.repeat=!a->mu.repeat;a->dirty=true;return true;}
    if(id==A_PL_SEEK){
        if(a->mu.local.duration_ms){int x=a->pointer_x;a->media_seek_ms=(uint32_t)((uint64_t)a->mu.local.duration_ms*(uint64_t)(x<52?0:x>668?616:x-52)/616u);player_local_control(a,A_QS_MEDIA_SEEK);}
        return true;
    }
    if(id==A_PL_VOLUME){player_volume(a,a->pointer_x);return true;}
    if(id==A_PL_OUTPUT){a->mu.output_sheet=true;media_service_send(a,"{\"op\":\"status\"}");a->dirty=true;return true;}
    if(id==A_PL_OUT_ITEM){media_output(a,"default","");a->mu.output_sheet=false;return true;}
    if(id==A_PL_OUT_CLOSE){a->mu.output_sheet=false;a->dirty=true;return true;}
    if(id>A_PL_OUT_ITEM&&id<=A_PL_OUT_ITEM+BT_DEVICES_MAX){
        unsigned int n=(unsigned int)(id-A_PL_OUT_ITEM-1);
        if(n<a->bt.count){char device[96];snprintf(device,sizeof(device),"bluealsa:DEV=%s,PROFILE=a2dp",a->bt.devices[n].address);media_output(a,device,a->bt.devices[n].name);}
        a->mu.output_sheet=false;return true;
    }
    if(id==A_PL_ADD){
        /* Files, where music usually is; its file page plays or queues. */
        tap_action(a,A_FILES);return true;
    }
    if(id>=A_PL_ITEM&&id<A_PL_ITEM+MEDIA_QUEUE_MAX){media_play_at(a,id-A_PL_ITEM,false);return true;}
    if(id>=A_PL_REMOVE&&id<A_PL_REMOVE+MEDIA_QUEUE_MAX){
        int n=id-A_PL_REMOVE;if(n>=a->mu.count)return true;
        if(n==a->mu.at){media_player_send(a,"stop\n");a->mu.local.playing=false;a->mu.video=a->mu.pip=false;media_choose(a);}
        memmove(&a->mu.queue[n],&a->mu.queue[n+1],sizeof(MediaItem)*(size_t)(a->mu.count-n-1));a->mu.count--;
        if(a->mu.at>n||(a->mu.at>=a->mu.count&&a->mu.at>0))a->mu.at--;
        if(!a->mu.count){memset(&a->mu.local,0,sizeof(a->mu.local));media_choose(a);}
        a->dirty=true;return true;
    }
    if(id==A_PL_FULL){a->mu.full=true;a->mu.controls=true;a->mu.controls_until=a->now+4000;a->dirty=true;return true;}
    if(id==A_PL_EXIT_FULL){a->mu.full=false;a->dirty=true;return true;}
    if(id==A_PL_SHOW_CONTROLS){a->mu.controls=true;a->mu.controls_until=a->now+4000;a->dirty=true;return true;}
    if(id==A_PL_CLOSE_PIP){media_player_send(a,"stop\n");a->mu.local.playing=false;a->mu.video=a->mu.pip=false;media_frame_size(a,0,0);media_choose(a);a->dirty=true;return true;}
    return false;
}
#endif
