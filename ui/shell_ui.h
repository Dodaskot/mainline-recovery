/* SPDX-License-Identifier: MIT — the interface's shell after the owner's mock-ups (2026-11-22: the home
 * page of variant 01, the navigation of variant 02, the service lists of variant 03).
 *
 *  - Four tabs at the bottom: Overview, Systems, Files, Tools. Each keeps the page it was left on, and a
 *    tap on the tab in use goes back to its first page.
 *  - An operation at work folds into a compact indicator above the tabs ("Collapse" on its page); it
 *    goes on, and its result waits there when it ends while folded.
 *  - Home: installation and backup cards, the systems installed on the phone as
 *    systems_overview.py reads them, and compact tools.
 *  - Lists as full-width rows in one group, a hairline between them.
 *  Floating bars stand on the theme's backdrop, frosted once (canvas_blur), under the panel colour. */
#ifndef A22X_SHELL_UI_H
#define A22X_SHELL_UI_H

#define TAB_TOP 1446      /* the bar ends at 1540: the swipe home starts below it (NAV_BOTTOM is 1530) */
#define TAB_HEIGHT 94
#define TASK_HEIGHT 80
#define OVERVIEW_PATH "/run/a22x-recovery/systems-overview.json"
#define OVERVIEW_EVERY_MS 60000u
/* How long one reading may take (it holds storage shared for about 2 s on the phone); past this it is
   over even when it left no answer (a busy phone answers ok:false and the file stays as it was). */
#define OVERVIEW_RUN_MS 20000u

/* With the three buttons at the bottom (Navigation: Buttons) the tabs stand above them. */
static int tab_top(const App*a){return a->nav_mode==NAV_BUTTONS?1418:TAB_TOP;}
static const char*const tab_label[TAB_COUNT]={"Overview","Systems","Files","Tools"};
static const int tab_glyph[TAB_COUNT]={ICON_OVERVIEW,A_OS,A_FILES,ICON_TUNE};
static enum Screen tab_root(int t){static const enum Screen roots[TAB_COUNT]={HOME,OS_MENU,FILE_VOLUMES,TOOLS};return roots[t<0||t>=TAB_COUNT?0:t];}
static int tab_of_root(enum Screen s){for(int t=0;t<TAB_COUNT;t++)if(tab_root(t)==s)return t;return -1;}
/* The tab a page under the tabs belongs to, when it is not a tab's first page. */
static int tab_of_page(enum Screen s){return s==SYSTEMS||s==ANDROID_MENU?TAB_SYSTEMS:(s==FILE_BROWSER?TAB_FILES:-1);}
/* The pages the tabs stand under: each ends its content above them. */
static bool tab_page_fits(enum Screen s){
    switch(s){case HOME:case OS_MENU:case SYSTEMS:case ANDROID_MENU:case FILE_VOLUMES:case FILE_BROWSER:case TOOLS:return true;default:return false;}
}
/* A file asked for by another page (an image to install, a theme...): that page's flow, not a tab's. */
static bool shell_picking(const App*a){return files_picking(a)||source_pick(a)||a->rom_pick||a->zip_pick||a->samsung_pick||a->compat_pick;}
static bool tab_bar_shown(const App*a){
    return !a->locked&&tab_page_fits(a->screen)&&!shell_picking(a)&&!a->source_sheet&&!a->qs.visible;
}
static bool task_shown(const App*a){
    if(a->locked||a->screen==SPLASH||a->screen==PROGRESS||a->screen==RESULT||a->screen==LOCKSCREEN)return false;
    /* Short work folded from its page shows too (2026-11-22): it went somewhere, and its result comes here. */
    return a->shell.result_waiting||(a->job.pid&&(job_long(a->job.kind)||(a->shell.collapsed&&!job_quiet(a->job.kind)&&!terminal_job(a->job.kind))));
}
/* Where a page's content ends: above the tabs and the indicator of an operation when they show. */
static int shell_bottom(const App*a){
    int bottom=tab_bar_shown(a)?tab_top(a)-14:1484;
    if(task_shown(a))bottom=(tab_bar_shown(a)?tab_top(a):(a->nav_mode==NAV_BUTTONS?1512:1560))-TASK_HEIGHT-24;
    return bottom;
}

/* --- frosted floating panels ------------------------------------------------------------------------------ */
static void shell_glass(App*a,Rect r,int radius){
    if(ui_theme->backdrop&&a->backdrop){
        if(!a->shell.glass)a->shell.glass=malloc((size_t)NW*NH*sizeof(uint32_t));
        if(a->shell.glass&&a->shell.glass_theme!=(const void*)ui_theme){canvas_blur(a->shell.glass,a->backdrop);a->shell.glass_theme=ui_theme;}
        if(a->shell.glass){
            /* The frosted backdrop inside the rounded shape, row by row. */
            int x0=nx(r.x),y0=nx(r.y),x1=nx(r.x+r.w),y1=nx(r.y+r.h);float rad=(float)nx(radius);
            for(int y=y0;y<y1&&y<NH;y++){
                if(y<0)continue;
                float dy=y<y0+rad?(float)(y0+rad-y):(y>=y1-rad?(float)(y-(y1-rad)+1):0.f),inset=dy>0?rad-sqrtf(fmaxf(0.f,rad*rad-dy*dy)):0.f;
                int left=x0+(int)inset,right=x1-(int)inset;if(left<0)left=0;if(right>NW)right=NW;
                if(right>left)memcpy(&a->pixels[(size_t)y*NW+(size_t)left],&a->shell.glass[(size_t)y*NW+(size_t)left],(size_t)(right-left)*4u);
            }
            veil(a,r,radius,PANEL,205);
            tile_outline(a,r,radius,nx(1)>1?nx(1):1,EDGE,140);
            return;
        }
    }
    rounded(a,r,radius,PANEL);tile_outline(a,r,radius,nx(1)>1?nx(1):1,EDGE,140);
}

/* --- the tabs ----------------------------------------------------------------------------------------------------- */
static void render_tab_bar(App*a){
    if(!tab_bar_shown(a))return;
    Rect bar={20,tab_top(a),680,TAB_HEIGHT};
    canvas_shadow(a->pixels,canvas_bounds(a),nx(bar.x),nx(bar.y),nx(bar.x+bar.w),nx(bar.y+bar.h),36.f,0,90);
    shell_glass(a,bar,44);
    int w=bar.w/TAB_COUNT;
    for(int t=0;t<TAB_COUNT;t++){
        Rect cell={bar.x+t*w,bar.y,w,bar.h};bool on=t==a->shell.tab;int cx=cell.x+w/2;
        Rect pill={cx-38,cell.y+12,76,42};
        if(on)rounded(a,pill,21,ORANGE_DARK);
        if(pressed(a,A_TAB+t))veil(a,pill,21,TEXT,36);
        icon(a,tab_glyph[t],cx-17,cell.y+16,34,on?ORANGE:MUTED);
        centered(a,(Rect){cell.x+4,cell.y+60,w-8,30},0,on?TEXT:MUTED,tab_label[t]);
        register_button(a,cell,A_TAB+t,true,0);button_glyph(a,A_TAB+t,tab_glyph[t]);
    }
}
/* The trail of Back for a tab's page: Home, the tab's first page, then that page. */
static void tab_trail(App*a,int t,enum Screen page){
    a->nav_trail[0]=HOME;a->nav_depth=1;
    if(tab_root(t)!=HOME&&page!=tab_root(t)&&a->nav_depth<(int)(sizeof(a->nav_trail)/sizeof(a->nav_trail[0])))a->nav_trail[a->nav_depth++]=tab_root(t);
}
static void tab_open_root(App*a,int t){
    switch(t){
    case TAB_OVERVIEW:screen(a,HOME);break;
    case TAB_SYSTEMS:screen(a,OS_MENU);break;
    case TAB_FILES:tap_action(a,A_FILES);break;           /* the volumes, read again */
    case TAB_TOOLS:if(a->tools_known)screen(a,TOOLS);else tap_action(a,A_TOOLS);break;
    }
}
static void tab_go(App*a,int t){
    if(t<0||t>=TAB_COUNT)return;
    if(t==a->shell.tab){
        /* The tab in use: its first page (a list is left at its place). */
        if(a->screen!=tab_root(t)){tab_trail(a,t,tab_root(t));tab_open_root(a,t);}
        return;
    }
    if(tab_page_fits(a->screen))a->shell.tab_page[a->shell.tab]=(int)a->screen;
    a->shell.tab=t;
    enum Screen page=(enum Screen)a->shell.tab_page[t];
    /* the page kept must be one of this tab's (a page never kept reads as Home) */
    bool mine=tab_of_root(page)==t||tab_of_page(page)==t;
    if(!mine||!tab_page_fits(page)||page==tab_root(t)||(page==FILE_BROWSER&&current_volume(a)==NULL)){tab_trail(a,t,tab_root(t));tab_open_root(a,t);}
    else{tab_trail(a,t,page);screen(a,page);}
    haptic(a,1);
}
/* After every change of page: a tab's first page names the tab; a page under the tabs is the one its
   tab shows again. A file picked for another page leaves the tabs as they are. */
static void shell_screen_changed(App*a){
    if(shell_picking(a))return;
    int t=tab_of_root(a->screen);if(t<0)t=tab_of_page(a->screen);
    if(t>=0)a->shell.tab=t;
    if(tab_page_fits(a->screen)&&a->shell.tab>=0&&a->shell.tab<TAB_COUNT)a->shell.tab_page[a->shell.tab]=(int)a->screen;
}

/* --- the operation folded into its indicator ---------------------------------------------------------------- */
static const char*job_title(int kind){
    switch(kind){
    case J_BACKUP:case J_AD_BACKUP:case J_AD_MEDIA_BACKUP:case J_LD_BACKUP:case J_ID_BACKUP:case J_AD_MODEL_BACKUP:return "Backup";
    case J_VERIFY:case J_AD_VERIFY:case J_COPY_VERIFY:return "Checking a backup";
    case J_RESTORE:case J_AD_MEDIA_RESTORE:case J_AD_APP_RESTORE:case J_LD_RESTORE:case J_ID_RESTORE:case J_COPY_RESTORE:return "Restore";
    case J_IMAGES_DOWNLOAD:case J_UPDATES_FETCH:case J_APK_FETCH:return "Download";
    case J_SYS_IMPORT:return "Installing a system";
    case J_SYS_SWITCH:case J_SYS_RECOVER:return "Switching systems";
    case J_FLASH_WRITE:case J_FLASH_CHECK:return "Flashing a partition";
    case J_FLASH_STAGE:return "Unpacking the update";
    case J_INSTALL_EXECUTE:case J_SAMSUNG_INSTALL:case J_ZIP_RUN:case J_ROOT_INSTALL:case J_MODULE_INSTALL:case J_AD_FIRST_BOOT:return "Installation";
    case J_FS_COPY:case J_FS_COPY_TREE:return "Copying";
    case J_FS_FORMAT:case J_WIPE:case J_WIPE_CACHE:case J_WIPE_DALVIK:case J_ANDROID_RESET:return "Erasing";
    case J_FS_CHECK:case J_FS_RESIZE:return "Checking the filesystem";
    case J_ARCHIVE_PACK:return "Packing an archive";
    case J_ARCHIVE_UNPACK:case J_SAMSUNG_UNPACK:return "Unpacking";
    default:return "Operation";
    }
}
static unsigned int job_percent(const App*a,bool*known){
    *known=a->progress_total>0;if(!*known)return 0;
    uint64_t done=a->progress_done>a->progress_total?a->progress_total:a->progress_done;return (unsigned int)(done*100/a->progress_total);
}
static void render_task(App*a){
    if(!task_shown(a))return;
    int bottom=tab_bar_shown(a)?tab_top(a)-12:(a->nav_mode==NAV_BUTTONS?1508:1556);Rect r={20,bottom-TASK_HEIGHT,680,TASK_HEIGHT};
    /* the page under it is painted again first: a disabled button must not show through */
    canvas_shadow(a->pixels,canvas_bounds(a),nx(r.x),nx(r.y),nx(r.x+r.w),nx(r.y+r.h),30.f,0,90);
    shell_glass(a,r,40);
    if(pressed(a,A_JOB_OPEN))veil(a,r,40,TEXT,24);
    int cx=r.x+46,cy=r.y+r.h/2;
    if(a->shell.result_waiting){
        gradient(a,(Rect){cx-26,cy-26,52,52},26,a->successful?ORANGE:RED,a->successful?ORANGE:RED);
        icon(a,a->successful?ICON_CHECK:ICON_CLOSE,cx-16,cy-16,32,ui_theme->on_accent);
        ellipsis(a,r.x+92,r.y+14,500,1,TEXT,a->successful?"Operation finished":"Operation failed");
        ellipsis(a,r.x+92,r.y+48,500,0,MUTED,"Open the result");
    }else{
        bool known=false;unsigned int percent=job_percent(a,&known);const float top=-1.5707963f,turn=6.2831853f;
        vector_circle(a,cx,cy,24,5,LINE);
        if(known)vector_arc(a,cx,cy,24,5,top,turn*(float)percent/100.f,ORANGE);
        else vector_arc(a,cx,cy,24,5,top+turn*(float)(a->now%1600u)/1600.f,1.6f,ORANGE);
        ellipsis(a,r.x+92,r.y+14,500,1,TEXT,a->job_cancelled?"Cancelling...":job_title(a->job.kind));
        char line[200]="",left[64];
        const char*phase=a->progress_phase[0]?phase_label(a,a->progress_phase):"";
        if(known)snprintf(line,sizeof(line),"%u%%",percent);
        if(progress_left(a,left,sizeof(left))){if(line[0])append(line,sizeof(line),"  ·  ");append(line,sizeof(line),left);}
        else if(phase[0]){if(line[0])append(line,sizeof(line),"  ·  ");append(line,sizeof(line),phase);}
        raw_text(true);ellipsis(a,r.x+92,r.y+48,500,0,MUTED,line[0]?line:tr("Please wait"));raw_text(false);
    }
    icon(a,ICON_CHEVRON,r.x+r.w-56,cy-16,32,MUTED);
    register_button(a,r,A_JOB_OPEN,true,0);
}
/* The operation page's details, folded under one row (the owner's mock-ups: "expandable details"): what
   runs, its stage and part, when it started; the helper's own words where it gives them. */
static void render_job_details(App*a,int y){
    if(!a->job.pid||a->job_cancel_asked)return;
    /* above Collapse and Cancel, and above the note of a step that cannot be stopped */
    int limit=job_cancellable(a->job.kind)&&!a->job_cancelled?1340:1250,room=limit-y;if(room<72)return;
    Rect row={28,y,664,72};surface(a,row,24,PANEL,A_JOB_DETAILS);
    icon(a,ICON_TUNE,52,y+18,36,ORANGE);text(a,104,y+22,1,TEXT,a->shell.details?"Hide details":"Details");
    icon(a,ICON_CHEVRON,640,y+20,32,MUTED);register_button(a,row,A_JOB_DETAILS,true,0);
    if(!a->shell.details)return;
    int top=y+84,lines=0;if(room<84+3*40+24)return;
    rounded(a,(Rect){28,top,664,limit-top},24,PANEL2);
    char line[320];
    snprintf(line,sizeof(line),"%s: %s",tr("Operation"),tr(job_title(a->job.kind)));raw_text(true);ellipsis(a,52,top+18+lines*40,616,0,TEXT,line);raw_text(false);lines++;
    if(a->progress_phase[0]){snprintf(line,sizeof(line),"%s: %s",tr("Stage"),tr(phase_label(a,a->progress_phase)));raw_text(true);ellipsis(a,52,top+18+lines*40,616,0,TEXT,line);raw_text(false);lines++;}
    if(a->progress_part[0]&&top+18+lines*40<limit-40){snprintf(line,sizeof(line),"%s: %s",tr("Part"),a->progress_part);raw_text(true);ellipsis(a,52,top+18+lines*40,616,0,MUTED,line);raw_text(false);lines++;}
    if(a->job_started&&top+18+lines*40<limit-40){char clock[16],date[96];clock_text(a,clock,sizeof(clock),date,sizeof(date));
        uint64_t ago=a->now>a->job_started?(a->now-a->job_started)/60000u:0;snprintf(line,sizeof(line),T("Started %u min ago, helper %s"),(unsigned int)ago,job_name(a->job.kind));
        raw_text(true);ellipsis(a,52,top+18+lines*40,616,0,MUTED,line);raw_text(false);lines++;}
}
/* The page an operation folds back to: where it came from, when that is a page to stay on. */
static enum Screen job_return_page(const App*a){
    enum Screen back=a->result_return;
    if(nav_stays(back)&&back!=PROGRESS)return back;
    return HOME;
}
/* A result of an operation folded away does not take the page: it waits in the indicator (screen()). */
static bool shell_hold_result(App*a,enum Screen s){
    if(s!=RESULT||!a->shell.collapsed||a->screen==PROGRESS||a->screen==RESULT)return false;
    a->shell.result_waiting=true;a->shell.collapsed=false;
    toast(a,a->successful?"Operation finished":"Operation failed");a->toast_icon=a->successful?ICON_CHECK:ICON_CLOSE;
    a->dirty=true;return true;
}
static bool shell_action(App*a,int id){
    /* Back on an operation's page (the key, the arrow of the buttons, the edge swipe) folds it. */
    if(id==A_BACK&&a->screen==PROGRESS&&a->job.pid)id=A_JOB_COLLAPSE;
    if(id>=A_TAB&&id<A_TAB+TAB_COUNT){tab_go(a,id-A_TAB);return true;}
    if(id==A_JOB_OPEN){
        if(a->shell.result_waiting){a->shell.result_waiting=false;screen(a,RESULT);}
        else if(a->job.pid){a->shell.collapsed=false;screen(a,PROGRESS);}
        a->dirty=true;return true;
    }
    if(id==A_JOB_COLLAPSE){if(a->job.pid){a->shell.collapsed=true;screen(a,job_return_page(a));}return true;}
    if(id==A_JOB_DETAILS){a->shell.details=!a->shell.details;a->dirty=true;return true;}
    if(id==A_HOME_SYSTEM){tap_action(a,A_ANDROID);return true;}
    if(id==A_HOME_SYSTEM+1){tap_action(a,A_SYSTEMS);return true;}
    return false;
}

/* --- what is installed (systems_overview.py, read in the background) --------------------------------- */
static void overview_parse(App*a,const char*text){
    static JsonToken tokens[256];Json j;
    if(json_parse(&j,text,tokens,256)<=0||json_bool(&j,json_get(&j,0,"ok"),0)!=1)return;
    ShellState*s=&a->shell;int an=json_get(&j,0,"android"),lx=json_get(&j,0,"linux");
    if(an<0||lx<0)return;
    s->android_data=json_bool(&j,json_get(&j,an,"data"),0)==1;
    jstring(&j,an,"boot",s->boot_kind,sizeof(s->boot_kind));jstring(&j,an,"version",s->android_version,sizeof(s->android_version));
    jstring(&j,an,"patch",s->android_patch,sizeof(s->android_patch));jstring(&j,an,"kernel",s->boot_kernel,sizeof(s->boot_kernel));
    jstring(&j,an,"root",s->boot_root,sizeof(s->boot_root));
    s->linux_count=0;int slots=json_get(&j,lx,"slots");
    if(slots>=0)for(int i=slots+1;i<json_next(&j,slots)&&s->linux_count<OVERVIEW_LINUX_MAX;i=json_next(&j,i)){
        jstring(&j,i,"name",s->linux_names[s->linux_count],sizeof(s->linux_names[0]));
        s->linux_active[s->linux_count]=json_bool(&j,json_get(&j,i,"active"),0)==1&&json_bool(&j,json_get(&j,lx,"boot"),0)==1;
        if(s->linux_names[s->linux_count][0])s->linux_count++;
    }
    s->ov_known=true;a->dirty=true;
}
/* Read again when a page that shows it is open and nothing runs: after a minute, or after any
   operation (one may have installed or removed a system). A busy phone keeps what was known. */
static void overview_tick(App*a){
    /* A reading that left no answer (busy) is over after OVERVIEW_RUN_MS: without this the page never
       read again after one busy answer (live 2026-11-22). */
    if(a->shell.ov_spawned&&a->now-a->shell.ov_at>=OVERVIEW_RUN_MS)a->shell.ov_spawned=false;
    if(!a->device||a->preview)return;
    struct stat st;
    if(stat(OVERVIEW_PATH,&st)==0&&(uint64_t)st.st_mtime*1000u+(uint64_t)(st.st_mtim.tv_nsec/1000000)!=a->shell.ov_mtime){
        a->shell.ov_mtime=(uint64_t)st.st_mtime*1000u+(uint64_t)(st.st_mtim.tv_nsec/1000000);a->shell.ov_spawned=false;
        char text[8192];FILE*f=fopen(OVERVIEW_PATH,"r");
        if(f){size_t n=fread(text,1,sizeof(text)-1,f);fclose(f);text[n]=0;overview_parse(a,text);}
    }
    bool shown=a->screen==HOME||a->screen==OS_MENU;
    if(!shown||a->job.pid||a->shell.ov_spawned)return;
    if(a->shell.ov_at&&a->now-a->shell.ov_at<OVERVIEW_EVERY_MS)return;
    char helper[PATH_LEN];if(!sibling_helper(a,"systems_overview.py",helper,sizeof(helper)))return;
    a->shell.ov_at=a->now?a->now:1;a->shell.ov_spawned=true;
    pid_t pid=fork();if(pid<0){a->shell.ov_spawned=false;return;}
    if(!pid){
        if(fork()==0){
            (void)setsid();(void)close_range(3,~0u,0);unsetenv("A22X_RECOVERY_LOCK_FD");
            int in=open("/dev/null",O_RDONLY|O_CLOEXEC),out=open(OVERVIEW_PATH ".tmp",O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW|O_CLOEXEC,0600);
            if(in>=0)dup2(in,0);
            if(out>=0)dup2(out,1);
            /* The answer replaces the last one only when it is whole (a busy phone answers ok:false). */
            pid_t run=fork();
            if(run==0){char*args[]={a->python,"-B",helper,"--device",NULL};execv(a->python,args);_exit(127);}
            int status=0;while(run>0&&waitpid(run,&status,0)<0&&errno==EINTR){}
            if(run>0&&WIFEXITED(status)&&WEXITSTATUS(status)==0)(void)rename(OVERVIEW_PATH ".tmp",OVERVIEW_PATH);else (void)unlink(OVERVIEW_PATH ".tmp");
            _exit(0);
        }
        _exit(0);
    }
    int status=0;while(waitpid(pid,&status,0)<0&&errno==EINTR){}
}
/* An operation ended: what is installed may have changed. */
static void overview_stale(App*a){a->shell.ov_at=0;}
/* Until when (CLOCK_MONOTONIC ms) a job started now waits for the storage lease a reading may hold:
   0 when none runs. A job that needs storage alone would otherwise fail OPERATION_BUSY whenever it
   starts during the ~2 s of a reading (live 2026-11-22: 2.1 s of every 60 s). */
static uint64_t overview_wait_until(const App*a){
    return a->shell.ov_spawned&&a->now-a->shell.ov_at<OVERVIEW_RUN_MS?a->shell.ov_at+OVERVIEW_RUN_MS:0;
}

/* --- full-width rows ------------------------------------------------------------------------------------------- */
/* One group of rows: a panel, then rows of ROW high with a hairline between them. */
#define LIST_ROW 96
static void list_group(App*a,int y,int rows){rounded(a,(Rect){28,y,664,rows*LIST_ROW},28,PANEL);}
static void list_row(App*a,int y,int index,int rows,int glyph,int tone,const char*title,const char*sub,const char*badge,int action,bool enabled,bool raw){
    Rect r={28,y+index*LIST_ROW,664,LIST_ROW};
    if(pressed(a,action)){int radius=(index==0||index==rows-1)?28:0;veil(a,r,radius,TEXT,20);}
    uint32_t fill=tone<0?ICON_FILL:ui_theme->tile_fill[tone],ink=tone<0?ORANGE:ui_theme->tile_ink[tone];
    gradient(a,(Rect){r.x+20,r.y+20,56,56},18,fill,fill);icon(a,glyph,r.x+32,r.y+32,32,enabled?ink:MUTED);
    /* The title ends before the badge: a fixed width let a long badge ("Запускається") cover the end
       of a long name ("Debian GNU/Linux 13 (trixie)", 2026-11-22, the owner's photo). */
    int badge_w=badge&&badge[0]?text_width(badge,0)+32:0,width=500;
    if(badge_w)width=(r.w-60-badge_w)-96-16;
    raw_text(raw);
    ellipsis(a,r.x+96,r.y+(sub&&sub[0]?16:30),width,1,enabled?TEXT:MUTED,title);
    if(sub&&sub[0])ellipsis(a,r.x+96,r.y+56,width,0,MUTED,sub);
    raw_text(false);
    if(badge_w){Rect b={r.x+r.w-60-badge_w,r.y+30,badge_w,36};rounded(a,b,18,ORANGE_DARK);centered(a,b,0,ORANGE,badge);}
    if(action)icon(a,ICON_CHEVRON,r.x+r.w-48,r.y+32,32,MUTED);
    if(index<rows-1)rectangle(a,(Rect){r.x+96,r.y+r.h-1,r.w-116,1},LINE);
    if(action)register_button(a,r,action,enabled,0);
}

/* --- the installed systems (home, Systems tab) ----------------------------------------------------------- */
static int installed_rows(const App*a){
    const ShellState*s=&a->shell;if(!s->ov_known)return 1;
    int rows=(s->android_data||!strcmp(s->boot_kind,"android"))?1:0;rows+=s->linux_count;
    return rows?rows:1;
}
static int render_installed(App*a,int y,int max_rows){
    const ShellState*s=&a->shell;bool free_ui=ui_free(a);
    int rows=installed_rows(a);if(rows>max_rows)rows=max_rows;
    list_group(a,y,rows);
    if(!s->ov_known){list_row(a,y,0,1,ICON_PHONE,-1,a->device?"Reading the phone...":"Android  ·  Linux","",NULL,0,true,false);return rows*LIST_ROW;}
    int n=0;
    if(s->android_data||!strcmp(s->boot_kind,"android")){
        char title[64],sub[200]="";
        /* BOOT's header names an Android version, but it is the BOOT's, not the system's (on the owner's
           phone: 12 in the header of a KernelSU BOOT under LineageOS 20, Android 13): not shown as the system's. */
        copy(title,sizeof(title),"Android");
        /* root first (it decides what Android can do), then the kernel; the data's absence only when so */
        if(s->boot_root[0]){static const struct{const char*code,*name;}roots[]={{"magisk","Magisk"},{"kernelsu","KernelSU"},{"apatch","APatch"}};
            for(size_t k=0;k<sizeof(roots)/sizeof(roots[0]);k++)if(strstr(s->boot_root,roots[k].code))copy(sub,sizeof(sub),roots[k].name);}
        if(!strcmp(s->boot_kind,"android")&&s->boot_kernel[0]){if(sub[0])append(sub,sizeof(sub),"  ·  ");append(sub,sizeof(sub),s->boot_kernel);}
        if(!s->android_data){if(sub[0])append(sub,sizeof(sub),"  ·  ");append(sub,sizeof(sub),tr("no data on userdata"));}
        else if(!sub[0])copy(sub,sizeof(sub),tr("Data on userdata"));
        bool starts=!strcmp(s->boot_kind,"android");
        raw_text(true);char badge[32];copy(badge,sizeof(badge),starts?tr("Starts"):"");raw_text(false);
        list_row(a,y,n,rows,ICON_PHONE,2,title,sub,badge,A_HOME_SYSTEM,free_ui,true);n++;
    }
    for(int i=0;i<s->linux_count&&n<rows;i++,n++){
        bool last=n==rows-1&&s->linux_count-i>1;char title[120],badge[32];
        if(last)snprintf(title,sizeof(title),T("+%d more"),s->linux_count-i);else copy(title,sizeof(title),s->linux_names[i]);
        copy(badge,sizeof(badge),s->linux_active[i]&&!last?tr("Starts"):"");
        list_row(a,y,n,rows,ICON_LINUX,3,title,last?"":tr("Linux on userdata"),badge,A_HOME_SYSTEM+1,free_ui,true);
    }
    /* Linux in BOOT while userdata is not mounted: its systems cannot be listed, but one is there
       (2026-11-22, live: the page said "No system installed" right after Fedora was installed). */
    if(!n&&!strcmp(s->boot_kind,"linux")){
        raw_text(true);char badge[32];copy(badge,sizeof(badge),tr("Starts"));raw_text(false);
        list_row(a,y,0,1,ICON_LINUX,3,"Linux",tr("In BOOT; mount userdata to see its systems"),badge,A_HOME_SYSTEM+1,free_ui,true);n++;
    }
    if(!n)list_row(a,y,0,1,A_OS,-1,"No system installed","Install Android or Linux",NULL,A_OS,free_ui,false);
    return rows*LIST_ROW;
}

/* --- home -------------------------------------------------------------------------------------------------------- */
static void home_card(App*a,Rect r,unsigned int tone,int action,const char*title,const char*sub,bool raw_sub){
    if(ui_theme->bento){bento_tile(a,r,tone,action,title,sub,tone%2==0);return;}
    surface(a,r,26,PANEL,action);icon_tile(a,action,r.x+20,r.y+18,64,ICON_FILL);
    text(a,r.x+22,r.y+100,1,TEXT,title);
    raw_text(raw_sub);ellipsis(a,r.x+22,r.y+140,r.w-40,0,MUTED,sub);raw_text(false);
    register_button(a,r,action,ui_free(a),0);button_glyph(a,action,action);
}
static void home_tool(App*a,Rect r,int tone,int action,int glyph,const char*label,bool enabled){
    surface(a,r,24,PANEL,action);
    uint32_t fill=tone<0?ICON_FILL:ui_theme->tile_fill[tone],ink=tone<0?ORANGE:ui_theme->tile_ink[tone];
    gradient(a,(Rect){r.x+r.w/2-26,r.y+12,52,52},18,fill,fill);icon(a,glyph,r.x+r.w/2-16,r.y+22,32,enabled?ink:MUTED);
    centered(a,(Rect){r.x+4,r.y+70,r.w-8,30},0,enabled?TEXT:MUTED,label);
    register_button(a,r,action,enabled,0);button_glyph(a,action,glyph);
}
static void render_home_shell(App*a){
    char now[16],date[96];clock_text(a,now,sizeof(now),date,sizeof(date));heading(a,"Mainline Recovery",date,false);
    home_device(a);
    bool plan=a->aplan_valid;char ready[160]="";
    if(plan){snprintf(ready,sizeof(ready),T("Ready from the Android app: %s"),a->aplan_name);}
    /* 2026-11-22, the owner: installing comes first, in two cards, Linux and Android; Backup and Restore
       below them. (Earlier the same day: Files was here twice, a card and a tab, so the card went.) A plan
       from the Android app shows on the Android card. */
    text(a,40,210,0,ORANGE,"INSTALL OR CHANGE");
    home_card(a,(Rect){28,240,324,184},0,A_SYSTEMS,"Install Linux","Debian, Ubuntu and more",false);
    home_card(a,(Rect){368,240,324,184},3,A_ANDROID,"Install Android",plan?ready:"Samsung, GSI or a ROM",plan);
    text(a,40,434,0,ORANGE,"BACKUP AND RESTORE");
    home_card(a,(Rect){28,464,324,184},1,A_BACKUP,"Backup","Save a system snapshot",false);
    home_card(a,(Rect){368,464,324,184},2,A_RESTORE,"Restore","Return to a saved state",false);
    int y=670;text(a,40,y,0,ORANGE,"INSTALLED SYSTEMS");y+=40;
    y+=render_installed(a,y,3)+30;
    text(a,40,y,0,ORANGE,"TOOLS");
    {const char*all=tr("All tools");int w=text_width(all,0)+40;Rect r={692-w,y-14,w,52};
     if(pressed(a,A_TAB+TAB_TOOLS))veil(a,r,26,TEXT,30);
     raw_text(true);text(a,r.x+20,y,0,ORANGE,all);raw_text(false);register_button(a,r,A_TAB+TAB_TOOLS,true,0);}
    y+=40;
    bool free_ui=ui_free(a),joined=a->wifi_connected&&a->wifi_ssid[0];
    static const int glyphs[8]={ICON_WIFI,ICON_LINUX,ICON_BROWSER,ICON_MUSIC,ICON_BLUETOOTH,A_VERIFY,ICON_USB,A_POWER};
    static const int actions[8]={A_WIFI,A_TERMINAL,A_HOME_CATALOG,A_PLAYER,A_BLUETOOTH,A_VERIFY,A_USB_FILES,A_POWER};
    static const char*const labels[8]={"Wi-Fi","Terminal","Browser","Player","Bluetooth","Verify","USB files","Power"};
    for(int i=0;i<8;i++){
        Rect r={28+(i%4)*170,y+(i/4)*120,154,108};
        /* the player, Bluetooth and the browser work beside an operation; the others wait for it */
        bool enabled=actions[i]==A_PLAYER||actions[i]==A_BLUETOOTH||actions[i]==A_HOME_CATALOG?true:free_ui;
        home_tool(a,r,i%6,actions[i],glyphs[i],labels[i],enabled);
        if(i==0&&joined){vector_circle(a,r.x+r.w-22,r.y+20,6,6,GREEN);}
    }
    render_automount_banner(a);
}

/* --- the Tools tab: its utilities above the settings ------------------------------------------------------- */
static int render_tools_utilities(App*a,int y,bool free_ui){
    text(a,40,y,0,ORANGE,"UTILITIES");y+=40;
    static const int glyphs[8]={ICON_LINUX,ICON_WIFI,ICON_BROWSER,ICON_USB,A_STORAGE,A_POWER,A_BACKUP,ICON_BLUETOOTH};
    static const int actions[8]={A_TERMINAL,A_WIFI,A_HOME_CATALOG,A_USB_FILES,A_STORAGE,A_POWER,A_TOOLS_EXPORT,A_BLUETOOTH};
    static const char*const labels[8]={"Terminal","Wi-Fi","Browser","USB files","Storage","Power","Diagnostics","Bluetooth"};
    for(int i=0;i<8;i++)home_tool(a,(Rect){28+(i%4)*170,y+(i/4)*120,154,108},(i+2)%6,actions[i],glyphs[i],labels[i],actions[i]==A_BLUETOOTH||actions[i]==A_HOME_CATALOG?true:free_ui);
    return y+2*120+20;
}

/* --- the Systems tab ------------------------------------------------------------------------------------------- */
static void render_systems_tab(App*a){
    heading(a,"Systems","What is installed, and what to install or change.",true);
    a->page_scroll=(int64_t)scroll_clamp((double)a->page_scroll,(double)page_max_scroll(a));int y=242-(int)a->page_scroll;
    a->clip_active=true;a->clip=page_viewport(a);bool free_ui=ui_free(a);
    y=render_aplan_card(a,y);
    text(a,40,y,0,ORANGE,"INSTALLED");y+=40;
    y+=render_installed(a,y,8)+30;
    text(a,40,y,0,ORANGE,"INSTALL OR CHANGE");y+=40;
    list_group(a,y,4);
    list_row(a,y,0,4,ICON_LINUX,3,"Linux","Distributions from the internet or a file; switch systems",NULL,A_SYSTEMS,free_ui,false);
    list_row(a,y,1,4,ICON_PHONE,2,"Android","Samsung firmware, ROMs and GSIs, root and modules",NULL,A_ANDROID,free_ui,false);
    list_row(a,y,2,4,ICON_FLASH,4,"Flash a partition","BOOT, DTBO, vbmeta and other images",NULL,A_FLASH,free_ui,false);
    list_row(a,y,3,4,ICON_PHONE,1,ad_l("Switch Android","Перемкнути Android","Android wechseln"),
             ad_l("Save it, install another, bring the data back","Зберегти, встановити інший, повернути дані","Sichern, ein anderes installieren, Daten zurückholen"),NULL,A_SWITCH,free_ui,false);
    y+=4*LIST_ROW+24;
    text(a,40,y,0,ORANGE,"MAINTENANCE");y+=40;
    list_group(a,y,1);
    list_row(a,y,0,1,ICON_TRASH,5,"Wipe","Cache, or a whole volume before an installation",NULL,A_WIPE,free_ui,false);
    y+=LIST_ROW+24;
    a->page_content=y+(int)a->page_scroll-230;a->clip_active=false;
    scroll_indicator(a,(Rect){698,230,5,page_height(a)},a->page_scroll,a->page_content,ORANGE);
    if(a->source_sheet)render_source_sheet(a);
}
#endif
