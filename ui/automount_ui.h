/* SPDX-License-Identifier: MIT
 * Volumes mounted when the recovery starts (2026-11-20, the owner: the card mounted for writing at
 * once, with settings to mount everything at start, single partitions for writing or reading, and
 * Android data at start with a prompt for its password; a tester: "/data/media/0 and the SD card
 * mounted read-write immediately after booting, like in TWRP or OrangeFox").
 *
 * automount.py mounts with the saved settings: once per boot when the home page first shows (a RAM
 * marker keeps a restarted interface from doing it again), and for SD cards and USB drives again
 * when a USB drive arrives. Android data that needs its password is then unlocked through the
 * startup unlock of android_session_ui.h, which leaves it mounted in the chosen mode
 * (android_startup_keep). */
#ifndef A22X_AUTOMOUNT_UI_H
#define A22X_AUTOMOUNT_UI_H
static const char*automount_marker="/run/a22x-recovery/automount-started";
static const char*const mount_mode_codes[3]={"off","ro","rw"};
static const char*mount_mode_title(int mode){return mode==0?"Don't mount":mode==1?"Read-only":"Read and write";}
static unsigned int mount_mode_index(const char*code,unsigned int fallback){
    for(unsigned int n=0;n<3;n++)if(code&&!strcmp(code,mount_mode_codes[n]))return n;
    return fallback;
}
/* A volume id as settings.py takes it in mount_list: [a-z0-9][a-z0-9_.-]{0,39}. */
static bool mount_id_ok(const char*id){
    size_t n=strlen(id);if(!n||n>40||id[0]=='-'||id[0]=='_'||id[0]=='.')return false;
    for(;*id;id++)if(!((*id>='a'&&*id<='z')||(*id>='0'&&*id<='9')||*id=='_'||*id=='.'||*id=='-'))return false;
    return true;
}
/* One "id:mode" item of mount_list (LEN bytes at P): its mode, or -1 when it is not well formed. */
static int mount_item(const char*p,size_t len,char*id,size_t id_size){
    const char*colon=memchr(p,':',len);if(!colon)return -1;
    size_t n=(size_t)(colon-p);if(!n||n>=id_size)return -1;
    memcpy(id,p,n);id[n]=0;if(!mount_id_ok(id))return -1;
    for(int k=0;k<3;k++)if(strlen(mount_mode_codes[k])==len-n-1&&!memcmp(colon+1,mount_mode_codes[k],len-n-1))return k;
    return -1;
}
static int mount_override(const App*a,const char*id){
    const char*p=a->mount_list;
    while(*p){
        const char*end=strchr(p,',');size_t n=end?(size_t)(end-p):strlen(p);char item[48];
        int mode=mount_item(p,n,item,sizeof(item));if(mode>=0&&!strcmp(item,id))return mode;
        if(!end)break;
        p=end+1;
    }
    return -1;
}
/* MODE -1 removes the volume's own choice (it follows its group again). Items that are not well
   formed are dropped: settings.py would refuse the whole list, and every later save with it. */
static void mount_override_set(App*a,const char*id,int mode){
    if(!mount_id_ok(id))return;
    char out[sizeof(a->mount_list)]={0};int count=0;const char*p=a->mount_list;
    while(*p){
        const char*end=strchr(p,',');size_t n=end?(size_t)(end-p):strlen(p);char item[48];
        int kept=mount_item(p,n,item,sizeof(item));
        if(kept>=0&&strcmp(item,id)&&count<63&&strlen(out)+n+2<sizeof(out)){if(out[0])append(out,sizeof(out),",");strncat(out,p,n);count++;}
        if(!end)break;
        p=end+1;
    }
    if(mode>=0&&mode<3){
        char item[64];snprintf(item,sizeof(item),"%s:%s",id,mount_mode_codes[mode]);
        if(strlen(out)+strlen(item)+2<sizeof(out)){if(out[0])append(out,sizeof(out),",");append(out,sizeof(out),item);}
    }
    copy(a->mount_list,sizeof(a->mount_list),out);
}
static bool automount_wants_any(const App*a,bool cards_only){
    if(a->mount_cards||strstr(a->mount_list,":r"))return true;
    return !cards_only&&(a->mount_data||a->mount_others);
}
static const char*automount_summary(const App*a){
    if(!automount_wants_any(a,false))return T("Nothing is mounted");
    if(a->mount_cards==2&&a->mount_data==2&&!a->mount_others&&!a->mount_list[0])return T("SD card and Android data");
    return T("Custom");
}
/* On the phone, or on fixture volumes (filesystem.py --fixture) when a test asks for it: the other
   fixture tests expect their volumes as they left them. */
static bool automount_available(const App*a){return !a->preview&&(a->device||(a->fixture[0]&&a->automount_fixture));}
/* The unlock of Android data that mounting at start chose, leaving it mounted (android_startup_keep). */
static bool automount_unlock(App*a){
    a->automount_unlock_offer=false;
    a->android_startup_keep=true;a->android_startup_stage=AS_INVENTORY;a->fs_inventory_destination=HOME;
    return true;
}
/* The banner of the home page: encrypted Android data that mounting at start would open. */
/* The banner leaves by itself (2026-11-20, the owner): AUTOMOUNT_OFFER_MS after it came, it slides
 * down out of sight over AUTOMOUNT_OFFER_OUT_MS. A preview's banner (no time set) stays. */
#define AUTOMOUNT_OFFER_MS 10000u
#define AUTOMOUNT_OFFER_OUT_MS 300u
static void automount_offer_tick(App*a){
    if(!a->automount_unlock_offer||!a->automount_offer_until||a->now<a->automount_offer_until)return;
    if(a->now>=a->automount_offer_until+AUTOMOUNT_OFFER_OUT_MS)a->automount_unlock_offer=false;
    a->dirty=true;
}
static void render_automount_banner(App*a){
    if(!a->automount_unlock_offer||a->screen!=HOME)return;
    /* Gone once the data is mounted, or once an unlock was tried and this recovery session cannot
       authenticate again (2026-11-20: it stayed after a failed unlock from Files). */
    for(int n=0;n<a->volume_count;n++)if(!strcmp(a->volumes[n].id,"userdata")&&
        (a->volumes[n].mounted||!strcmp(a->volumes[n].decrypt_state,"reboot_required"))){a->automount_unlock_offer=false;return;}
    /* Above the last row of tiles, as a sheet with its own close button (the bento home page has
       no free row for it). */
    Rect r={28,1436,664,112};
    if(a->automount_offer_until&&a->now>=a->automount_offer_until){
        float t=(float)(a->now-a->automount_offer_until)/(float)AUTOMOUNT_OFFER_OUT_MS;if(t>1.f)t=1.f;
        r.y+=(int)(t*t*(float)(CH-r.y));
        if(r.y>=CH)return;
    }
    Rect close={r.x+r.w-92,r.y+16,80,80};
    canvas_shadow(a->pixels,canvas_bounds(a),nx(r.x),nx(r.y),nx(r.x+r.w),nx(r.y+r.h),40.f,0,90);
    /* The tiles under the sheet take no tap (button_at gives the first button registered). */
    /* 2026-11-20, on the owner's phone: the whole bottom row took no tap, also where it shows above the
       sheet. A tile keeps the part above the sheet; only what lies under it is cut off. */
    for(int n=0;n<a->button_count;n++){Rect b=a->buttons[n].r;if(b.x<r.x+r.w&&r.x<b.x+b.w&&b.y<r.y+r.h&&r.y<b.y+b.h){
        if(b.y<r.y-24)a->buttons[n].r.h=r.y-b.y;else a->buttons[n].enabled=false;}}
    surface(a,r,26,PANEL2,A_AUTOMOUNT_UNLOCK);
    icon(a,ICON_LOCK,r.x+22,r.y+36,40,ORANGE);
    wrapped(a,r.x+80,r.y+24,r.w-190,0,TEXT,"Android data is encrypted: tap to enter the password",2);
    register_button(a,(Rect){r.x,r.y,r.w-100,r.h},A_AUTOMOUNT_UNLOCK,ui_free(a),0);
    button(a,close,"×",A_AUTOMOUNT_UNLOCK_DISMISS,true,false,0);
}
static bool start_automount_job(App*a,bool cards_only){
    static char helper[PATH_LEN];
    if(a->job.pid||!automount_available(a)||!sibling_helper(a,"automount.py",helper,sizeof(helper)))return false;
    char*args[10];int n=0;
    args[n++]=a->python;args[n++]="-B";args[n++]=helper;
    if(a->device)args[n++]="--device";else{args[n++]="--fixture";args[n++]=a->fixture;}
    args[n++]="run";
    if(cards_only)args[n++]="--cards-only";
    args[n]=NULL;
    a->automount_cards_only=cards_only;
    return launch_job(a,J_AUTOMOUNT,args);
}
static void automount_tick(App*a){
    automount_offer_tick(a);
    if(!automount_available(a)||a->locked||a->settings_broken||a->job.pid||a->settings_pid||a->android_pending||
       a->android_cancel_requested||a->android_format_stage||a->android_startup_stage!=AS_IDLE||a->screen==SPLASH)return;
    if(!a->automount_started){
        if(a->screen!=HOME)return;
        a->automount_started=true;a->automount_rerun=false;
        /* Once per boot: an interface started again (an update, a crash) finds the marker. */
        if(a->device){
            int fd=open(automount_marker,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
            if(fd<0)return;
            close(fd);
        }
        /* settings.py decides with the saved choices; the interface's copy may not be read yet. */
        (void)start_automount_job(a,false);
        return;
    }
    if(!a->automount_rerun)return;
    a->automount_rerun=false;
    if(automount_wants_any(a,true))(void)start_automount_job(a,true);
}
/* J_FS_INVENTORY when the volumes are to be read next: for the unlock of Android data, or for a list
   on screen that shows what was just mounted; J_NONE otherwise. */
static int complete_automount(App*a,const Json*j,bool ok){
    bool cards_only=a->automount_cards_only;a->automount_cards_only=false;
    if(!ok||!j){
        fprintf(stderr,"[recovery-ui:automount] the helper failed\n");
        toast(a,T("Not everything could be mounted at start. Open Files to mount volumes."));return J_NONE;
    }
    unsigned int mounted=0,failed=0;char log[512]="",wanted[8]="";
    int results=json_get(j,0,"results");
    if(results>=0&&j->tokens[results].type==J_ARRAY)
        for(int item=results+1,end=json_next(j,results);item<end;item=json_next(j,item)){
            char id[48]={0},result[24]={0},code[48]={0};
            jstring(j,item,"id",id,sizeof(id));jstring(j,item,"result",result,sizeof(result));jstring(j,item,"code",code,sizeof(code));
            if(!code[0])jstring(j,item,"reason",code,sizeof(code));
            if(!strcmp(result,"mounted"))mounted++;else if(!strcmp(result,"failed"))failed++;
            if(!strcmp(id,"userdata")&&!strcmp(result,"needs_password"))jstring(j,item,"wanted",wanted,sizeof(wanted));
            /* Volume names and result codes only: what a tester's log needs, nothing private. */
            char entry[112];snprintf(entry,sizeof(entry)," %s=%s%s%s",id,result,code[0]?":":"",code);
            if(strlen(log)+strlen(entry)<sizeof(log))append(log,sizeof(log),entry);
        }
    fprintf(stderr,"[recovery-ui:automount]%s%s\n",cards_only?" (drive)":"",log[0]?log:" nothing to mount");
    if(failed)toast(a,T("Not everything could be mounted at start. Open Files to mount volumes."));
    else if(mounted&&cards_only)toast(a,T("USB drive mounted for writing"));
    else if(mounted){char note[96];snprintf(note,sizeof(note),T("Mounted at start: %u"),mounted);toast(a,note);}
    if(!cards_only&&json_bool(j,json_get(j,0,"needs_password"),0)==1&&wanted[0]){
        a->android_startup_rw=!strcmp(wanted,"rw");
        /* The prompt of the startup policy is this one: it is not offered a second time. */
        if(!a->android_startup_handled)(void)android_startup_claim(a);
        /* Only the startup policy unlocks at once. Otherwise a banner on the home page offers it
           (2026-11-20, on the owner's phone: an unlock started by itself at start used the one
           authentication of this recovery session on data it could not open, and showed an error
           nobody had asked for). */
        if(a->android_password_policy!=ANDROID_PASSWORD_STARTUP||a->screen!=HOME){a->automount_unlock_offer=true;a->automount_offer_until=a->now+AUTOMOUNT_OFFER_MS;a->dirty=true;return J_NONE;}
        return automount_unlock(a)?J_FS_INVENTORY:J_NONE;
    }
    if(mounted&&(a->screen==STORAGE||a->screen==FILE_VOLUMES||a->screen==AUTOMOUNT_SETTINGS)){a->fs_inventory_destination=a->screen;return J_FS_INVENTORY;}
    /* Elsewhere a quiet read: the cards mounted now become the backup destinations (see repositories_refresh). */
    if(mounted){a->repositories_refresh=true;return J_FS_INVENTORY;}
    return J_NONE;
}
/* The three modes in one row, each as wide as its label needs (a fixed third cut "Lesen und
   schreiben" and "Lectura y escritura" short). */
static void mount_mode_buttons(App*a,int y,int first_action,unsigned int value,bool enabled){
    int need[3],sum=0,x=44;
    for(int m=0;m<3;m++){need[m]=text_width(mount_mode_title(m),1)+48;sum+=need[m];}
    for(int m=0;m<3;m++){
        int w=m<2?need[m]*616/sum:676-x;
        button(a,(Rect){x,y,w,80},mount_mode_title(m),first_action+m,enabled,value==(unsigned int)m,0);
        x+=w+8;
    }
}
static void render_automount_settings(App*a){
    heading(a,"Mounting at start","Choose what the recovery mounts when it starts.",true);
    a->page_scroll=(int64_t)scroll_clamp((double)a->page_scroll,(double)page_max_scroll(a));
    int y=242-(int)a->page_scroll;
    a->clip_active=true;a->clip=page_viewport(a);
    bool free_ui=ui_free(a);
    const char*titles[3]={"SD card and USB drives","Android data","Other partitions"};
    const char*notes[3]={NULL,"Asks for the Android password when the data is encrypted.","Every other partition this recovery can mount."};
    const unsigned int values[3]={a->mount_cards,a->mount_data,a->mount_others};
    for(int g=0;g<3;g++){
        int h=notes[g]?200+wrapped_height(a,616,0,notes[g],2):186;
        rounded(a,(Rect){28,y,664,h},24,PANEL);text(a,52,y+22,1,TEXT,titles[g]);
        mount_mode_buttons(a,y+80,A_AUTOMOUNT_CARDS+g*3,values[g],free_ui);
        if(notes[g])wrapped(a,52,y+180,616,0,MUTED,notes[g],2);
        y+=h+16;
    }
    text(a,40,y+10,0,ORANGE,"SINGLE PARTITIONS");y+=54;
    y+=text_tile(a,y,0,MUTED,"A single partition's choice comes before the groups above.",2)+16;
    int shown=0;
    for(int n=0;n<a->volume_count&&n<MAX_VOLUMES;n++){
        const FileVolume*v=&a->volumes[n];
        if(!mount_id_ok(v->id)||!(v->mountable||v->decrypt_supported||!strcmp(v->id,"userdata")))continue;
        shown++;rounded(a,(Rect){28,y,664,112},20,PANEL);
        raw_text(true);ellipsis(a,52,y+14,380,1,TEXT,v->label[0]?v->label:v->id);ellipsis(a,52,y+64,380,0,MUTED,v->id);raw_text(false);
        int own=mount_override(a,v->id);
        button(a,(Rect){444,y+18,232,76},own<0?"As above":mount_mode_title(own),A_AUTOMOUNT_VOLUME+n,free_ui,own>=0,0);
        y+=128;
    }
    if(!shown)y+=text_tile(a,y,0,MUTED,a->job.pid?"Reading the partitions...":"No partitions found.",2)+16;
    a->page_content=y+a->page_scroll-230;a->clip_active=false;
}
static bool automount_action(App*a,int id){
    if(id==A_AUTOMOUNT_UNLOCK_DISMISS){a->automount_unlock_offer=false;a->dirty=true;return true;}
    if(id==A_AUTOMOUNT_UNLOCK){
        if(a->automount_unlock_offer&&ui_free(a)&&automount_unlock(a)&&!start_files_job(a,J_FS_INVENTORY)){
            a->android_startup_stage=AS_IDLE;toast(a,T("Open Files to unlock Android data."));
        }
        return true;
    }
    if(id==A_AUTOMOUNT_SETTINGS){
        if(ui_free(a)){a->page_scroll=0;screen(a,AUTOMOUNT_SETTINGS);a->fs_inventory_destination=AUTOMOUNT_SETTINGS;(void)start_files_job(a,J_FS_INVENTORY);}
        return true;
    }
    if(id>=A_AUTOMOUNT_CARDS&&id<A_AUTOMOUNT_CARDS+9){
        if(a->screen==AUTOMOUNT_SETTINGS&&ui_free(a)){
            unsigned int group=(unsigned int)(id-A_AUTOMOUNT_CARDS)/3,mode=(unsigned int)(id-A_AUTOMOUNT_CARDS)%3;
            if(group==0)a->mount_cards=mode;else if(group==1)a->mount_data=mode;else a->mount_others=mode;
            a->automount_dirty=true;settings_changed(a);
        }
        return true;
    }
    if(id>=A_AUTOMOUNT_VOLUME&&id<A_AUTOMOUNT_VOLUME+MAX_VOLUMES){
        int n=id-A_AUTOMOUNT_VOLUME;
        if(a->screen==AUTOMOUNT_SETTINGS&&ui_free(a)&&n<a->volume_count){
            /* Each tap: as above, don't mount, read only, read and write, as above again. */
            int own=mount_override(a,a->volumes[n].id);
            mount_override_set(a,a->volumes[n].id,own>=2?-1:own+1);
            a->automount_dirty=true;settings_changed(a);
        }
        return true;
    }
    if(id==A_BACK&&a->screen==AUTOMOUNT_SETTINGS){screen(a,TOOLS);return true;}
    return false;
}
#endif
