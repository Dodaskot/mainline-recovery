/* SPDX-License-Identifier: MIT */
#ifndef A22X_WIPE_UI_H
#define A22X_WIPE_UI_H

static bool wipe_job(int kind){return kind==J_WIPE_CACHE||kind==J_WIPE_DALVIK||kind==J_ANDROID_RESET;}
/* Android's request to erase its data (2026-11-11): init read misc at the start (bcb.py arrive) and
   left what it found in RAM. The page of Data for Android opens for it once, from the home page. */
static void reset_request_poll(App*a){
    if(a->reset_checked||a->preview)return;
    if(a->screen!=HOME||a->locked||a->job.pid||a->pointer_down)return;
    a->reset_checked=true;
    const char*path=getenv("A22X_RECOVERY_BCB");if(!path||!*path)path="/run/a22x-recovery/bcb.json";
    int fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);char data[2048];ssize_t n=fd>=0?read(fd,data,sizeof(data)-1):-1;if(fd>=0)close(fd);
    if(n<=0)return;
    data[n]=0;JsonToken t[64];Json j;if(json_parse(&j,data,t,64)<1||t[0].type!=J_OBJECT||json_bool(&j,json_get(&j,0,"wipe"),0)!=1)return;
    a->reset_asked=true;a->reset_prompt=strstr(data,"--prompt_and_wipe_data")!=NULL;
    a->wipe_android=true;a->reset_page=true;screen(a,WIPE_REVIEW);
}
/* The owner's word that the request is dropped: misc is cleared, nothing is erased, Android starts as it is. */
static void reset_request_forget(App*a){
    const char*helper=getenv("A22X_RECOVERY_BCB_HELPER");if(!helper||!*helper)helper="/opt/a22x-recovery/bcb.py";
    bool done=a->preview;
    if(!a->preview){
        char*args[6]={a->python,"-B",(char*)helper,a->device?"--device":"--fixture",NULL,NULL};int n=4;
        if(!a->device)args[n++]=a->fixture;
        args[n++]="forget";char*argv[8];for(int k=0;k<n;k++)argv[k]=args[k];argv[n]=NULL;
        pid_t pid=fork();
        if(!pid){(void)close_range(3,~0u,0);int null=open("/dev/null",O_WRONLY);if(null>=0){dup2(null,1);dup2(null,2);}execv(a->python,argv);_exit(2);}
        int status=0;done=pid>0&&waitpid(pid,&status,0)==pid&&WIFEXITED(status)&&WEXITSTATUS(status)==0;
    }
    if(!done){toast(a,"The request could not be cleared");return;}
    a->reset_asked=a->reset_page=false;a->wipe_android=false;unlink(getenv("A22X_RECOVERY_BCB")?getenv("A22X_RECOVERY_BCB"):"/run/a22x-recovery/bcb.json");
    toast(a,"The request is forgotten: Android starts as it is");screen(a,HOME);
}
/* Android's own factory reset (2026-11-21, the owner): Settings checked the owner's password before
   it asked with "--wipe_data", so the reset needs no check here (format_authorization.py
   android_requested_reset decides it again). A request after Android could not open its data
   ("--prompt_and_wipe_data") still asks for the password. */
static bool android_asked_reset(const App*a){return a->wipe_android&&a->reset_page&&a->reset_asked&&!a->reset_prompt;}
static bool start_wipe_job(App*a){
    if(a->job.pid||a->preview||!a->filesystem_helper[0])return false;
    char*args[14];int n=0;args[n++]=a->python;
    /* Data for Android (2026-11-10), TWRP's Format Data: samsung_firmware.py reset-data. */
    if(a->wipe_android){if(!a->samsung_helper[0])return false;args[n++]=a->samsung_helper;}else args[n++]=a->filesystem_helper;
    if(a->device)args[n++]="--device";else{args[n++]="--fixture";args[n++]=a->fixture;}
    if(a->wipe_android){
        bool asked=android_asked_reset(a);
        if(!asked&&(!android_format_ready(a)||strcmp(a->android_format_request.purpose,"android-reset")||strcmp(a->android_format_request.mode,"f2fs")))return false;
        if(asked)a->android_format_grant[0]=0;
        args[n++]="reset-data";if(a->android_format_grant[0]){args[n++]="--format-authorization";args[n++]=a->android_format_grant;}args[n++]="--confirm";args[n]=NULL;
        a->android_format_stage=AF_EXECUTING;bool launched=launch_job(a,J_ANDROID_RESET,args);if(launched)memset(a->android_format_grant,0,sizeof(a->android_format_grant));else a->android_format_stage=AF_REVIEW;return launched;
    }
    args[n++]="wipe";args[n++]="--volume";args[n++]="cache";args[n++]="--confirm";args[n]=NULL;
    return launch_job(a,J_WIPE_CACHE,args);
}
static const FileVolume*dalvik_target(const App*a){
    for(int i=0;i<a->volume_count;i++){
        const FileVolume*v=&a->volumes[i];
        if(!strcmp(v->id,"userdata")&&v->mounted&&!v->read_only&&v->write_supported&&valid_sha256(v->token)
            &&(!a->device||(!strcmp(v->mount_owner,"android-decrypt")&&!strcmp(v->decrypt_state,"mounted"))))return v;
    }
    return NULL;
}
static bool start_dalvik_wipe(App*a){
    const FileVolume*v=dalvik_target(a);
    if(!v||a->job.pid||a->preview||!a->filesystem_helper[0])return false;
    char*args[13];int n=0;
    args[n++]=a->python;args[n++]=a->filesystem_helper;
    if(a->device)args[n++]="--device";else{args[n++]="--fixture";args[n++]=a->fixture;}
    args[n++]="wipe-dalvik";args[n++]="--volume";args[n++]="userdata";
    args[n++]="--expected-volume-token";args[n++]=(char*)v->token;args[n++]="--confirm";args[n]=NULL;
    return launch_job(a,J_WIPE_DALVIK,args);
}
static void complete_wipe_job(App*a,const Json*j,int kind,bool ok){
    bool reset=kind==J_ANDROID_RESET,dalvik=kind==J_WIPE_DALVIK;
    if(reset)android_format_finish(a);
    if(!ok||!j){
        char code[64]="WIPE_FAILED",message[256]="";
        copy(message,sizeof(message),dalvik?T("The Dalvik / ART cache could not be cleared."):T("Cache could not be wiped."));
        if(j){int error=json_get(j,0,"error");if(error>=0&&j->tokens[error].type==J_OBJECT){jstring(j,error,"code",code,sizeof(code));jstring(j,error,"message",message,sizeof(message));}}
        bool erased=false;
        if(j){int error=json_get(j,0,"error"),details=json_get(j,error,"details");erased=json_bool(j,json_get(j,details,"data_erased"),0);}
        if(reset&&erased){
            copy(message,sizeof(message),T("Android data was erased, but cache cleanup failed. Use Wipe cache separately. Do not repeat the data reset."));
            a->reset_asked=a->reset_page=false;a->android_installed=true;
        }
        files_problem(a,code,message,dalvik?WIPE_DALVIK:WIPE);
        if(reset){a->android_refresh_pending=true;start_files_job(a,J_FS_INVENTORY);}
        return;
    }
    if(reset){
        a->successful=true;copy(a->status,sizeof(a->status),"Data formatted for Android");
        copy(a->message,sizeof(a->message),tr("userdata is formatted for Android and metadata erased; Android sets up its encryption on its next start. The recovery's own folder on cache stays."));
        /* The helper cleared Android's request with the data. */
        bool asked=a->reset_page;a->reset_asked=a->reset_page=false;
        a->android_installed=true;a->systems_reboot_blocked=a->install.reboot_blocked=false;a->result_return=asked?HOME:WIPE;screen(a,RESULT);return;
    }
    unsigned int removed=(unsigned int)json_uint(j,json_get(j,0,"removed"),0);
    a->successful=true;
    if(dalvik){
        copy(a->status,sizeof(a->status),T("Dalvik / ART cache cleared"));
        snprintf(a->message,sizeof(a->message),T("Removed %u cache entries."),removed);
    }else{
        char freed[48];human_bytes(json_uint(j,json_get(j,0,"freed_bytes"),0),freed,sizeof(freed));
        copy(a->status,sizeof(a->status),"Cache wiped");
        snprintf(a->message,sizeof(a->message),T("Removed %u items and freed %s. Recovery settings are stored in /misc."),removed,freed);
    }
    a->result_return=WIPE;screen(a,RESULT);
}
static void render_wipe(App*a){
    heading(a,"Wipe","Erase what is no longer needed. Nothing is erased before you hold the button.",true);
    os_card(a,242,150,ICON_TRASH,"Cache","Update packages, logs and temporary files",A_WIPE_CACHE,PANEL);
    os_card(a,408,150,ICON_ERASE,"A whole volume","Format userdata, cache, an SD card or a USB drive",A_WIPE_VOLUMES,PANEL);
    os_card(a,574,150,ICON_PHONE,"Android factory reset","Erase apps and data, keep the installed firmware",A_WIPE_ANDROID,PANEL);
    os_card(a,740,150,ICON_TRASH,"Dalvik / ART cache","Remove compiled Android runtime files",A_WIPE_DALVIK,PANEL);
    os_card(a,906,150,A_STORAGE,"Partition a card","Files, Linux and swap on an SD card",A_CARD,PANEL);
    text_tile(a,1088,0,MUTED,"Erasing userdata removes every Linux system and every saved image.",4);
}
static void render_wipe_dalvik(App*a){
    const FileVolume*v=dalvik_target(a);
    heading(a,"Dalvik / ART cache","Android rebuilds these files during its next startup.",true);
    int y=236+text_tile(a,236,0,MUTED,"Clears the Dalvik and ART runtime cache directories in Android Data.",3)+16;
    if(!a->job.pid&&!v)text_tile(a,y,0,ORANGE,"Unlock Android Data with write access in Files, then return here.",4);
    button(a,(Rect){28,1320,664,104},"Hold 1 second to wipe",A_WIPE_CONFIRM,ui_free(a)&&!a->job.pid&&v,true,3000);
}
static bool wipe_volume_supported(const FileVolume*v){
    return v&&valid_sha256(v->token)&&(!strcmp(v->id,"userdata")||!strcmp(v->id,"cache")||external_volume(v));
}
static void render_wipe_volumes(App*a){
    heading(a,"Erase a volume","Choose a volume to format.",true);
    if(a->job.pid){text(a,40,254,1,MUTED,"Reading storage volumes...");return;}
    int count=0;for(int i=0;i<a->volume_count;i++)count+=wipe_volume_supported(&a->volumes[i]);
    a->page_content=count*156+12;
    a->page_scroll=(int64_t)scroll_clamp((double)a->page_scroll,(double)page_max_scroll(a));
    a->clip_active=true;a->clip=page_viewport(a);
    int y=242-(int)a->page_scroll;
    for(int i=0;i<a->volume_count;i++){
        FileVolume*v=&a->volumes[i];if(!wipe_volume_supported(v))continue;
        Rect r={28,y,664,144};rounded(a,r,24,PANEL);volume_icon(a,v,49,y+45);
        char size[40],detail[100];human_bytes(v->bytes,size,sizeof(size));
        snprintf(detail,sizeof(detail),"%s  /  %s",v->id,size);
        raw_text(true);ellipsis(a,116,y+20,550,1,TEXT,v->label[0]?v->label:v->id);ellipsis(a,116,y+78,550,0,MUTED,detail);raw_text(false);
        register_button(a,r,A_FS_VOLUME_ITEM+i,true,0);y+=156;
    }
    a->clip_active=false;scroll_indicator(a,(Rect){698,230,5,1254},a->page_scroll,a->page_content,ORANGE);
    if(!count)wrapped(a,40,254,640,0,MUTED,"No formattable volumes were found.",3);
}
static void render_wipe_volume(App*a){
    FileVolume*v=current_volume(a);
    heading(a,"Format a volume","Formatting erases every file on this volume.",true);
    if(!wipe_volume_supported(v)){text(a,40,260,1,MUTED,"Volume unavailable");return;}
    rounded(a,(Rect){28,240,664,250},24,PANEL);
    char size[40];human_bytes(v->bytes,size,sizeof(size));
    raw_text(true);wrapped(a,52,266,610,2,TEXT,v->label[0]?v->label:v->id,2);
    ellipsis(a,52,374,606,0,MUTED,v->id);ellipsis(a,52,424,606,0,MUTED,size);raw_text(false);
    if(a->fs_status[0])wrapped(a,40,522,640,0,GREEN,a->fs_status,3);
    bool ready=ui_free(a)&&!a->job.pid&&!a->android_format_cancel_grant[0]&&!a->android_cancel_requested;
    if(v->mounted){
        wrapped(a,40,670,640,0,MUTED,"Unmount the volume before formatting it.",3);
        button(a,(Rect){28,1220,664,88},"Unmount",A_FS_UNMOUNT,ready,false,0);return;
    }
    bool data=!strcmp(v->id,"userdata"),external=external_volume(v);
    if(data)wrapped(a,40,670,640,0,MUTED,"Choose a filesystem. Android may ask you to verify its password.",3);
    if(external){
        /* 2026-11-20, the owner: exFAT and F2FS too; a hold on one erases the volume as it. */
        wrapped(a,40,1130,640,0,MUTED,"Hold a filesystem to erase this volume as it.",2);
        format_choices(a,1220,92,ready,5000);
        return;
    }
    button(a,(Rect){28,1220,320,92},data?"Format ext4":"Hold: erase, ext4",A_FS_FORMAT_EXT4,ready,true,data?0:5000);
    button(a,(Rect){372,1220,320,92},data?"Format F2FS":"Hold: erase, F2FS",A_FS_FORMAT_F2FS,ready,true,data?0:5000);
}
static void android_wipe_auth_button(App*a){
    bool asked=android_asked_reset(a),ready=asked||(android_format_ready(a)&&!strcmp(a->android_format_request.purpose,"android-reset")&&!strcmp(a->android_format_request.mode,"f2fs"));
    const char*note=asked?T("Android checked its password before it asked for this reset."):ready?(a->android_format_unprotected?(T("No Android encryption. Confirm erasing this data.")):(T("Android password verified. Confirmation lasts two minutes."))):(T("First verify the current Android password. Erasing then needs a separate confirmation."));
    wrapped(a,40,1202,640,0,ready?GREEN:MUTED,note,3);
    button(a,(Rect){28,1320,664,104},ready?(T("Hold 2 seconds to format")):(T("Verify before formatting")),A_WIPE_CONFIRM,ui_free(a)&&!a->job.pid,true,ready?5000:0);
}
static void render_wipe_review(App*a){
    if(a->wipe_android&&a->reset_page){
        /* Android itself asked: what it asked, what the hold erases, and the two ways not to. */
        heading(a,"Android asks for a reset","Nothing has been erased yet.",true);
        int y=240+text_tile(a,240,0,ORANGE,a->reset_prompt?"Android could not open its data and asks to erase it. When it failed only once, starting it again may be enough: forget the request and restart.":
                                                              "A factory reset was asked for in Android's settings: Android restarted into this recovery to have its data erased.",4)+16;
        rounded(a,(Rect){28,y,664,206},24,PANEL);text(a,52,y+18,0,RED,"WILL BE ERASED");
        text(a,52,y+58,1,TEXT,"userdata");wrapped(a,300,y+64,370,0,MUTED,"Formatted for Android: every Linux system, saved image and Android's own data",3);
        text(a,52,y+152,1,TEXT,"metadata");wrapped(a,300,y+158,370,0,MUTED,"Android creates it again",1);y+=222;
        text_tile(a,y,0,MUTED,"BOOT stays as it is, and a root in it with it. Until the data is erased or the request is forgotten, a restart of the system comes back here.",4);
        button(a,(Rect){28,1104,324,84},"Not now",A_RESET_LATER,ui_free(a),false,0);
        button(a,(Rect){368,1104,324,84},"Forget the request",A_RESET_FORGET,ui_free(a),false,0);
        android_wipe_auth_button(a);
        return;
    }
    if(a->wipe_android){
        heading(a,"Android factory reset","Nothing has been erased yet.",true);
        rounded(a,(Rect){28,240,664,252},24,PANEL);text(a,52,258,0,RED,"WILL BE ERASED");
        text(a,52,298,1,TEXT,"userdata");wrapped(a,300,304,370,0,MUTED,"Formatted for Android: every Linux system, saved image and Android's own data",3);
        text(a,52,392,1,TEXT,"metadata");wrapped(a,300,398,370,0,MUTED,"Android creates it again",2);
        text(a,52,444,1,TEXT,"cache");wrapped(a,300,450,370,0,MUTED,"The recovery's own folder stays",2);
        text_tile(a,516,0,MUTED,"The installed Android firmware and the SD card are kept. Android sets up encryption on its next start.",4);
        android_wipe_auth_button(a);
        return;
    }
    heading(a,"Wipe cache","Nothing has been erased yet.",true);
    rounded(a,(Rect){28,240,664,120},24,PANEL);text(a,52,258,0,ORANGE,"VOLUME");text(a,52,296,2,TEXT,"cache");
    rounded(a,(Rect){28,376,664,216},24,PANEL);text(a,52,394,0,ORANGE,"STAYS");
    wrapped(a,52,432,606,1,TEXT,"Recovery settings and saved Wi-Fi networks are stored in /misc. The a22x-recovery folder on cache is kept.",4);
    text_tile(a,616,0,MUTED,"Everything else on cache is deleted: update packages, logs and temporary files.",3);
    button(a,(Rect){28,1320,664,104},"Hold 1 second to wipe",A_WIPE_CONFIRM,ui_free(a)&&!a->job.pid,true,3000);
}
static bool wipe_action(App*a,int id){
    if(id==A_WIPE){if(ui_free(a))screen(a,WIPE);return true;}
    if(a->screen==WIPE){
        if(id==A_BACK){reopen(a,came_from(a,OS_MENU));return true;}
        if(id==A_WIPE_CACHE||id==A_WIPE_ANDROID){if(ui_free(a)){a->wipe_android=id==A_WIPE_ANDROID;a->reset_page=a->wipe_android&&a->reset_asked;screen(a,WIPE_REVIEW);}return true;}
        if(id==A_WIPE_DALVIK){
            if(!a->job.pid){a->fs_inventory_destination=WIPE_DALVIK;screen(a,WIPE_DALVIK);start_files_job(a,J_FS_INVENTORY);}
            return true;
        }
        if(id==A_WIPE_VOLUMES){
            if(!ui_free(a))return true;
            a->page_scroll=0;a->fs_inventory_destination=WIPE_VOLUMES;
            screen(a,WIPE_VOLUMES);start_files_job(a,J_FS_INVENTORY);return true;
        }
    }
    if(a->screen==WIPE_DALVIK){
        if(id==A_BACK){a->fs_inventory_destination=FILE_VOLUMES;screen(a,WIPE);return true;}
        if(id==A_WIPE_CONFIRM){if(ui_free(a)&&dalvik_target(a))start_dalvik_wipe(a);return true;}
    }
    if(a->screen==WIPE_VOLUMES){
        if(id==A_BACK){a->fs_inventory_destination=FILE_VOLUMES;screen(a,WIPE);return true;}
        if(id>=A_FS_VOLUME_ITEM&&id<A_FS_VOLUME_ITEM+a->volume_count){
            int index=id-A_FS_VOLUME_ITEM;FileVolume*v=&a->volumes[index];
            if(!a->job.pid&&wipe_volume_supported(v)){
                a->volume_index=index;copy(a->volume_id,sizeof(a->volume_id),v->id);
                a->fs_status[0]=0;a->fs_inventory_destination=WIPE_VOLUME;screen(a,WIPE_VOLUME);
            }
            return true;
        }
    }
    if(a->screen==WIPE_VOLUME){
        if(id==A_BACK){a->fs_inventory_destination=WIPE_VOLUMES;screen(a,WIPE_VOLUMES);return true;}
        FileVolume*v=current_volume(a);
        if(id==A_FS_UNMOUNT){
            if(!a->job.pid&&wipe_volume_supported(v)&&v->mounted)start_files_job(a,J_FS_UNMOUNT);
            return true;
        }
        if(id==A_FS_FORMAT_EXT4||id==A_FS_FORMAT_VFAT||id==A_FS_FORMAT_F2FS||id==A_FS_FORMAT_EXFAT){
            if(a->job.pid||!wipe_volume_supported(v)||v->mounted||a->android_format_cancel_grant[0]||a->android_cancel_requested)return true;
            bool external=external_volume(v);
            if((id==A_FS_FORMAT_VFAT||id==A_FS_FORMAT_EXFAT)&&!external)return true;
            const char*format=format_name(id);
            if(!strcmp(v->id,"userdata"))android_format_start(a,format,false,WIPE_VOLUME);
            else{FileRequest q=file_request(a,J_FS_FORMAT);copy(q.mode,sizeof(q.mode),format);start_files_request(a,&q);}
            return true;
        }
    }
    if(a->screen==WIPE_REVIEW){
        /* Opened for Android's request: back, and Not now, go home, and the request stays. */
        if(a->reset_page&&(id==A_BACK||id==A_RESET_LATER)){a->reset_page=false;a->wipe_android=false;screen(a,HOME);return true;}
        if(a->reset_page&&id==A_RESET_FORGET){if(ui_free(a))reset_request_forget(a);return true;}
        if(id==A_BACK){screen(a,WIPE);return true;}
        if(id==A_WIPE_CONFIRM){
            if(a->wipe_android&&!android_format_ready(a)&&!android_asked_reset(a)){if(ui_free(a))android_format_start(a,"f2fs",true,WIPE_REVIEW);return true;}
            if(ui_free(a)&&!a->job.pid&&!start_wipe_job(a))files_problem(a,"WIPE_UNAVAILABLE","Wait for the current operation to finish.",WIPE);
            return true;
        }
    }
    return false;
}
#endif
