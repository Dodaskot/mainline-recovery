/* Installing a file from its own page (2026-11-21, the owner: ROMs, Linux images and archives, recovery
   ZIPs and scripts were installed only from their own pages, never for a file in Files or a download).
   The name decides what is offered; each flow then reads the content itself and refuses what it is not,
   exactly as when the file is picked on that flow's page. */

static const char*const file_option_label[FO_COUNT]={
    "Flash to a partition","Run its installer","Install as Android","Check if it suits this phone",
    "Install Samsung firmware","Take out the stock BOOT","Install as Linux","Run in the terminal","Install as a root module",
    "Install in Android at its next start"};
static const char*const file_option_note[FO_COUNT]={
    "boot, recovery, vbmeta, super/system ... or an image inside an archive",
    "A recovery ZIP, as in TWRP: kernels, Magisk, add-ons",
    "A ROM ZIP, a GSI or Samsung firmware, reviewed before anything is written",
    "A report that changes nothing: device, partitions, Android version",
    "AP, with BL, CP and CSC found beside it",
    "Saved from the firmware, to root it or to flash it later",
    "A new Linux system from this image or archive; its plan comes first",
    "sh in a shell, in this file's folder",
    "Magisk or KernelSU Next: it joins the modules at the next start of Android",
    "Android installs the app after it starts; Magisk, KernelSU or APatch runs the step"};

static bool file_name_ends(const char*name,const char*tail){size_t n=strlen(name),t=strlen(tail);return n>t&&!strcasecmp(name+n-t,tail);}
/* Samsung's parts: AP_..., BL_..., CP_..., CSC_..., HOME_CSC_... as .tar or .tar.md5. */
static bool samsung_file_name(const char*name){
    if(file_name_ends(name,".tar.md5"))return true;
    if(!file_name_ends(name,".tar"))return false;
    static const char*const parts[]={"AP_","BL_","CP_","CSC_","HOME_CSC_"};
    for(size_t k=0;k<sizeof(parts)/sizeof(parts[0]);k++)if(!strncasecmp(name,parts[k],strlen(parts[k])))return true;
    return false;
}
static int file_options(const App*a,int*out){
    const FileEntry*f=&a->fs_selected;int count=0;
    if(!file_is_regular(f))return 0;
    const char*n=f->name;
    bool zip=file_name_ends(n,".zip"),samsung=samsung_file_name(n),img=image_file_name(n),sevenz=file_name_ends(n,".7z");
    int wanted[FO_COUNT*2],w=0;
    if(samsung){wanted[w++]=FO_SAMSUNG;wanted[w++]=FO_STOCK_BOOT;wanted[w++]=FO_FLASH;}
    if(zip){wanted[w++]=FO_ROM;wanted[w++]=FO_ZIP;wanted[w++]=FO_MODULE;wanted[w++]=FO_COMPAT;wanted[w++]=FO_FLASH;}
    if(img){wanted[w++]=FO_FLASH;wanted[w++]=FO_ROM;}
    if(sevenz)wanted[w++]=FO_ROM;
    if(!samsung&&(systems_image_choice(n,(unsigned long long)f->size)||systems_manifest_name(n)))wanted[w++]=FO_LINUX;
    if(file_name_ends(n,".sh"))wanted[w++]=FO_SCRIPT;
    /* An app; the Magisk ZIP is the Magisk app too (2026-11-21, the owner). */
    if(file_name_ends(n,".apk")||(zip&&strcasestr(n,"magisk")))wanted[w++]=FO_APK;
    for(int k=0;k<w;k++){bool seen=false;for(int m=0;m<count;m++)seen=seen||out[m]==wanted[k];if(!seen)out[count++]=wanted[k];}
    return count;
}

static void render_file_install_sheet(App*a){
    if(!a->fs_install_sheet||a->screen!=FILE_INFO)return;
    int options[FO_COUNT],count=file_options(a,options);
    if(!count){a->fs_install_sheet=false;return;}
    for(int n=0;n<a->button_count;n++)a->buttons[n].enabled=false;
    veil(a,(Rect){0,0,CW,CH},0,0,90);
    int height=128+count*124+120;Rect sheet={0,CH-height,CW,height};
    canvas_shadow(a->pixels,canvas_bounds(a),0,nx(sheet.y),NW,NH,40.f,0,110);
    rounded(a,(Rect){sheet.x,sheet.y,sheet.w,sheet.h+40},36,BG);rounded(a,(Rect){sheet.x,sheet.y,sheet.w,sheet.h+40},36,PANEL);
    raw_text(true);ellipsis(a,40,sheet.y+36,640,2,TEXT,a->fs_selected.name);raw_text(false);
    int y=sheet.y+112;
    for(int k=0;k<count;k++){
        Rect r={28,y,664,112};surface(a,r,24,PANEL2,A_FS_OPTION+options[k]);
        text(a,52,y+14,1,TEXT,file_option_label[options[k]]);ellipsis(a,52,y+64,604,0,MUTED,file_option_note[options[k]]);
        register_button(a,r,A_FS_OPTION+options[k],ui_free(a),0);y+=124;
    }
    button(a,(Rect){28,y+4,664,84},"Close",A_FS_INSTALL_CLOSE,true,false,0);
    register_button(a,(Rect){0,0,CW,sheet.y},A_FS_INSTALL_CLOSE,true,0);
}

/* 'text' in single quotes for sh: a quote inside becomes '\''. False when it does not fit. */
static bool shell_quote(char*out,size_t size,const char*text){
    size_t n=0;if(size<3)return false;
    out[n++]='\'';
    for(;*text;text++){
        if(*text=='\''){if(n+5>=size)return false;memcpy(out+n,"'\\''",4);n+=4;}
        else{if(n+2>=size)return false;out[n++]=*text;}
    }
    out[n++]='\'';out[n]=0;return true;
}
/* sh with the script, in its own folder: volumes are mounted noexec, so not ./script. The command is
   typed into the shell once it runs (complete_terminal_job), so it can be seen and stopped there. */
static void file_run_script(App*a){
    FileVolume*v=current_volume(a);
    if(!v||!v->mounted||!v->mountpoint[0]||!file_is_regular(&a->fs_selected))return;
    char folder[2*PATH_LEN],quoted_folder[4*PATH_LEN],quoted_name[1024];
    snprintf(folder,sizeof(folder),"%s%s",v->mountpoint,a->fs_selected.path);
    char*slash=strrchr(folder,'/');if(slash&&slash!=folder)*slash=0;
    if(!shell_quote(quoted_folder,sizeof(quoted_folder),folder)||!shell_quote(quoted_name,sizeof(quoted_name),a->fs_selected.name)||
       (size_t)snprintf(a->terminal_command,sizeof(a->terminal_command),"cd %s && sh %s\n",quoted_folder,quoted_name)>=sizeof(a->terminal_command)){
        a->terminal_command[0]=0;files_problem(a,"PATH_TOO_LONG","The script's path is too long to type into the shell.",FILE_INFO);return;
    }
    action_run(a,A_TERMINAL);
}

/* Linux from a file: Systems decides first whether it goes beside the Linux there or replaces Android. */
static void files_linux_offer(App*a){
    if(systems_ready(a)){a->systems_adding=true;a->systems_wipe=false;}
    else if(systems_new_android(a)){a->systems_adding=false;a->systems_wipe=true;}
    else{files_problem(a,"SYSTEMS_UNAVAILABLE","Linux cannot be installed now. Install → Operating system shows why.",FILE_INFO);return;}
    a->systems_remote_id[0]=0;a->systems_pick_manifest=true;a->systems_pick_script=false;a->systems_plan_page=0;a->files_linux_from_file=true;
    screen(a,FILE_INFO);
}

/* A root module from its file page (2026-11-21, the owner): android_modules.py reviews the ZIP and the
   Magisk there, and installs it into modules_update with a journal; the page shows that review first. */
static bool module_install_job(int kind){return kind==J_MODULE_INSTALL_PREVIEW||kind==J_MODULE_INSTALL;}
static bool start_module_install_job(App*a,int kind){
    if(a->job.pid||a->preview||!a->modules_helper[0]||!a->mi_volume[0]||!a->mi_token[0]||!a->mi_path[0])return false;
    char*args[20];int n=0;args[n++]=a->python;args[n++]=a->modules_helper;
    if(a->device)args[n++]="--device";else{args[n++]="--fixture";args[n++]=a->fixture;}
    args[n++]=kind==J_MODULE_INSTALL?"install":"install-preview";
    args[n++]="--source-volume";args[n++]=a->mi_volume;args[n++]="--source-token";args[n++]=a->mi_token;args[n++]="--source-path";args[n++]=a->mi_path;
    if(kind==J_MODULE_INSTALL){if(!a->mi_allowed||!valid_sha256(a->mi_sha))return false;args[n++]="--expected-plan";args[n++]=a->mi_sha;args[n++]="--confirm";}
    args[n]=NULL;if(!launch_job(a,kind,args))return false;
    a->result_return=FILE_INFO;return true;
}
static void module_review_start(App*a){
    FileVolume*v=current_volume(a);if(!v)return;
    copy(a->mi_volume,sizeof(a->mi_volume),v->id);copy(a->mi_token,sizeof(a->mi_token),v->token);copy(a->mi_path,sizeof(a->mi_path),a->fs_selected.path);
    a->mi_known=a->mi_allowed=false;a->mi_review=true;a->page_scroll=0;a->dirty=true;
    if(!start_module_install_job(a,J_MODULE_INSTALL_PREVIEW)){a->mi_review=false;files_problem(a,"MODULE_REVIEW_UNAVAILABLE","Wait for the current operation to finish.",FILE_INFO);}
}
static void complete_module_install_job(App*a,const Json*j,int kind,bool ok){
    char code[96]="MODULE_RESULT_INVALID",message[512]="The helper returned an incomplete result. Nothing was installed.";
    if(!ok||!j||!json_bool(j,json_get(j,0,"ok"),0)){
        if(j){int e=json_get(j,0,"error");if(e>=0){jstring(j,e,"code",code,sizeof(code));jstring(j,e,"message",message,sizeof(message));}}
        a->mi_review=false;a->mi_known=false;files_problem(a,code,message,FILE_INFO);return;
    }
    if(kind==J_MODULE_INSTALL){
        if(!jequals(j,0,"status","applied")||!jequals(j,0,"plan_sha256",a->mi_sha)){a->mi_review=false;files_problem(a,code,message,FILE_INFO);return;}
        a->mi_review=a->mi_known=false;a->successful=true;copy(a->status,sizeof(a->status),"Module installed");
        /* KernelSU Next's ksud moves a pending module in as Magisk does (2026-11-22, goal item 6). */
        snprintf(a->message,sizeof(a->message),!strncmp(a->mi_framework,"KernelSU",8)?T("%s %s is waiting in /data/adb/modules_update. KernelSU Next moves it in at the next start of Android; customize.sh was not run here."):T("%s %s is waiting in /data/adb/modules_update. Magisk moves it in at the next start of Android; customize.sh was not run here."),a->mi_name,a->mi_version);
        a->result_return=FILE_INFO;screen(a,RESULT);return;
    }
    int p=json_get(j,0,"plan"),m=p>=0?json_get(j,p,"module"):-1,f=p>=0?json_get(j,p,"framework"):-1,i=p>=0?json_get(j,p,"installed"):-1;
    if(p<0||m<0||!jequals(j,p,"schema","a22x.android-modules.plan.v1")||!jequals(j,p,"action","install")){a->mi_review=false;files_problem(a,code,message,FILE_INFO);return;}
    jstring(j,p,"plan_sha256",a->mi_sha,sizeof(a->mi_sha));a->mi_allowed=json_bool(j,json_get(j,p,"allowed"),0)!=0;
    a->mi_reason[0]=0;jstring(j,p,"reason",a->mi_reason,sizeof(a->mi_reason));
    jstring(j,m,"id",a->mi_id,sizeof(a->mi_id));jstring(j,m,"name",a->mi_name,sizeof(a->mi_name));jstring(j,m,"version",a->mi_version,sizeof(a->mi_version));
    jstring(j,m,"author",a->mi_author,sizeof(a->mi_author));jstring(j,m,"description",a->mi_description,sizeof(a->mi_description));
    a->mi_files=json_uint(j,json_get(j,m,"files"),0);a->mi_bytes=json_uint(j,json_get(j,m,"bytes"),0);
    a->mi_no_mount=json_bool(j,json_get(j,p,"mount_needs_metamodule"),0)!=0;
    int nr=json_get(j,m,"not_run");a->mi_not_run=nr>=0&&j->tokens[nr].type==J_ARRAY&&json_next(j,nr)>nr+1;
    a->mi_boot[0]=0;int bc=json_get(j,m,"boot_content");
    if(bc>=0&&j->tokens[bc].type==J_ARRAY)for(int k=bc+1;k<json_next(j,bc);k=json_next(j,k)){char item[40]={0};if(json_string(j,k,item,sizeof(item))<0)continue;if(a->mi_boot[0])append(a->mi_boot,sizeof(a->mi_boot),", ");append(a->mi_boot,sizeof(a->mi_boot),item);}
    a->mi_framework[0]=0;if(f>=0){char id_[32]={0},ver[32]={0};jstring(j,f,"id",id_,sizeof(id_));jstring(j,f,"version",ver,sizeof(ver));snprintf(a->mi_framework,sizeof(a->mi_framework),"%s %s",!strcmp(id_,"kernelsu")?"KernelSU Next":!strcmp(id_,"magisk")?"Magisk":id_,ver);}
    a->mi_installed[0]=0;if(i>=0&&j->tokens[i].type==J_OBJECT)jstring(j,i,"version",a->mi_installed,sizeof(a->mi_installed));
    if(!valid_sha256(a->mi_sha)||!module_id_valid(a->mi_id)){a->mi_review=false;files_problem(a,code,message,FILE_INFO);return;}
    /* The review on the file page: a long job left the page for its progress (2026-11-21, on the phone it stayed there). */
    a->mi_known=true;a->mi_review=true;a->page_scroll=0;screen(a,FILE_INFO);
}
static void render_module_review(App*a){
    heading(a,"Root module",a->mi_known?NULL:"Reading the module...",true);
    if(!a->mi_known){wrapped(a,48,300,624,1,MUTED,"The ZIP and the root on this Android are being checked. Nothing is written yet.",4);return;}
    char line[512],size[48];human_bytes(a->mi_bytes,size,sizeof(size));
    rounded(a,(Rect){28,232,664,300},24,PANEL);
    raw_text(true);ellipsis(a,52,256,616,2,TEXT,a->mi_name);snprintf(line,sizeof(line),"%s  ·  %s",a->mi_version,a->mi_id);ellipsis(a,52,318,616,0,ORANGE,line);
    if(a->mi_author[0])ellipsis(a,52,360,616,0,MUTED,a->mi_author);
    wrapped(a,52,404,616,0,TEXT,a->mi_description,3);raw_text(false);
    int y=556;
    snprintf(line,sizeof(line),T("%llu files, %s"),a->mi_files,size);text_tile(a,y,0,TEXT,line,1);y+=74;
    {bool none=!a->mi_framework[0]||!strncmp(a->mi_framework,"unknown",7);snprintf(line,sizeof(line),"%s: %s",tr("Root"),none?tr("not found"):a->mi_framework);
     raw_text(true);text_tile(a,y,0,TEXT,line,1);raw_text(false);y+=74;}
    if(a->mi_installed[0]){snprintf(line,sizeof(line),T("Replaces version %s"),a->mi_installed);raw_text(true);text_tile(a,y,0,TEXT,line,1);raw_text(false);y+=74;}
    if(a->mi_boot[0]){snprintf(line,sizeof(line),T("Runs at Android's start: %s"),a->mi_boot);raw_text(true);text_tile(a,y,0,MUTED,line,2);raw_text(false);y+=104;}
    bool ksu=!strncmp(a->mi_framework,"KernelSU",8);
    if(a->mi_not_run){text_tile(a,y,0,ORANGE,ksu?"Its customize.sh is not run here. A module that needs it may not work: then install it from the KernelSU Next app.":"Its customize.sh is not run here. A module that needs it may not work: then install it from the Magisk app.",3);y+=134;}
    if(a->mi_no_mount){text_tile(a,y,0,ORANGE,"KernelSU Next mounts a module's system files only through a metamodule, and none is installed: here only its scripts will run.",3);y+=134;}
    if(!a->mi_allowed)text_tile(a,y,0,ORANGE,a->mi_reason[0]?a->mi_reason:"This module cannot be installed here.",3);  /* translated by text_tile */
    else text_tile(a,y,0,MUTED,ksu?"It goes to /data/adb/modules_update, with a journal; KernelSU Next moves it in at the next start of Android.":"It goes to /data/adb/modules_update, with a journal; Magisk moves it in at the next start of Android.",3);
    button(a,(Rect){28,1330,664,108},a->mi_allowed?"Hold 1 s to install":"Cannot be installed here",A_MODULE_INSTALL_CONFIRM,ui_free(a)&&a->mi_allowed,true,a->mi_allowed?1000:0);
}

/* An app for Android's next start (apk_queue.py, 2026-11-21): reviewed on the file page, then queued with a
   hold. The recovery cannot install it; Android's package manager does, run by the root's boot script. */
static bool apk_job(int kind){return kind==J_APK_PREVIEW||kind==J_APK_QUEUE||kind==J_APK_FETCH_PREVIEW||kind==J_APK_FETCH;}
static bool start_apk_job(App*a,int kind){
    if(a->job.pid||a->preview||!a->apk_helper[0])return false;
    char*args[20];int n=0;args[n++]=a->python;args[n++]=a->apk_helper;
    if(a->device)args[n++]="--device";else{args[n++]="--fixture";args[n++]=a->fixture;}
    args[n++]=kind==J_APK_PREVIEW?"preview":kind==J_APK_QUEUE?"queue":kind==J_APK_FETCH_PREVIEW?"fetch-preview":"fetch";
    if(kind==J_APK_PREVIEW||kind==J_APK_QUEUE){
        if(!a->aq_volume[0]||!a->aq_token[0]||!a->aq_path[0])return false;
        args[n++]="--source-volume";args[n++]=a->aq_volume;args[n++]="--source-token";args[n++]=a->aq_token;args[n++]="--source-path";args[n++]=a->aq_path;
    }else{if(!a->aq_app[0])return false;args[n++]="--app";args[n++]=a->aq_app;}
    if(kind==J_APK_QUEUE||kind==J_APK_FETCH){if(!a->aq_allowed||!valid_sha256(a->aq_sha))return false;args[n++]="--expected-plan";args[n++]=a->aq_sha;args[n++]="--confirm";}
    args[n]=NULL;if(!launch_job(a,kind,args))return false;
    a->result_return=a->aq_back;return true;
}
static void apk_review_begin(App*a,enum Screen back){a->aq_known=a->aq_allowed=false;a->aq_review=true;a->aq_back=back;a->page_scroll=0;a->dirty=true;}
static void apk_review_file(App*a,const char*volume,const char*token,const char*path,enum Screen back){
    copy(a->aq_volume,sizeof(a->aq_volume),volume);copy(a->aq_token,sizeof(a->aq_token),token);copy(a->aq_path,sizeof(a->aq_path),path);
    a->aq_fetch=false;a->aq_app[0]=0;apk_review_begin(a,back);
    if(!start_apk_job(a,J_APK_PREVIEW)){a->aq_review=false;files_problem(a,"APK_REVIEW_UNAVAILABLE","Wait for the current operation to finish.",back);}
}
static void apk_review_fetch(App*a,const char*app,enum Screen back){
    copy(a->aq_app,sizeof(a->aq_app),app);a->aq_fetch=true;a->aq_volume[0]=a->aq_token[0]=a->aq_path[0]=0;apk_review_begin(a,back);
    if(!start_apk_job(a,J_APK_FETCH_PREVIEW)){a->aq_review=false;files_problem(a,"APK_REVIEW_UNAVAILABLE","Wait for the current operation to finish.",back);}
}
static void complete_apk_job(App*a,const Json*j,int kind,bool ok){
    char code[96]="APK_RESULT_INVALID",message[512]="The helper returned an incomplete result. Nothing was queued.";
    if(!ok||!j||!json_bool(j,json_get(j,0,"ok"),0)){
        if(j){int e=json_get(j,0,"error");if(e>=0){jstring(j,e,"code",code,sizeof(code));jstring(j,e,"message",message,sizeof(message));}}
        a->aq_review=a->aq_known=false;files_problem(a,code,message,a->aq_back);return;
    }
    if(kind==J_APK_QUEUE||kind==J_APK_FETCH){
        if(!jequals(j,0,"status","queued")||!jequals(j,0,"plan_sha256",a->aq_sha)){a->aq_review=false;files_problem(a,code,message,a->aq_back);return;}
        a->aq_review=a->aq_known=false;a->successful=true;copy(a->status,sizeof(a->status),"App queued");
        snprintf(a->message,sizeof(a->message),T("%s waits in /data/adb/a22x-apk-queue. Android installs it after its next start; the result is written to install.log beside it."),a->aq_label[0]?a->aq_label:a->aq_name);
        a->result_return=a->aq_back;screen(a,RESULT);return;
    }
    int p=json_get(j,0,"plan"),k=p>=0?json_get(j,p,"apk"):-1;
    if(p<0||k<0||!jequals(j,p,"schema","a22x.apk-queue.plan.v1")){a->aq_review=false;files_problem(a,code,message,a->aq_back);return;}
    jstring(j,p,"plan_sha256",a->aq_sha,sizeof(a->aq_sha));a->aq_allowed=json_bool(j,json_get(j,p,"allowed"),0)!=0;a->aq_setup=json_bool(j,json_get(j,p,"magisk_setup"),0)!=0;
    a->aq_reason[0]=0;jstring(j,p,"reason",a->aq_reason,sizeof(a->aq_reason));a->aq_framework[0]=0;jstring(j,p,"framework",a->aq_framework,sizeof(a->aq_framework));
    jstring(j,k,"name",a->aq_name,sizeof(a->aq_name));a->aq_label[0]=a->aq_version[0]=0;jstring(j,k,"label",a->aq_label,sizeof(a->aq_label));jstring(j,k,"version",a->aq_version,sizeof(a->aq_version));
    a->aq_size=json_uint(j,json_get(j,k,"size"),0);int w=json_get(j,p,"waiting");a->aq_waiting=0;
    if(w>=0&&j->tokens[w].type==J_ARRAY)for(int i=w+1;i<json_next(j,w);i=json_next(j,i))a->aq_waiting++;
    if(!valid_sha256(a->aq_sha)){a->aq_review=false;files_problem(a,code,message,a->aq_back);return;}
    a->aq_known=true;a->aq_review=true;a->page_scroll=0;screen(a,FILE_INFO);
}
static void render_apk_review(App*a){
    heading(a,"App for Android",a->aq_known?NULL:(a->aq_fetch?"Asking GitHub for the newest release...":"Reading the app..."),true);
    if(!a->aq_known){wrapped(a,48,300,624,1,MUTED,"Nothing is written yet.",3);return;}
    char line[512],size[48];human_bytes(a->aq_size,size,sizeof(size));
    rounded(a,(Rect){28,232,664,170},24,PANEL);
    raw_text(true);ellipsis(a,52,256,616,2,TEXT,a->aq_label[0]?a->aq_label:a->aq_name);
    snprintf(line,sizeof(line),"%s%s%s",a->aq_version[0]?a->aq_version:"",a->aq_version[0]?"  ·  ":"",size);ellipsis(a,52,318,616,0,ORANGE,line);
    if(a->aq_label[0])ellipsis(a,52,356,616,0,MUTED,a->aq_name);
    raw_text(false);
    int y=426;
    {bool none=!a->aq_framework[0];snprintf(line,sizeof(line),"%s: %s",tr("Root"),none?tr("not found"):a->aq_framework);raw_text(true);text_tile(a,y,0,TEXT,line,1);raw_text(false);y+=74;}
    if(a->aq_waiting){snprintf(line,sizeof(line),T("Already waiting: %llu"),a->aq_waiting);raw_text(true);text_tile(a,y,0,TEXT,line,1);raw_text(false);y+=74;}
    if(a->aq_fetch)y+=text_tile(a,y,0,MUTED,"Downloaded from its official GitHub release and checked against the SHA-256 GitHub states for it.",3)+16;
    if(a->aq_setup)y+=text_tile(a,y,0,MUTED,"Magisk's files go to /data/adb/magisk from this app, as its own setup puts them, so that Magisk runs the step.",3)+16;
    if(!a->aq_allowed)text_tile(a,y,0,ORANGE,a->aq_reason[0]?a->aq_reason:"The app cannot be queued here.",3);
    else text_tile(a,y,0,MUTED,"The recovery cannot install apps: it queues this one, and Android's package manager installs it after the next start. Open the app once then.",4);
    button(a,(Rect){28,1330,664,108},a->aq_allowed?(a->aq_fetch?"Hold 1 s to download and queue":"Hold 1 s to queue"):"Cannot be queued here",A_APK_CONFIRM,ui_free(a)&&a->aq_allowed,true,a->aq_allowed?1000:0);
}
static bool apk_action(App*a,int id){
    if(id==A_APK_FROM_ZIP&&a->screen==RESULT){
        /* The Magisk ZIP that just ran is the Magisk app too: queued for Android's next start. */
        for(unsigned int n=0;n<a->zip_count;n++)if(a->zip_queue[n].state==1&&!strcmp(a->zip_queue[n].what,"magisk")){zip_item_to_review(a,&a->zip_queue[n]);break;}
        if(strcmp(a->zip_what,"magisk"))return true;
        a->zip_ran=a->zip_reset=false;apk_review_file(a,a->zip_volume,a->zip_token,a->zip_path,ANDROID_MENU);if(a->aq_review)screen(a,FILE_INFO);
        return true;
    }
    if(id==A_APK_FETCH&&a->screen==RESULT&&a->root_app_offer){if(ui_free(a)){a->root_app_offer=false;apk_review_fetch(a,a->root_app[0]?a->root_app:"magisk",ANDROID_MENU);if(a->aq_review)screen(a,FILE_INFO);}return true;}
    if(id>=A_APK_FETCH&&id<A_APK_FETCH+3&&a->screen==ROOT_PAGE){if(ui_free(a)){static const char*const apps[]={"magisk","kernelsu-next","apatch"};apk_review_fetch(a,apps[id-A_APK_FETCH],ROOT_PAGE);if(a->aq_review)screen(a,FILE_INFO);}return true;}
    if(a->screen!=FILE_INFO||!a->aq_review)return false;
    if(id==A_BACK){a->aq_review=a->aq_known=false;enum Screen back=a->aq_back;if(back!=FILE_INFO)screen(a,back);a->dirty=true;return true;}
    if(id==A_APK_CONFIRM){if(a->aq_known&&a->aq_allowed&&!start_apk_job(a,a->aq_fetch?J_APK_FETCH:J_APK_QUEUE))files_problem(a,"APK_QUEUE_UNAVAILABLE","Wait for the current operation to finish.",a->aq_back);return true;}
    return true;
}

static bool file_install_action(App*a,int id){
    if(apk_action(a,id))return true;
    if(a->screen!=FILE_INFO)return false;
    if(a->mi_review){
        if(id==A_BACK){a->mi_review=a->mi_known=false;a->dirty=true;return true;}
        if(id==A_MODULE_INSTALL_CONFIRM){if(a->mi_known&&a->mi_allowed&&!start_module_install_job(a,J_MODULE_INSTALL))files_problem(a,"MODULE_INSTALL_UNAVAILABLE","Wait for the current operation to finish.",FILE_INFO);return true;}
    }
    /* Back from Linux's Continue page returns to the file's actions, not to Systems. */
    if(id==A_BACK&&a->systems_pick_manifest&&a->files_linux_from_file){a->systems_pick_manifest=a->systems_pick_script=a->files_linux_from_file=false;a->dirty=true;return true;}
    if(id==A_BACK&&a->fs_install_sheet){a->fs_install_sheet=false;a->dirty=true;return true;}
    if(id==A_FS_INSTALL){int options[FO_COUNT];if(ui_free(a)&&file_options(a,options)>0){a->fs_install_sheet=true;a->dirty=true;}return true;}
    if(id==A_FS_INSTALL_CLOSE){a->fs_install_sheet=false;a->dirty=true;return true;}
    if(id==A_FS_RUN_SCRIPT){if(ui_free(a))file_run_script(a);return true;}
    if(id<A_FS_OPTION||id>=A_FS_OPTION+FO_COUNT)return false;
    a->fs_install_sheet=false;a->dirty=true;
    if(!ui_free(a)||!current_volume(a)||!file_is_regular(&a->fs_selected)||!a->fs_selected.token[0])return true;
    switch(id-A_FS_OPTION){
    case FO_FLASH:action_run(a,A_FS_FLASH);break;
    case FO_ZIP:a->zip_adding=false;a->android_gsi=a->gsi_file=a->rom_origin=false;zip_chosen(a);break;
    case FO_ROM:a->compat_pick=false;rom_chosen(a);break;
    case FO_COMPAT:a->compat_pick=true;rom_chosen(a);break;
    case FO_SAMSUNG:a->stock_boot_pick=false;samsung_chosen(a);break;
    case FO_STOCK_BOOT:stock_boot_chosen(a);break;
    case FO_LINUX:a->files_linux_pending=true;if(!start_systems_job(a,J_SYS_STATUS)){a->files_linux_pending=false;files_problem(a,"SYSTEMS_UNAVAILABLE","Wait for the current operation to finish.",FILE_INFO);}break;
    case FO_SCRIPT:file_run_script(a);break;
    case FO_MODULE:module_review_start(a);break;
    case FO_APK:{FileVolume*v=current_volume(a);if(v)apk_review_file(a,v->id,v->token,a->fs_selected.path,FILE_INFO);}break;
    }
    return true;
}
