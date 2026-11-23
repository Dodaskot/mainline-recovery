/* SPDX-License-Identifier: MIT
 * Read-only Android compatibility and authenticated root-module recovery.
 * This UI has no preserve-data writer. Backend plans are revalidated on apply.
 */
#ifndef A22X_ANDROID_TOOLS_UI_H
#define A22X_ANDROID_TOOLS_UI_H
static unsigned int module_action_bit(const char*s){
    if(!strcmp(s,"disable"))return 1u;
    if(!strcmp(s,"enable"))return 2u;
    if(!strcmp(s,"remove"))return 4u;
    if(!strcmp(s,"cancel-remove"))return 8u;
    return 0;
}
static const char*module_action_label(const char*s){
    if(!strcmp(s,"disable"))return "Disable module";
    if(!strcmp(s,"enable"))return "Enable module";
    if(!strcmp(s,"remove"))return "Remove on next Android boot";
    if(!strcmp(s,"cancel-remove"))return "Cancel pending removal";
    if(!strcmp(s,"disable-all"))return "Disable all modules";
    return "Module action unavailable";
}
/* P0 admits only the same exact marker adapters as the backend. */
static bool module_id_valid(const char*s){
    size_t n=strlen(s);if(n<2||n>128||!((s[0]>='A'&&s[0]<='Z')||(s[0]>='a'&&s[0]<='z')))return false;
    for(size_t i=1;i<n;i++)if(!((s[i]>='A'&&s[i]<='Z')||(s[i]>='a'&&s[i]<='z')||(s[i]>='0'&&s[i]<='9')||s[i]=='.'||s[i]=='_'||s[i]=='-'))return false;
    return true;
}
/* Unsupported directory names are diagnostic labels, never command arguments. */
static void module_display_label(char*out,size_t size,const char*source){
    copy(out,size,source);for(char*p=out;*p;p++)if((unsigned char)*p<32u||(unsigned char)*p==127u)*p='?';
}
static bool module_status_valid(const char*s){return !strcmp(s,"enabled")||!strcmp(s,"disabled")||!strcmp(s,"remove-pending")||!strcmp(s,"update-pending")||!strcmp(s,"unsupported");}
static bool module_framework_supported(const Json*j,int f){
    if(!jequals(j,f,"status","supported"))return false;
    /* KernelSU Next with the reviewed ksud (android_modules.py KERNELSU_NEXT_33555, 2026-11-22). */
    if(jequals(j,f,"id","kernelsu"))return jequals(j,f,"version","v3.4.2-200-g32e25d58")&&json_uint(j,json_get(j,f,"version_code"),0)==33555&&jequals(j,f,"adapter","kernelsu-next-33555-markers-v1");
    if(!jequals(j,f,"id","magisk"))return false;
    return (jequals(j,f,"version","31.0")&&json_uint(j,json_get(j,f,"version_code"),0)==31000&&jequals(j,f,"adapter","magisk-31.0-markers-v1"))||
           (jequals(j,f,"version","31.1")&&json_uint(j,json_get(j,f,"version_code"),0)==31100&&jequals(j,f,"adapter","magisk-31.1-markers-v1"));
}
static bool module_access_writable(const Json*j,int v){
    return json_bool(j,json_get(j,v,"mounted"),-1)==1&&json_bool(j,json_get(j,v,"authenticated"),-1)==1&&
        json_bool(j,json_get(j,v,"read_only"),-1)==0&&json_bool(j,json_get(j,v,"write_supported"),-1)==1;
}
static bool android_tools_job(int kind){return kind==J_ANDROID_COMPAT||kind==J_MODULE_LIST||kind==J_MODULE_PREVIEW||kind==J_MODULE_APPLY;}
static void module_forget_plan(App*a){a->modules_plan_allowed=false;a->modules_plan_sha[0]=0;a->module_change_count=0;}
static bool start_android_tools_job(App*a,int kind){
    if(a->job.pid||a->preview)return false;
    char*args[24];int n=0;args[n++]=a->python;args[n++]=kind==J_ANDROID_COMPAT?a->compat_helper:a->modules_helper;
    if(!args[1][0])return false;
    if(a->device)args[n++]="--device";else{args[n++]="--fixture";args[n++]=a->fixture;}
    args[n++]=kind==J_ANDROID_COMPAT?"inspect":kind==J_MODULE_LIST?"inventory":kind==J_MODULE_PREVIEW?"preview":"apply";
    if(kind==J_ANDROID_COMPAT){
        if(!a->samsung_volume[0]||!a->samsung_token[0]||!a->samsung_path[0])return false;
        args[n++]="--volume";args[n++]=a->samsung_volume;args[n++]="--volume-token";args[n++]=a->samsung_token;args[n++]="--path";args[n++]=a->samsung_path;
        a->compat_known=false;
    }else if(kind==J_MODULE_PREVIEW||kind==J_MODULE_APPLY){
        if(!module_action_bit(a->modules_action)&&strcmp(a->modules_action,"disable-all"))return false;
        if(strcmp(a->modules_action,"disable-all")?!module_id_valid(a->modules_target):a->modules_target[0]!=0)return false;
        args[n++]="--action";args[n++]=a->modules_action;
        if(a->modules_target[0]){args[n++]="--module-id";args[n++]=a->modules_target;}
        if(kind==J_MODULE_APPLY){
            if(!a->modules_plan_allowed||!valid_sha256(a->modules_plan_sha))return false;
            args[n++]="--expected-plan";args[n++]=a->modules_plan_sha;args[n++]="--confirm";
        }
    }
    args[n]=NULL;if(!launch_job(a,kind,args))return false;
    if(kind==J_MODULE_APPLY){a->modules_plan_allowed=false;a->modules_known=false;}
    a->result_return=kind==J_ANDROID_COMPAT?ANDROID_COMPAT:ANDROID_MODULES;return true;
}
static bool compat_status_valid(const char*s){return !strcmp(s,"supported")||!strcmp(s,"unknown")||!strcmp(s,"incompatible");}
static bool parse_android_compat(App*a,const Json*j){
    a->compat_known=false;a->compat_count=0;a->compat_sha[0]=0;
    if(!jequals(j,0,"schema","a22x.android-compat.v1")||json_bool(j,json_get(j,0,"preserve_allowed"),-1)!=0)return false;
    jstring(j,0,"status",a->compat_status,sizeof(a->compat_status));jstring(j,0,"manifest_sha256",a->compat_sha,sizeof(a->compat_sha));
    int rows=json_get(j,0,"checks"),rollback=json_get(j,0,"rollback");
    if(!compat_status_valid(a->compat_status)||!valid_sha256(a->compat_sha)||rows<0||j->tokens[rows].type!=J_ARRAY||rollback<0||j->tokens[rollback].type!=J_OBJECT)return false;
    jstring(j,rollback,"before_first_boot",a->compat_before_boot,sizeof(a->compat_before_boot));jstring(j,rollback,"after_first_boot",a->compat_after_boot,sizeof(a->compat_after_boot));
    if((strcmp(a->compat_before_boot,"unknown")&&strcmp(a->compat_before_boot,"complete"))||strcmp(a->compat_after_boot,"not_guaranteed"))return false;
    for(int i=rows+1;i<json_next(j,rows);i=json_next(j,i)){
        if(a->compat_count>=ANDROID_COMPAT_CHECKS||j->tokens[i].type!=J_OBJECT)return false;
        AndroidCompatCheck*r=&a->compat_checks[a->compat_count];memset(r,0,sizeof(*r));
        jstring(j,i,"id",r->id,sizeof(r->id));jstring(j,i,"status",r->status,sizeof(r->status));jstring(j,i,"reason",r->reason,sizeof(r->reason));
        if(!r->id[0]||!r->reason[0]||!compat_status_valid(r->status))return false;
        a->compat_count++;
    }
    int source=json_get(j,0,"source"),target=json_get(j,0,"target");
    jstring(j,json_get(j,source,"build"),"id",a->compat_source_build,sizeof(a->compat_source_build));
    jstring(j,json_get(j,target,"build"),"id",a->compat_target_build,sizeof(a->compat_target_build));
    if(!a->compat_count)return false;
    a->compat_known=true;return true;
}
static bool parse_android_modules(App*a,const Json*j){
    a->modules_known=a->modules_can_mutate=false;a->modules_count=0;a->modules_selected=-1;module_forget_plan(a);
    if(!jequals(j,0,"operation","inventory"))return false;
    int framework=json_get(j,0,"framework"),access_=json_get(j,0,"access"),rows=json_get(j,0,"modules");
    if(framework<0||j->tokens[framework].type!=J_OBJECT||access_<0||j->tokens[access_].type!=J_OBJECT||rows<0||j->tokens[rows].type!=J_ARRAY)return false;
    jstring(j,framework,"id",a->modules_framework,sizeof(a->modules_framework));jstring(j,framework,"version",a->modules_version,sizeof(a->modules_version));
    jstring(j,framework,"reason",a->modules_reason,sizeof(a->modules_reason));jstring(j,framework,"adapter",a->modules_adapter,sizeof(a->modules_adapter));
    jstring(j,access_,"volume_token",a->modules_volume_token,sizeof(a->modules_volume_token));
    if(!a->modules_framework[0])return false;
    a->modules_mounted=json_bool(j,json_get(j,access_,"mounted"),0)==1;
    a->modules_authenticated=json_bool(j,json_get(j,access_,"authenticated"),0)==1;
    a->modules_rw=json_bool(j,json_get(j,access_,"read_only"),-1)==0&&json_bool(j,json_get(j,access_,"write_supported"),0)==1;
    bool can_mutate=module_framework_supported(j,framework)&&module_access_writable(j,access_)&&valid_sha256(a->modules_volume_token)&&json_bool(j,json_get(j,0,"can_mutate"),0)==1;
    for(int i=rows+1;i<json_next(j,rows);i=json_next(j,i)){
        if(a->modules_count>=ANDROID_MODULES_MAX||j->tokens[i].type!=J_OBJECT)return false;
        AndroidModule*r=&a->modules[a->modules_count];memset(r,0,sizeof(*r));
        jstring(j,i,"id",r->id,sizeof(r->id));jstring(j,i,"name",r->name,sizeof(r->name));jstring(j,i,"version",r->version,sizeof(r->version));jstring(j,i,"status",r->status,sizeof(r->status));jstring(j,i,"reason",r->reason,sizeof(r->reason));
        bool unsupported=!strcmp(r->status,"unsupported");
        if(!r->id[0]||!module_status_valid(r->status)||(!module_id_valid(r->id)&&!unsupported))return false;
        for(unsigned int k=0;k<a->modules_count;k++)if(!strcmp(a->modules[k].id,r->id))return false;
        int disabled=json_bool(j,json_get(j,i,"disabled"),-1),removing=json_bool(j,json_get(j,i,"remove_pending"),-1),pending=json_bool(j,json_get(j,i,"pending_update"),-1);
        if(disabled<0||removing<0||pending<0)return false;
        r->disabled=disabled==1;r->remove_pending=removing==1;r->pending_update=pending==1;
        int actions=json_get(j,i,"actions");if(actions<0||j->tokens[actions].type!=J_ARRAY)return false;
        for(int k=actions+1;k<json_next(j,actions);k=json_next(j,k)){char value[32]={0};if(json_string(j,k,value,sizeof(value))<=0||!module_action_bit(value))return false;r->actions|=module_action_bit(value);}
        /* A malformed module must remain visible without hiding valid neighbours.
         * Even a helper that advertises actions for that row is refused. */
        if(unsupported&&r->actions)return false;
        if(!can_mutate||unsupported)r->actions=0;
        a->modules_count++;
    }
    a->modules_can_mutate=can_mutate;a->modules_known=true;return true;
}
static bool parse_android_module_plan(App*a,const Json*j){
    module_forget_plan(a);a->modules_plan_reason[0]=0;
    if(!jequals(j,0,"operation","preview"))return false;
    int p=json_get(j,0,"plan");if(p<0||j->tokens[p].type!=J_OBJECT||!jequals(j,p,"schema","a22x.android-modules.plan.v1"))return false;
    char action_[24]={0},target[129]={0};jstring(j,p,"action",action_,sizeof(action_));jstring(j,p,"module_id",target,sizeof(target));
    if(strcmp(action_,a->modules_action)||strcmp(target,a->modules_target)||(!module_action_bit(action_)&&strcmp(action_,"disable-all"))||(target[0]&&!module_id_valid(target)))return false;
    jstring(j,p,"plan_sha256",a->modules_plan_sha,sizeof(a->modules_plan_sha));jstring(j,p,"reason",a->modules_plan_reason,sizeof(a->modules_plan_reason));
    int allowed=json_bool(j,json_get(j,p,"allowed"),-1),rows=json_get(j,p,"changes");
    if(allowed<0||!valid_sha256(a->modules_plan_sha)||rows<0||j->tokens[rows].type!=J_ARRAY)return false;
    int framework=json_get(j,p,"framework"),access_=json_get(j,p,"access");
    if(framework<0||j->tokens[framework].type!=J_OBJECT||access_<0||j->tokens[access_].type!=J_OBJECT)return false;
    bool same_framework=module_framework_supported(j,framework)&&jequals(j,framework,"id",a->modules_framework)&&jequals(j,framework,"version",a->modules_version)&&jequals(j,framework,"adapter",a->modules_adapter);
    char token[72]={0};jstring(j,access_,"volume_token",token,sizeof(token));
    if(allowed==1&&(!same_framework||!valid_sha256(token)||strcmp(token,a->modules_volume_token)))return false;
    bool writable=module_access_writable(j,access_);
    const char*marker=(!strcmp(action_,"remove")||!strcmp(action_,"cancel-remove"))?"remove":"disable";
    bool desired=strcmp(action_,"enable")&&strcmp(action_,"cancel-remove");
    for(int i=rows+1;i<json_next(j,rows);i=json_next(j,i)){
        if(a->module_change_count>=ANDROID_MODULE_CHANGES||j->tokens[i].type!=J_OBJECT)return false;
        AndroidModuleChange*r=&a->module_changes[a->module_change_count];memset(r,0,sizeof(*r));
        jstring(j,i,"id",r->id,sizeof(r->id));jstring(j,i,"path",r->path,sizeof(r->path));jstring(j,i,"marker",r->marker,sizeof(r->marker));
        int before=json_bool(j,json_get(j,i,"before"),-1),after=json_bool(j,json_get(j,i,"after"),-1);
        if(!module_id_valid(r->id)||before<0||after<0||before==after||strcmp(r->marker,marker)||(after==1)!=desired)return false;
        if(a->modules_target[0]&&strcmp(r->id,a->modules_target))return false;
        char active[256],pending[256];snprintf(active,sizeof(active),"/adb/modules/%s",r->id);snprintf(pending,sizeof(pending),"/adb/modules_update/%s",r->id);
        if(strcmp(r->path,active)&&strcmp(r->path,pending))return false;
        for(unsigned int k=0;k<a->module_change_count;k++)if(!strcmp(a->module_changes[k].path,r->path)&&!strcmp(a->module_changes[k].marker,r->marker))return false;
        bool listed=false;for(unsigned int k=0;k<a->modules_count;k++)if(!strcmp(a->modules[k].id,r->id)){listed=true;break;}
        if(!listed)return false;
        r->before=before==1;r->after=after==1;a->module_change_count++;
    }
    if(allowed==1&&!a->module_change_count)copy(a->modules_plan_reason,sizeof(a->modules_plan_reason),T("The modules already have the requested state."));
    if(allowed==1&&!writable)copy(a->modules_plan_reason,sizeof(a->modules_plan_reason),T("Android data is read-only. Reopen it with write access before changing module state."));
    a->modules_plan_allowed=allowed==1&&a->module_change_count>0&&a->modules_can_mutate&&writable;
    return true;
}
static void complete_android_tools_job(App*a,const Json*j,int kind,bool ok){
    if(kind==J_MODULE_PREVIEW&&a->job_orphan){module_forget_plan(a);return;}
    bool parsed=ok&&j;
    if(parsed&&kind==J_ANDROID_COMPAT)parsed=parse_android_compat(a,j);
    else if(parsed&&kind==J_MODULE_LIST)parsed=parse_android_modules(a,j);
    else if(parsed&&kind==J_MODULE_PREVIEW)parsed=parse_android_module_plan(a,j);
    else if(parsed&&kind==J_MODULE_APPLY)parsed=jequals(j,0,"operation","apply")&&jequals(j,0,"status","applied")&&jequals(j,0,"plan_sha256",a->modules_plan_sha)&&json_uint(j,json_get(j,0,"changed"),UINT64_MAX)==a->module_change_count&&jequals(j,json_get(j,0,"journal"),"status","applied");
    if(!parsed){
        char code[96]="ANDROID_TOOLS_RESULT_INVALID",message[512]="The helper returned an incomplete result. Refresh before continuing.";
        if(j){int e=json_get(j,0,"error");if(e>=0){jstring(j,e,"code",code,sizeof(code));jstring(j,e,"message",message,sizeof(message));}}
        if(kind==J_ANDROID_COMPAT)a->compat_known=false;else{a->modules_known=a->modules_can_mutate=false;module_forget_plan(a);}
        files_problem(a,code,message,kind==J_ANDROID_COMPAT?ANDROID_COMPAT:ANDROID_MODULES);return;
    }
    a->page_scroll=0;
    if(kind==J_ANDROID_COMPAT){screen(a,ANDROID_COMPAT);return;}
    if(kind==J_MODULE_PREVIEW){screen(a,ANDROID_MODULE_CONFIRM);return;}
    if(kind==J_MODULE_APPLY){
        module_forget_plan(a);a->modules_known=false;screen(a,ANDROID_MODULES);toast(a,T("Module state saved. Refreshing the list."));
        (void)start_android_tools_job(a,J_MODULE_LIST);return;
    }
    screen(a,ANDROID_MODULES);
}
static const char*compat_state_label(const char*s){return !strcmp(s,"supported")?"Verified check":!strcmp(s,"incompatible")?"Incompatible":"Needs verification";}
static uint32_t compat_state_color(const char*s){return !strcmp(s,"supported")?GREEN:!strcmp(s,"incompatible")?RED:ORANGE;}
static int android_tools_page_begin(App*a){a->page_scroll=(int64_t)scroll_clamp((double)a->page_scroll,(double)page_max_scroll(a));a->clip_active=true;a->clip=page_viewport(a);return 236-(int)a->page_scroll;}
static void android_tools_page_end(App*a,int y){a->page_content=y+a->page_scroll-230+16;a->clip_active=false;scroll_indicator(a,(Rect){698,230,5,page_height(a)},a->page_scroll,a->page_content,ORANGE);}
static void render_android_compat(App*a){
    heading(a,"Data preservation report","Read-only package analysis",true);int y=android_tools_page_begin(a);
    if(a->samsung_path[0]){raw_text(true);y+=text_tile(a,y,0,TEXT,a->samsung_path,4)+16;raw_text(false);}
    y+=text_tile(a,y,0,ORANGE,"This report does not install Android. A qualified pair of builds is required before an update can preserve data.",5)+16;
    if(!a->compat_known)y+=text_tile(a,y,0,MUTED,a->job.pid?"Reading compatibility checks...":"No verified report is available. Refresh or choose another package.",4)+16;
    else{
        y+=text_tile(a,y,1,compat_state_color(a->compat_status),compat_state_label(a->compat_status),2)+16;
        char builds[512];snprintf(builds,sizeof(builds),"%s: %s\n%s: %s",T("Current build"),a->compat_source_build[0]?a->compat_source_build:T("Not identified"),T("Target build"),a->compat_target_build[0]?a->compat_target_build:T("Not identified"));
        raw_text(true);y+=text_tile(a,y,0,TEXT,builds,6)+16;raw_text(false);
        y+=text_tile(a,y,0,MUTED,!strcmp(a->compat_before_boot,"complete")?"System-image rollback coverage before the first Android boot is complete.":"Complete system-image rollback before the first Android boot has not been verified.",5)+16;
        y+=text_tile(a,y,0,ORANGE,"After Android first boots, restoring old images may not restore migrated data or hardware-backed keys.",5)+16;
        for(unsigned int n=0;n<a->compat_count;n++){
            AndroidCompatCheck*r=&a->compat_checks[n];y+=text_tile(a,y,0,compat_state_color(r->status),compat_state_label(r->status),2)+8;
            raw_text(true);y+=text_tile(a,y,0,MUTED,r->id,2)+8;y+=text_tile(a,y,0,TEXT,r->reason,9)+16;raw_text(false);
        }
    }
    android_tools_page_end(a,y);
    button(a,(Rect){28,1320,664,104},"Refresh report",A_COMPAT_REFRESH,ui_free(a)&&!a->job.pid&&a->samsung_path[0],false,0);
}
static void render_android_modules(App*a){
    heading(a,"Android modules","Recover module state before starting Android",true);int y=android_tools_page_begin(a);
    if(!a->modules_known)y+=text_tile(a,y,0,MUTED,a->job.pid?"Reading Android modules...":"Refresh to read the current module state.",4)+16;
    else{
        const char*shown=!strcmp(a->modules_framework,"kernelsu")?"KernelSU Next":!strcmp(a->modules_framework,"magisk")?"Magisk":a->modules_framework;
        char title[160];snprintf(title,sizeof(title),"%s%s%s",shown,a->modules_version[0]?"  /  ":"",a->modules_version);raw_text(true);y+=text_tile(a,y,1,TEXT,title,3)+16;raw_text(false);
        if(!a->modules_mounted||!a->modules_authenticated)y+=text_tile(a,y,0,ORANGE,"Open Android data and authenticate with its password. Use read and write access to change modules.",5)+16;
        else if(!a->modules_rw)y+=text_tile(a,y,0,ORANGE,"Android data is read-only. Reopen it with write access before changing module state.",4)+16;
        if(a->modules_reason[0]){raw_text(true);y+=text_tile(a,y,0,MUTED,a->modules_reason,8)+16;raw_text(false);}
        if(!a->modules_can_mutate)y+=text_tile(a,y,0,ORANGE,"Module changes are unavailable for this current state or framework version.",4)+16;
        if(!a->modules_count&&a->modules_authenticated)y+=text_tile(a,y,0,MUTED,"No modules were reported.",2)+16;
        for(unsigned int n=0;n<a->modules_count;n++){
            AndroidModule*r=&a->modules[n];char note[320],label[256],version[256];
            module_display_label(label,sizeof(label),r->name[0]?r->name:r->id);module_display_label(version,sizeof(version),r->version[0]?r->version:r->id);
            snprintf(note,sizeof(note),"%s  /  %s",version,r->status);
            raw_text(true);installer_card(a,(Rect){28,y,664,140},r->disabled?1:4,ICON_TUNE,label,note,A_MODULE_ITEM+(int)n,ui_free(a)&&!a->job.pid);raw_text(false);y+=152;
        }
        button(a,(Rect){28,y,664,84},"Disable all modules",A_MODULE_DISABLE_ALL,ui_free(a)&&!a->job.pid&&a->modules_can_mutate&&a->modules_count,false,0);y+=100;
    }
    button(a,(Rect){28,y,664,84},"Open Android data",A_MODULE_DATA,ui_free(a)&&!a->job.pid,false,0);y+=100;
    android_tools_page_end(a,y);
    button(a,(Rect){28,1320,664,104},"Refresh modules",A_MODULE_REFRESH,ui_free(a)&&!a->job.pid,false,0);
}
static void render_android_module_detail(App*a){
    if(a->modules_selected<0||(unsigned int)a->modules_selected>=a->modules_count){heading(a,"Android modules","Refresh to read the current module state.",true);return;}
    AndroidModule*r=&a->modules[a->modules_selected];char label[256],ident[256];module_display_label(label,sizeof(label),r->name[0]?r->name:r->id);module_display_label(ident,sizeof(ident),r->id);
    raw_text(true);heading(a,label,ident,true);raw_text(false);int y=android_tools_page_begin(a);
    char detail[240];snprintf(detail,sizeof(detail),"%s  /  %s",r->version,r->status);raw_text(true);y+=text_tile(a,y,1,TEXT,detail,3)+16;
    if(r->reason[0])y+=text_tile(a,y,0,ORANGE,r->reason,8)+16;
    raw_text(false);
    y+=text_tile(a,y,0,MUTED,"Disabling a module does not undo changes it already made. Removal is completed by its framework on the next Android boot.",5)+16;
    const char*actions[]={"disable","enable","remove","cancel-remove"};int ids[]={A_MODULE_DISABLE,A_MODULE_ENABLE,A_MODULE_REMOVE,A_MODULE_CANCEL_REMOVE};
    for(unsigned int n=0;n<4;n++){button(a,(Rect){28,y,664,90},module_action_label(actions[n]),ids[n],ui_free(a)&&!a->job.pid&&a->modules_can_mutate&&module_id_valid(r->id)&&(r->actions&module_action_bit(actions[n])),false,0);y+=106;}
    android_tools_page_end(a,y);
}
static void render_android_module_confirm(App*a){
    heading(a,"Review module change",module_action_label(a->modules_action),true);int y=android_tools_page_begin(a);
    raw_text(true);y+=text_tile(a,y,1,TEXT,a->modules_target[0]?a->modules_target:T("All modules"),3)+16;raw_text(false);
    y+=text_tile(a,y,0,ORANGE,!strcmp(a->modules_action,"remove")?"Android removes the module on its next boot. Its uninstall script is not run in recovery.":"The reviewed module markers will be changed. Android applies module state on its next boot.",5)+16;
    if(a->modules_plan_reason[0]){raw_text(true);y+=text_tile(a,y,0,ORANGE,a->modules_plan_reason,9)+16;raw_text(false);}
    for(unsigned int n=0;n<a->module_change_count;n++){
        AndroidModuleChange*r=&a->module_changes[n];char line[432];snprintf(line,sizeof(line),"%s\n%s: %s -> %s",r->path,r->marker,tr(r->before?"present":"absent"),tr(r->after?"present":"absent"));
        raw_text(true);y+=text_tile(a,y,0,TEXT,line,6)+16;raw_text(false);
    }
    android_tools_page_end(a,y);
    button(a,(Rect){28,1320,664,104},"Hold 1 second to apply",A_MODULE_APPLY,ui_free(a)&&!a->job.pid&&a->modules_plan_allowed&&valid_sha256(a->modules_plan_sha),true,2000);
}
static bool android_tools_action(App*a,int id){
    if(id==A_MODULES&&a->screen==ANDROID_MENU){if(!a->job.pid){a->modules_known=false;a->page_scroll=0;screen(a,ANDROID_MODULES);(void)start_android_tools_job(a,J_MODULE_LIST);}return true;}
    if(id==A_ANDROID_COMPAT&&a->screen==ANDROID_MENU){
        if(a->job.pid)return true;
        a->compat_pick=true;a->compat_known=false;a->android_gsi=a->gsi_file=a->rom_origin=false;
        a->samsung_pick=a->stock_boot_pick=a->zip_pick=a->flash_restore=false;a->flash_pick=a->rom_pick=true;source_open(a);return true;
    }
    if(a->compat_pick&&(id==A_SOURCE_CANCEL||id==A_FLASH_CANCEL_PICK||(a->source_sheet&&id==A_BACK))){
        /* Closing a sheet keeps ANDROID_MENU underneath: the normal page-change
         * orphan detector cannot see this cancellation. Drop its late read. */
        if(a->source_sheet&&a->job.pid&&a->job.kind==J_FS_INVENTORY)a->job_orphan=true;
        a->compat_pick=false;
    }
    if(id==A_COMPAT_REFRESH&&a->screen==ANDROID_COMPAT){if(!a->job.pid)(void)start_android_tools_job(a,J_ANDROID_COMPAT);return true;}
    if(id==A_BACK&&a->screen==ANDROID_COMPAT){a->compat_pick=false;screen(a,ANDROID_MENU);return true;}
    if(id==A_BACK&&a->screen==ANDROID_MODULE_CONFIRM){module_forget_plan(a);a->page_scroll=0;screen(a,a->modules_target[0]?ANDROID_MODULE_DETAIL:ANDROID_MODULES);return true;}
    if(id==A_BACK&&a->screen==ANDROID_MODULE_DETAIL){a->page_scroll=0;screen(a,ANDROID_MODULES);return true;}
    if(id==A_BACK&&a->screen==ANDROID_MODULES){screen(a,ANDROID_MENU);return true;}
    if(a->modules_data_route&&id==A_BACK&&a->screen==FILE_VOLUME){a->modules_data_route=a->modules_data_open=false;reopen(a,ANDROID_MODULES);return true;}
    if(id==A_MODULE_REFRESH&&a->screen==ANDROID_MODULES){if(!a->job.pid){a->modules_known=false;(void)start_android_tools_job(a,J_MODULE_LIST);}return true;}
    if(id==A_MODULE_DATA&&a->screen==ANDROID_MODULES){
        if(a->job.pid)return true;
        module_forget_plan(a);a->modules_data_route=a->modules_data_open=true;a->fs_inventory_destination=FILE_VOLUME;
        a->flash_pick=a->rom_pick=a->compat_pick=false;a->source_sheet=false;screen(a,FILE_VOLUME);
        if(!start_files_job(a,J_FS_INVENTORY)){a->modules_data_route=a->modules_data_open=false;screen(a,ANDROID_MODULES);}return true;
    }
    if(id>=A_MODULE_ITEM&&id<A_MODULE_ITEM+(int)ANDROID_MODULES_MAX&&a->screen==ANDROID_MODULES){
        unsigned int n=(unsigned int)(id-A_MODULE_ITEM);if(!a->job.pid&&a->modules_known&&n<a->modules_count){module_forget_plan(a);a->modules_selected=(int)n;a->page_scroll=0;screen(a,ANDROID_MODULE_DETAIL);}return true;
    }
    if(id==A_MODULE_APPLY&&a->screen==ANDROID_MODULE_CONFIRM){if(!a->job.pid&&!start_android_tools_job(a,J_MODULE_APPLY))module_forget_plan(a);return true;}
    const char*action_=id==A_MODULE_DISABLE?"disable":id==A_MODULE_ENABLE?"enable":id==A_MODULE_REMOVE?"remove":id==A_MODULE_CANCEL_REMOVE?"cancel-remove":id==A_MODULE_DISABLE_ALL?"disable-all":NULL;
    if(action_&&(a->screen==ANDROID_MODULE_DETAIL||a->screen==ANDROID_MODULES)){
        if(a->job.pid||!a->modules_known||!a->modules_can_mutate)return true;
        if(!strcmp(action_,"disable-all")){if(a->screen!=ANDROID_MODULES)return true;a->modules_target[0]=0;}
        else{if(a->screen!=ANDROID_MODULE_DETAIL||a->modules_selected<0||(unsigned int)a->modules_selected>=a->modules_count)return true;AndroidModule*r=&a->modules[a->modules_selected];if(!module_id_valid(r->id)||!(r->actions&module_action_bit(action_)))return true;copy(a->modules_target,sizeof(a->modules_target),r->id);}
        module_forget_plan(a);copy(a->modules_action,sizeof(a->modules_action),action_);
        if(!start_android_tools_job(a,J_MODULE_PREVIEW))files_problem(a,"MODULE_PREVIEW_UNAVAILABLE",T("The module change could not be reviewed."),ANDROID_MODULES);
        return true;
    }
    return false;
}
/* Synthetic previews are never evidence of an installed framework or physical write. */
static bool android_tools_preview(App*a,const char*name){
    if(!strcmp(name,"android-compat")){
        a->screen=ANDROID_COMPAT;a->compat_known=true;copy(a->compat_status,sizeof(a->compat_status),"unknown");copy(a->compat_before_boot,sizeof(a->compat_before_boot),"unknown");copy(a->compat_after_boot,sizeof(a->compat_after_boot),"not_guaranteed");a->compat_count=3;
        const char*ids[]={"TARGET_PROFILE_UNKNOWN","ROLLBACK_COPY_MISSING","TRANSITION_NOT_QUALIFIED"};const char*reasons[]={"The target build has no qualified recovery decrypt profile.","The system image exceeds the automatic 64 MiB rollback limit. A complete previous image set is required.","This pair of Android builds has not passed hardware qualification."};
        for(unsigned int n=0;n<3;n++){copy(a->compat_checks[n].id,sizeof(a->compat_checks[n].id),ids[n]);copy(a->compat_checks[n].status,sizeof(a->compat_checks[n].status),"unknown");copy(a->compat_checks[n].reason,sizeof(a->compat_checks[n].reason),reasons[n]);}return true;
    }
    if(strcmp(name,"android-modules")&&strcmp(name,"android-modules-locked")&&strcmp(name,"android-module-confirm"))return false;
    a->screen=ANDROID_MODULES;a->modules_known=true;copy(a->modules_framework,sizeof(a->modules_framework),!strcmp(name,"android-modules-locked")?"unknown":"magisk");copy(a->modules_reason,sizeof(a->modules_reason),"Synthetic preview: this is not a phone capture.");
    if(!strcmp(name,"android-modules-locked"))return true;
    a->modules_mounted=a->modules_authenticated=a->modules_rw=a->modules_can_mutate=true;copy(a->modules_version,sizeof(a->modules_version),"31.0");copy(a->modules_adapter,sizeof(a->modules_adapter),"synthetic-preview");a->modules_count=2;
    for(unsigned int n=0;n<2;n++){AndroidModule*r=&a->modules[n];snprintf(r->id,sizeof(r->id),"example_module_%u",n+1);snprintf(r->name,sizeof(r->name),"Example module %u (synthetic)",n+1);copy(r->version,sizeof(r->version),"1.0");copy(r->status,sizeof(r->status),n?"disabled":"enabled");r->disabled=n!=0;r->actions=n?2|4:1|4;}
    if(!strcmp(name,"android-module-confirm")){a->screen=ANDROID_MODULE_CONFIRM;a->modules_selected=0;copy(a->modules_target,sizeof(a->modules_target),a->modules[0].id);copy(a->modules_action,sizeof(a->modules_action),"disable");a->modules_plan_allowed=true;memset(a->modules_plan_sha,'a',64);a->modules_plan_sha[64]=0;a->module_change_count=1;AndroidModuleChange*r=&a->module_changes[0];copy(r->id,sizeof(r->id),a->modules_target);copy(r->path,sizeof(r->path),"/adb/modules/example_module_1");copy(r->marker,sizeof(r->marker),"disable");r->after=true;}
    return true;
}
#endif
