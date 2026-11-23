/* SPDX-License-Identifier: MIT
 * Password-gated userdata formatting. Authentication never formats; the last
 * hold consumes a short-lived backend grant bound to this exact target.
 */
#ifndef A22X_ANDROID_FORMAT_UI_H
#define A22X_ANDROID_FORMAT_UI_H
static bool android_authentication_id(const char*value){
    if(strlen(value)!=32)return false;
    for(const char*p=value;*p;p++)if(!((*p>='0'&&*p<='9')||(*p>='a'&&*p<='f')))return false;
    return true;
}
static bool android_format_session_baseline(const FileVolume*v){
    if(!v->session_reusable)return true;
    if(!v->auth_generation)return !v->mounted&&!v->authentication_id[0];
    return android_authentication_id(v->authentication_id);
}
static bool android_positive_generation(const Json*j,int object,const char*key,uint64_t*out){
    int token=json_get(j,object,key);if(token<0||j->tokens[token].type!=J_PRIMITIVE)return false;
    int first=j->tokens[token].start,last=j->tokens[token].end;
    if(first>=last||j->text[first]<'1'||j->text[first]>'9')return false;
    for(int n=first;n<last;n++)if(j->text[n]<'0'||j->text[n]>'9')return false;
    *out=json_uint(j,token,UINT64_MAX);return *out>0&&*out<UINT64_MAX;
}
static bool android_epoch_verified(const Json*j,int volume,bool reusable_expected,uint64_t auth_before,uint64_t mount_before,const char*id_before){
    bool reusable=json_bool(j,json_get(j,volume,"session_reusable"),0)==1;
    bool top_reusable=json_bool(j,json_get(j,0,"session_reusable"),0)==1;
    if(!reusable_expected&&!reusable&&!top_reusable)return true;
    if(!reusable||!top_reusable)return false;
    char top[40]={0},mounted[40]={0};jstring(j,0,"authentication_id",top,sizeof(top));jstring(j,volume,"authentication_id",mounted,sizeof(mounted));
    uint64_t auth=0,mount=0,volume_auth=0,volume_mount=0;
    return android_authentication_id(top)&&!strcmp(top,mounted)&&
        (!android_authentication_id(id_before)||strcmp(top,id_before))&&
        android_positive_generation(j,0,"auth_generation",&auth)&&android_positive_generation(j,volume,"auth_generation",&volume_auth)&&
        android_positive_generation(j,0,"mount_generation",&mount)&&android_positive_generation(j,volume,"mount_generation",&volume_mount)&&
        auth==volume_auth&&mount==volume_mount&&auth>auth_before&&mount>mount_before;
}
static bool android_format_epoch_verified(const App*a,const Json*j,int volume){
    return android_epoch_verified(j,volume,a->android_format_reusable,a->android_format_auth_before,a->android_format_mount_before,a->android_format_authentication_before);
}
static bool android_format_ready(const App*a){
    return a->android_format_stage==AF_REVIEW&&a->android_format_deadline>milliseconds()&&
        (a->android_format_unprotected||valid_sha256(a->android_format_grant));
}
static void android_format_abandon(App*a){
    if(a->android_format_stage==AF_EXECUTING)return;
    if(a->android_format_grant[0])copy(a->android_format_cancel_grant,sizeof(a->android_format_cancel_grant),a->android_format_grant);
    memset(a->android_format_grant,0,sizeof(a->android_format_grant));memset(a->android_format_request.authorization,0,sizeof(a->android_format_request.authorization));
    memset(a->fs_pending.authorization,0,sizeof(a->fs_pending.authorization));
    a->android_format_stage=AF_IDLE;a->android_format_deadline=0;a->android_format_unprotected=false;a->android_format_abandoned=true;
    a->android_format_reusable=false;a->android_format_auth_before=a->android_format_mount_before=0;a->android_format_authentication_before[0]=0;
}
static void android_format_finish(App*a){
    memset(a->android_format_run_id,0,sizeof(a->android_format_run_id));
    memset(a->android_format_grant,0,sizeof(a->android_format_grant));
    memset(a->android_format_request.authorization,0,sizeof(a->android_format_request.authorization));
    memset(a->fs_pending.authorization,0,sizeof(a->fs_pending.authorization));
    a->android_format_stage=AF_IDLE;a->android_format_deadline=0;a->android_format_unprotected=false;
    a->android_format_reusable=false;a->android_format_auth_before=a->android_format_mount_before=0;a->android_format_authentication_before[0]=0;
}
static void android_format_on_screen(App*a,enum Screen s){
    if(!a->android_format_stage||a->android_format_stage==AF_EXECUTING||s==a->screen)return;
    bool review=a->android_format_stage==AF_REVIEW;
    bool allowed=review?(s==FILE_CONFIRM||(!strcmp(a->android_format_request.purpose,"android-reset")&&s==WIPE_REVIEW)):
        (s==PROGRESS||s==FILE_PROMPT||s==FILE_VOLUME||s==WIPE_VOLUME);
    if(!allowed){if(a->android_format_stage==AF_PREPARING)a->android_prepare_abandoned=true;android_format_abandon(a);}
}
static void android_format_review(App*a){
    a->android_format_stage=AF_REVIEW;
    if(!strcmp(a->android_format_request.purpose,"android-reset")){a->wipe_android=true;screen(a,WIPE_REVIEW);}
    else confirm_file_request(a,a->android_format_request,a->android_format_from);
}
static void android_format_block(App*a,const char*code,const char*message){
    enum Screen back=a->android_format_from;
    android_format_abandon(a);
    files_problem(a,code,message,back);
}
static void android_format_continue(App*a){
    if(a->android_format_stage!=AF_INVENTORY)return;
    FileVolume*v=NULL;
    for(int n=0;n<a->volume_count;n++)if(!strcmp(a->volumes[n].id,"userdata")){a->volume_index=n;copy(a->volume_id,sizeof(a->volume_id),"userdata");v=&a->volumes[n];break;}
    if(!v||!valid_sha256(v->token)){android_format_block(a,"FORMAT_VOLUME_UNAVAILABLE",T("Data is unavailable. Refresh the volume list."));return;}
    copy(a->android_format_request.volume,sizeof(a->android_format_request.volume),"userdata");
    copy(a->android_format_request.volume_token,sizeof(a->android_format_request.volume_token),valid_sha256(v->physical_token)?v->physical_token:v->token);
    if(!strcmp(v->format_auth_state,"not_required")){
        if(v->mounted){android_format_block(a,"FORMAT_VOLUME_MOUNTED",T("Data is mounted. Unmount it in Files before formatting."));return;}
        a->android_format_unprotected=true;a->android_format_deadline=milliseconds()+120000;
        android_format_review(a);return;
    }
    if(!strcmp(v->format_auth_state,"unavailable")||!strcmp(v->credential_type,"none")||!strcmp(v->credential_type,"pattern")){
        android_format_block(a,"FORMAT_AUTH_UNAVAILABLE",T("The protection of this data could not be verified. Formatting is blocked."));return;
    }
    if((v->mounted&&!v->session_reusable)||!strcmp(v->format_auth_state,"restart_required")||!strcmp(v->decrypt_state,"reboot_required")){
        android_format_block(a,"FORMAT_RESTART_REQUIRED",T("Formatting needs a fresh password check. Unmount data, restart recovery, and open formatting again."));return;
    }
    if(strcmp(v->format_auth_state,"required")||!v->decrypt_supported||v->android_user_id!=0){
        android_format_block(a,"FORMAT_AUTH_UNAVAILABLE",T("The protection of this data could not be verified. Formatting is blocked."));return;
    }
    if(!android_format_session_baseline(v)){
        android_format_block(a,"FORMAT_AUTH_NOT_VERIFIED",T("Password verification was not confirmed. No data was formatted."));return;
    }
    FileRequest q=a->android_format_request;q.kind=J_ANDROID_FORMAT_AUTH;copy(q.volume_token,sizeof(q.volume_token),v->token);
    a->android_mount_request=q;
    if(v->preparation_required&&!strcmp(v->credential_type,"unknown")&&!strcmp(v->decrypt_state,"locked")){
        FileRequest prep=q;prep.kind=J_ANDROID_PREPARE;a->android_format_stage=AF_PREPARING;a->android_prepare_abandoned=false;
        if(!start_files_request(a,&prep))android_format_block(a,"FORMAT_PREPARE_UNAVAILABLE","Could not start the password check. Refresh the volume state.");
        return;
    }
    bool live_reusable=v->session_reusable&&v->session_retained&&
        ((!strcmp(v->decrypt_state,"mounted")&&v->mounted)||android_volume_retained(v));
    if(!v->preparation_required&&(!strcmp(v->decrypt_state,"awaiting_credential")||live_reusable)&&!strcmp(v->credential_type,"password")){
        if(!v->decrypt_run_id[0]){android_format_block(a,"FORMAT_AUTH_NOT_VERIFIED",T("Password verification was not confirmed. No data was formatted."));return;}
        copy(a->android_format_run_id,sizeof(a->android_format_run_id),v->decrypt_run_id);
        a->android_format_reusable=v->session_reusable;a->android_format_auth_before=v->auth_generation;a->android_format_mount_before=v->mount_generation;copy(a->android_format_authentication_before,sizeof(a->android_format_authentication_before),v->authentication_id);
        a->android_format_stage=AF_AUTHENTICATING;copy(a->android_pending_token,sizeof(a->android_pending_token),v->token);a->android_pending=true;
        if(!android_unlock_begin(a,&q))android_format_block(a,"FORMAT_AUTH_UNAVAILABLE","Could not open the Android password prompt.");
        return;
    }
    android_format_block(a,"FORMAT_CREDENTIAL_UNSUPPORTED",T("Formatting requires a supported current Android password or PIN."));
}
static bool android_format_start(App*a,const char*fs,bool reset,enum Screen from){
    if(a->job.pid||a->preview||a->android_cancel_requested||a->android_format_cancel_grant[0])return false;
    if(strcmp(fs,"ext4")&&strcmp(fs,"f2fs"))return false;
    android_format_finish(a);a->android_format_abandoned=false;a->android_format_from=from;
    a->android_format_request=(FileRequest){.kind=J_FS_FORMAT};copy(a->android_format_request.volume,sizeof(a->android_format_request.volume),"userdata");
    copy(a->android_format_request.mode,sizeof(a->android_format_request.mode),fs);
    copy(a->android_format_request.purpose,sizeof(a->android_format_request.purpose),reset?"android-reset":"format");
    a->android_format_stage=AF_INVENTORY;
    a->fs_inventory_destination=from==WIPE_VOLUME?WIPE_VOLUME:FILE_VOLUME;
    screen(a,a->fs_inventory_destination);
    if(!start_files_job(a,J_FS_INVENTORY)){android_format_finish(a);return false;}
    return true;
}
static int complete_android_format_auth(App*a,const Json*j){
    a->android_auth_started=false;a->android_pending=false;a->android_cancel_requested=false;a->android_pending_token[0]=0;
    char grant[80]={0},purpose[24]={0},fs[16]={0},physical[256]={0};
    jstring(j,0,"format_authorization",grant,sizeof(grant));jstring(j,0,"format_purpose",purpose,sizeof(purpose));jstring(j,0,"format_fs",fs,sizeof(fs));jstring(j,0,"format_volume_token",physical,sizeof(physical));
    int v=json_get(j,0,"volume");uint64_t expiry=json_uint(j,json_get(j,0,"expires_in_seconds"),0);
    char run[80]={0},mounted_run[80]={0},mounted_physical[256]={0},mounted_token[256]={0};
    jstring(j,0,"authentication_run_id",run,sizeof(run));jstring(j,v,"decrypt_run_id",mounted_run,sizeof(mounted_run));jstring(j,v,"physical_volume_token",mounted_physical,sizeof(mounted_physical));jstring(j,v,"volume_token",mounted_token,sizeof(mounted_token));
    bool valid=valid_sha256(grant)&&valid_sha256(physical)&&!strcmp(purpose,a->android_format_request.purpose)&&!strcmp(fs,a->android_format_request.mode)&&
        !strcmp(physical,a->android_format_request.volume_token)&&expiry>0&&expiry<=120&&android_format_epoch_verified(a,j,v)&&
        json_bool(j,json_get(j,0,"authentication_performed"),-1)==1&&json_bool(j,json_get(j,0,"ce_authenticated"),-1)==1&&json_bool(j,json_get(j,0,"fscrypt_policy_verified"),-1)==1&&
        valid_sha256(mounted_token)&&strcmp(mounted_token,physical)&&a->android_format_run_id[0]&&!strcmp(run,a->android_format_run_id)&&!strcmp(mounted_run,run)&&!strcmp(mounted_physical,physical)&&
        jequals(j,v,"credential_type","password")&&json_uint(j,json_get(j,v,"android_user_id"),UINT64_MAX)==0&&
        json_bool(j,json_get(j,v,"ce_authenticated"),-1)==1&&json_bool(j,json_get(j,v,"fscrypt_policy_verified"),-1)==1&&
        jequals(j,v,"mount_owner","android-decrypt")&&jequals(j,v,"current_access_mode","ro")&&json_bool(j,json_get(j,v,"write_supported"),-1)==0&&
        jequals(j,v,"id","userdata")&&jequals(j,v,"decrypt_state","mounted")&&json_bool(j,json_get(j,v,"mounted"),-1)==1&&json_bool(j,json_get(j,v,"read_only"),-1)==1;
    if(!valid){
        if(valid_sha256(grant))copy(a->android_format_cancel_grant,sizeof(a->android_format_cancel_grant),grant);
        android_format_block(a,"FORMAT_AUTH_NOT_VERIFIED",T("Password verification was not confirmed. No data was formatted."));
        a->android_refresh_pending=true;return J_FS_INVENTORY;
    }
    if(a->android_format_abandoned||a->locked){
        copy(a->android_format_cancel_grant,sizeof(a->android_format_cancel_grant),grant);android_format_finish(a);a->android_refresh_pending=true;return J_FS_INVENTORY;
    }
    copy(a->android_format_grant,sizeof(a->android_format_grant),grant);
    copy(a->android_format_request.authorization,sizeof(a->android_format_request.authorization),grant);
    a->android_format_deadline=milliseconds()+expiry*1000;a->android_format_unprotected=false;
    android_format_review(a);return J_NONE;
}
static void android_format_tick(App*a){
    if(a->job.pid||a->preview)return;
    if(a->android_format_cancel_grant[0]){
        FileRequest q={.kind=J_ANDROID_FORMAT_CANCEL};copy(q.authorization,sizeof(q.authorization),a->android_format_cancel_grant);
        if(start_files_request(a,&q))memset(a->android_format_cancel_grant,0,sizeof(a->android_format_cancel_grant));
        return;
    }
    if(a->android_format_stage==AF_REVIEW&&!android_format_ready(a)){
        enum Screen back=a->android_format_from;android_format_abandon(a);
        files_problem(a,"FORMAT_AUTH_EXPIRED",T("The confirmation expired. Data is unchanged. Verify the current Android password again."),back);
    }
}
static void render_android_format_confirmation(App*a){
    heading(a,T("Format data"),T("Data has not been changed."),true);
    rounded(a,(Rect){28,240,664,286},24,PANEL);
    text(a,52,264,0,RED,T("WILL BE ERASED"));
    text(a,52,316,2,TEXT,"userdata");
    wrapped(a,52,388,600,1,MUTED,T("Every file and installed system on this volume."),3);
    text(a,40,580,0,ORANGE,T("FILESYSTEM"));text(a,40,626,2,TEXT,a->android_format_request.mode);
    wrapped(a,40,738,640,1,android_format_ready(a)?GREEN:ORANGE,a->android_format_unprotected?(T("Verified: this volume has no Android encryption.")):(T("The current Android password was verified.")),3);
    wrapped(a,40,910,640,0,MUTED,T("Confirmation lasts two minutes. Cancelling does not erase data."),3);
    button(a,(Rect){28,1320,664,104},T("Hold 2 seconds to format"),A_FS_CONFIRM,ui_free(a)&&android_format_ready(a),true,5000);
}
#endif
