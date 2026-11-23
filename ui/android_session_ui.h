/* SPDX-License-Identifier: MIT
 * The startup policy unlocks a RAM session, then leaves userdata unmounted.
 * A RAM marker records only that the prompt was offered, never authentication.
 * Mounting at start (automount_ui.h, android_startup_keep) unlocks the same way and leaves the
 * data mounted, for writing when that was chosen and the data allows it.
 */
#ifndef A22X_ANDROID_SESSION_UI_H
#define A22X_ANDROID_SESSION_UI_H
static const char*android_startup_marker="/run/a22x-recovery/android-startup-prompted";
static bool android_startup_claim(App*a){
    a->android_startup_handled=true;
    if(!a->device)return true;
    int fd=open(android_startup_marker,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0)return false;
    close(fd);return true;
}
static void android_startup_mark_handled(App*a){
    if(!a->android_startup_handled)(void)android_startup_claim(a);
    a->android_startup_stage=AS_IDLE;
}
static FileVolume*android_startup_volume(App*a){
    for(int n=0;n<a->volume_count;n++)if(!strcmp(a->volumes[n].id,"userdata")){
        a->volume_index=n;copy(a->volume_id,sizeof(a->volume_id),"userdata");return &a->volumes[n];
    }
    return NULL;
}
static void android_warm_tick(App*a){
    if(a->android_warm_pid>0){
        if(waitpid(a->android_warm_pid,NULL,WNOHANG)==a->android_warm_pid)a->android_warm_pid=0;
        return;
    }
    if(!a->device||a->preview||a->android_warm_started)return;
    a->android_warm_started=true;
    pid_t child=fork();
    if(child==0){
        execl(a->python,a->python,"-B","/opt/a22x-recovery/decrypt_prepare.py","--warm-public-runtime",(char*)NULL);
        _exit(127);
    }
    if(child>0)a->android_warm_pid=child;
}
static void android_startup_tick(App*a){
    if(!a->device||a->preview||a->android_startup_handled||a->android_password_policy!=ANDROID_PASSWORD_STARTUP||
        a->locked||a->settings_broken||a->screen!=HOME||a->job.pid||a->settings_pid||a->android_pending||
        a->android_cancel_requested||a->android_format_stage||a->android_format_cancel_grant[0])return;
    /* Claim before any child is launched: cancellation, an error and a UI restart cannot loop. */
    if(!android_startup_claim(a))return;
    a->android_startup_keep=false;a->android_startup_stage=AS_INVENTORY;a->fs_inventory_destination=HOME;
    if(!start_files_job(a,J_FS_INVENTORY)){a->android_startup_stage=AS_IDLE;toast(a,T("Open Files to unlock Android data."));}
}
static bool android_startup_inventory(App*a){
    enum AndroidStartupStage stage=a->android_startup_stage;
    if(stage!=AS_INVENTORY&&stage!=AS_MOUNTED_INVENTORY&&stage!=AS_FINAL_INVENTORY)return false;
    FileVolume*v=android_startup_volume(a);
    if(!v||!v->decrypt_supported||v->android_user_id!=0||!valid_sha256(v->token)){
        a->android_startup_stage=AS_IDLE;screen(a,HOME);toast(a,T("Open Files to unlock Android data."));return true;
    }
    if(stage==AS_INVENTORY&&a->android_startup_keep){
        if(v->mounted){a->android_startup_stage=AS_IDLE;screen(a,HOME);return true;}
        bool rw=a->android_startup_rw&&(v->access_modes_known?v->access_rw:v->decrypt_write_supported);
        FileRequest q=file_request(a,J_FS_MOUNT);copy(q.mode,sizeof(q.mode),rw?"rw":"ro");
        a->android_startup_stage=AS_AUTHENTICATING;
        if(!android_mount_begin(a,&q)){a->android_startup_stage=AS_IDLE;screen(a,HOME);toast(a,T("Open Files to unlock Android data."));}
        return true;
    }
    if(stage==AS_MOUNTED_INVENTORY&&a->android_startup_keep){
        a->android_startup_stage=AS_IDLE;screen(a,HOME);
        toast(a,v->mounted?(v->read_only?T("Android data is mounted read-only."):T("Android data is mounted for writing.")):T("Open Files to unlock Android data."));
        return true;
    }
    if(stage==AS_INVENTORY){
        if(!v->reusable_session_supported||v->mounted||(android_volume_retained(v)&&!android_volume_needs_password(v))){
            a->android_startup_stage=AS_IDLE;screen(a,HOME);return true;
        }
        FileRequest q=file_request(a,J_FS_MOUNT);copy(q.mode,sizeof(q.mode),"ro");
        a->android_startup_stage=AS_AUTHENTICATING;
        if(!android_mount_begin(a,&q)){a->android_startup_stage=AS_IDLE;screen(a,HOME);toast(a,T("Open Files to unlock Android data."));}
        return true;
    }
    if(stage==AS_MOUNTED_INVENTORY){
        if(!v->mounted||!v->read_only||!v->session_reusable||!v->session_retained||!v->auth_generation||
            strcmp(v->mount_owner,"android-decrypt")){
            a->android_startup_stage=AS_IDLE;files_problem(a,"ANDROID_SESSION_NOT_VERIFIED",T("The unlocked session was not confirmed. Refresh the volume state."),FILE_VOLUME);return true;
        }
        FileRequest q=file_request(a,J_FS_UNMOUNT);a->android_startup_stage=AS_SUSPENDING;
        if(!start_files_request(a,&q)){a->android_startup_stage=AS_IDLE;files_problem(a,"UNMOUNT_NOT_STARTED",T("Data is still mounted. Open Files to unmount it."),FILE_VOLUME);}
        return true;
    }
    a->android_startup_stage=AS_IDLE;
    if(!android_volume_retained(v)){files_problem(a,"ANDROID_SESSION_NOT_VERIFIED",T("The unmounted session was not confirmed. Refresh the volume state."),FILE_VOLUME);return true;}
    screen(a,HOME);toast(a,android_volume_needs_password(v)?T("Data is unmounted. The next mount will ask for its password."):T("Android data is unlocked for this recovery session."));
    return true;
}
#endif
