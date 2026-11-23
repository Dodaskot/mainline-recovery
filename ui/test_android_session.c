/* Offline UI integration. The synthetic backend touches only this test's
 * private temporary state. It never opens a block device or invokes Android. */
#define main recovery_ui_original_main
#include "recovery_ui.c"
#undef main
#define RAW "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define SESSION "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define MOUNTED "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
#define GRANT "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
#define RUN "gui11112222333344"
#define SAMPLE " synthetic session pass "
typedef struct {
    int phase,key,mounted,rw,policy,auth_generation,mount_generation,legacy;
    int inventory,prepare,mounts,auth,unmounts,cancel,revoke,formats;
} SyntheticState;
static char test_state_path[PATH_MAX],test_marker_path[PATH_MAX];
static SyntheticState state_read(void){
    SyntheticState s;FILE*f=fopen(getenv("A22X_UI_SESSION_TEST_STATE"),"rb");assert(f);
    assert(fread(&s,sizeof(s),1,f)==1);assert(!fclose(f));return s;
}
static void state_write(SyntheticState s){
    FILE*f=fopen(getenv("A22X_UI_SESSION_TEST_STATE"),"wb");assert(f);
    assert(fwrite(&s,sizeof(s),1,f)==1);assert(!fclose(f));
}
static const char*arg_value(int argc,char**argv,const char*key){
    for(int n=2;n+1<argc;n++){if(!strcmp(argv[n],key))return argv[n+1];}
    return "";
}
static bool arg_has(int argc,char**argv,const char*key){
    for(int n=2;n<argc;n++){if(!strcmp(argv[n],key))return true;}
    return false;
}
static int refused(const char*code){
    printf("{\"ok\":false,\"error\":{\"code\":\"%s\",\"message\":\"Synthetic refusal\"}}\n",code);return 1;
}
static bool required(SyntheticState s){return !s.key||s.policy==ANDROID_PASSWORD_EACH_MOUNT;}
static const char*token(SyntheticState s){return s.phase==0?RAW:s.mounted?MOUNTED:SESSION;}
static void volume(SyntheticState s){
    const char*state=s.phase==0?"locked":s.phase==1?"awaiting_credential":s.mounted?"mounted":"session_unmounted";
    char auth_id[40];if(s.auth_generation)snprintf(auth_id,sizeof(auth_id),"\"%032x\"",s.auth_generation);else copy(auth_id,sizeof(auth_id),"null");
    printf("{\"id\":\"userdata\",\"label\":\"Android data (synthetic)\",\"fs_type\":\"f2fs\","
           "\"volume_token\":\"%s\",\"physical_volume_token\":\"%s\",\"format_auth_state\":\"required\","
           "\"decrypt_state\":\"%s\",\"credential_type\":\"%s\",\"credential_required\":%s,"
           "\"preparation_required\":%s,\"decrypt_supported\":true,\"mounted\":%s,"
           "\"read_only\":%s,\"mountable\":%s,\"write_supported\":%s,\"decrypt_write_supported\":true,"
           "\"access_modes\":[\"ro\",\"rw\"],\"android_user_id\":0,\"size_bytes\":120000000000,"
           "\"mountpoint\":\"%s\",\"mount_owner\":\"android-decrypt\",\"current_access_mode\":\"%s\","
           "\"ce_authenticated\":%s,\"fscrypt_policy_verified\":%s,\"decrypt_run_id\":\"%s\","
           "\"reusable_session_supported\":%s,\"session_reusable\":%s,\"session_retained\":%s,"
           "\"mount_requires_credential\":%s,\"android_password_policy\":\"%s\","
           "\"authentication_id\":%s,\"auth_generation\":%d,\"mount_generation\":%d}",
        token(s),RAW,state,s.phase==0?"unknown":"password",required(s)?"true":"false",
        s.phase==0?"true":"false",s.mounted?"true":"false",s.rw?"false":"true",
        s.mounted||!required(s)?"true":"false",s.mounted&&s.rw?"true":"false",s.mounted?"/mnt/android-data":"",
        s.mounted?(s.rw?"rw":"ro"):"",s.mounted?"true":"false",s.mounted?"true":"false",RUN,
        s.phase==0||!s.legacy?"true":"false",s.phase==0||s.legacy?"false":"true",s.phase==0||s.legacy?"false":"true",required(s)?"true":"false",
        android_password_policy_codes[s.policy],auth_id,s.auth_generation,s.mount_generation);
}
static bool credential_read(int fd){
    unsigned char frame[268]={0};ssize_t used=0,n;
    while(used<(ssize_t)sizeof(frame)&&(n=read(fd,frame+used,sizeof(frame)-(size_t)used))>0)used+=n;
    size_t length=sizeof(SAMPLE)-1;
    bool valid=fd>=64&&used==(ssize_t)(4+length)&&frame[0]==length&&!frame[1]&&!frame[2]&&!frame[3]&&!memcmp(frame+4,SAMPLE,length);
    memset(frame,0,sizeof(frame));return valid;
}
static int fake_backend(int argc,char**argv){
    const char*scenario=argv[1],*op="";
    for(int n=2;n<argc;n++){
        assert(!strstr(argv[n],"synthetic session pass"));
        if(!op[0]&&(!strcmp(argv[n],"inventory")||!strcmp(argv[n],"prepare-android")||!strcmp(argv[n],"mount")||
           !strcmp(argv[n],"unmount")||!strcmp(argv[n],"list")||!strcmp(argv[n],"cancel-android-unlock")||
           !strcmp(argv[n],"format-authorize")||!strcmp(argv[n],"format-cancel")||!strcmp(argv[n],"format")))op=argv[n];
    }
    assert(arg_has(argc,argv,"--device"));
    SyntheticState s=state_read();
    if(!strcmp(op,"inventory")){s.inventory++;state_write(s);printf("{\"ok\":true,\"volumes\":[");volume(s);puts("]}");return 0;}
    if(!strcmp(op,"list")){printf("{\"ok\":true,\"path\":\"/\",\"offset\":0,\"total\":0,\"entries\":[],\"read_only\":%s}\n",s.rw?"false":"true");return 0;}
    if(!strcmp(op,"format-cancel")){assert(!strcmp(arg_value(argc,argv,"--format-authorization"),GRANT));s.revoke++;state_write(s);puts("{\"ok\":true,\"cancelled\":true}");return 0;}
    assert(!strcmp(arg_value(argc,argv,"--expected-volume-token"),token(s)));
    if(!strcmp(op,"prepare-android")){
        assert(s.phase==0&&!arg_has(argc,argv,"--credential-fd"));s.prepare++;s.phase=1;state_write(s);
        printf("{\"ok\":true,\"credential_type\":\"password\",\"ce_authenticated\":false,\"volume\":");volume(s);puts("}");return 0;
    }
    if(!strcmp(op,"cancel-android-unlock")){
        assert(!arg_has(argc,argv,"--credential-fd"));s.cancel++;if(s.phase==1){s.phase=3;s.mount_generation++;}state_write(s);
        printf("{\"ok\":true,\"cancelled\":true,\"session_preserved\":true,\"session_retained\":true,\"reboot_required\":false,\"volume\":");volume(s);puts("}");return 0;
    }
    if(!strcmp(op,"unmount")){
        s.unmounts++;if(strstr(scenario,"busy")){state_write(s);return refused("VOLUME_BUSY");}
        s.mounted=s.rw=0;s.phase=3;s.mount_generation++;state_write(s);
        printf("{\"ok\":true,\"filesystem_unmounted\":true,\"session_retained\":true,\"device_offline\":false,\"reboot_required\":false,\"volume\":");volume(s);puts("}");return 0;
    }
    if(!strcmp(op,"mount")||!strcmp(op,"format-authorize")){
        bool format=!strcmp(op,"format-authorize"),fresh=arg_has(argc,argv,"--credential-fd");
        if(format||required(s))assert(fresh);
        if(fresh){assert(!strcmp(arg_value(argc,argv,"--android-user"),"0"));assert(credential_read(atoi(arg_value(argc,argv,"--credential-fd"))));s.auth++;}
        if(strstr(scenario,"wrong")&&(!strstr(scenario,"once")||s.auth==1)){
            /* A rejected reusable authentication drops the cache and leaves a
             * suspended session. Only explicit typed evidence permits retry guidance. */
            s.key=s.mounted=s.rw=0;s.phase=3;s.mount_generation++;state_write(s);
            const char*details=strstr(scenario,"untyped")?"\"session_preserved\":\"true\",\"reboot_required\":\"false\"":
                strstr(scenario,"numeric")?"\"session_preserved\":1,\"reboot_required\":0":
                strstr(scenario,"retry-denied")?"\"session_preserved\":true,\"reboot_required\":false,\"retry_allowed\":false":
                strstr(scenario,"reboot")?"\"session_preserved\":true,\"reboot_required\":true":
                strstr(scenario,"preserved")?"\"session_preserved\":true,\"reboot_required\":false":NULL;
            if(!details)return refused("CREDENTIAL_REJECTED");
            printf("{\"ok\":false,\"error\":{\"code\":\"CREDENTIAL_REJECTED\",\"message\":\"Synthetic refusal\",\"details\":{%s}}}\n",details);return 1;
        }
        if(fresh){s.key=1;s.auth_generation++;}
        if(s.mounted)s.mount_generation++;
        s.mounted=1;s.rw=!format&&!strcmp(arg_value(argc,argv,"--mode"),"rw");s.phase=2;s.mount_generation++;s.mounts++;state_write(s);
        printf("{\"ok\":true,\"authentication_performed\":%s,\"ce_authenticated\":true,\"fscrypt_policy_verified\":true,"
               "\"session_reusable\":%s,\"authentication_run_id\":\"%s\",\"authentication_id\":\"%032x\","
               "\"auth_generation\":%d,\"mount_generation\":%d,",fresh?"true":"false",s.legacy?"false":"true",RUN,s.auth_generation,strstr(scenario,"bad-epoch")?0:s.auth_generation,s.mount_generation);
        if(format)printf("\"format_authorization\":\"%s\",\"format_purpose\":\"%s\",\"format_fs\":\"%s\",\"format_volume_token\":\"%s\",\"expires_in_seconds\":120,",GRANT,arg_value(argc,argv,"--purpose"),arg_value(argc,argv,"--fs"),RAW);
        printf("\"volume\":");volume(s);puts("}");return 0;
    }
    if(!strcmp(op,"format")){s.formats++;state_write(s);return refused("SYNTHETIC_ERASE_FORBIDDEN");}
    return refused("SYNTHETIC_UNKNOWN_OPERATION");
}
static App*app_new(const char*scenario,int policy,bool key,bool initial){
    SyntheticState s={.phase=initial?0:3,.key=key,.policy=policy,.auth_generation=key?1:0,.mount_generation=initial?0:1,.legacy=strstr(scenario,"legacy")!=NULL};state_write(s);unlink(test_marker_path);
    App*a=calloc(1,sizeof(*a));assert(a);a->pixels=calloc((size_t)NW*NH,sizeof(uint32_t));assert(a->pixels);
    a->device=true;a->screen=FILE_VOLUME;a->volume_index=-1;a->focus=-1;a->android_password_policy=(unsigned int)policy;
    copy(a->python,sizeof(a->python),"/proc/self/exe");copy(a->filesystem_helper,sizeof(a->filesystem_helper),scenario);
    copy(a->volume_id,sizeof(a->volume_id),"userdata");copy(a->fs_path,sizeof(a->fs_path),"/");a->fs_inventory_destination=FILE_VOLUME;
    assert(start_files_job(a,J_FS_INVENTORY)&&await_job(a)&&current_volume(a));return a;
}
static void app_free(App*a){assert(!a->job.pid);android_secret_clear(a);free(a->pixels);free(a);}
static void submit(App*a){
    assert(a->android_secret&&a->screen==FILE_PROMPT&&!screenshot_allowed(a));copy(a->android_secret,257,SAMPLE);
    accept_file_prompt(a);assert(a->job.pid&&!a->android_secret&&a->android_fd==0&&a->android_write_fd==0);
    pid_t pid=a->job.pid;accept_file_prompt(a);assert(a->job.pid==pid);assert(await_job(a));
}
static void mount_data(App*a,const char*mode){
    FileRequest q=file_request(a,J_FS_MOUNT);copy(q.mode,sizeof(q.mode),mode);assert(android_mount_begin(a,&q));
}
static void unmount_data(App*a){assert(start_files_job(a,J_FS_UNMOUNT)&&await_job(a));}
static void shot(App*a,const char*name){
    const char*folder=getenv("A22X_UI_SESSION_TEST_SHOTS");if(!folder)return;char path[PATH_MAX];snprintf(path,sizeof(path),"%s/%s.ppm",folder,name);render(a);assert(write_ppm(a,path));
}
static void epoch_case(App*a,const char*auth,const char*mount,const char*body_auth,const char*body_mount,const char*body_id,bool expected){
    char value[2000];snprintf(value,sizeof(value),
        "{\"session_reusable\":true,\"authentication_id\":\"00000000000000000000000000000002\",\"auth_generation\":%s,\"mount_generation\":%s,"
        "\"volume\":{\"session_reusable\":true,\"authentication_id\":\"%s\",\"auth_generation\":%s,\"mount_generation\":%s}}",auth,mount,body_id,body_auth,body_mount);
    Json j;JsonToken tokens[64];assert(json_parse(&j,value,tokens,64)>0);assert(android_format_epoch_verified(a,&j,json_get(&j,0,"volume"))==expected);
}
int main(int argc,char**argv){
    if(argc>1&&!strncmp(argv[1],"synthetic-session-",18))return fake_backend(argc,argv);
    copy(test_state_path,sizeof(test_state_path),"/tmp/a22x-ui-session-state-XXXXXX");int fd=mkstemp(test_state_path);assert(fd>=0);close(fd);
    snprintf(test_marker_path,sizeof(test_marker_path),"%s.prompt",test_state_path);android_startup_marker=test_marker_path;
    assert(!setenv("A22X_UI_SESSION_TEST_STATE",test_state_path,1));ui_language=1;unsigned int tests=0;

    App*a=app_new("synthetic-session-good",ANDROID_PASSWORD_FIRST_ACCESS,true,false);
    assert(android_volume_retained(current_volume(a))&&!android_volume_needs_password(current_volume(a)));
    mount_data(a,"rw");assert(a->job.pid&&!a->android_secret&&await_job(a));assert(state_read().mounts==1&&!state_read().auth&&files_writable(a));tests++;
    unmount_data(a);assert(!current_volume(a)->mounted&&android_volume_retained(current_volume(a)));
    shot(a,"session-unmounted-unlocked-uk");mount_data(a,"ro");assert(await_job(a)&&state_read().mounts==2&&!state_read().auth&&!files_writable(a));tests++;
    unmount_data(a);assert(state_read().unmounts==2);app_free(a);

    a=app_new("synthetic-session-good",ANDROID_PASSWORD_EACH_MOUNT,true,false);
    mount_data(a,"rw");assert(!a->job.pid&&a->android_secret);shot(a,"session-password-each-mount-uk");submit(a);
    assert(state_read().auth==1&&state_read().mounts==1&&files_writable(a));tests++;
    unmount_data(a);mount_data(a,"ro");assert(a->android_secret);submit(a);assert(state_read().auth==2&&state_read().mounts==2&&!files_writable(a));tests++;app_free(a);

    a=app_new("synthetic-session-good",ANDROID_PASSWORD_EACH_MOUNT,true,false);
    mount_data(a,"ro");assert(a->android_secret&&a->screen==FILE_PROMPT);
    assert(test_press(a,A_KB_KEY+3,40)&&a->kb_bubble_until&&a->kb_bubble_cp==a->keyboard_keys[3]);
    a->now=a->kb_bubble_until-1;
    render(a);
    Rect key=a->kb_bubble_rect;
    int cx=key.x+key.w/2,cy=key.y-60;
    if(cx<58)cx=58;
    if(cx>CW-58)cx=CW-58;
    size_t sample=(size_t)nx(cy)*NW+nx(cx+31);
    uint32_t glow=a->pixels[sample];
    a->now=a->kb_bubble_until;render(a);
    assert(glow!=a->pixels[sample]);
    android_secret_clear(a);assert(!a->kb_bubble_cp&&!a->kb_bubble_until);tests++;app_free(a);

    a=app_new("synthetic-session-bad-epoch",ANDROID_PASSWORD_EACH_MOUNT,true,false);
    mount_data(a,"ro");submit(a);
    assert(!strcmp(a->status,"INVALID_DECRYPT_RESULT")&&!a->successful&&state_read().auth==1&&state_read().mounts==1&&!state_read().unmounts);
    assert(current_volume(a)->mounted&&!a->android_secret);tests++;app_free(a);

    a=app_new("synthetic-session-wrong",ANDROID_PASSWORD_EACH_MOUNT,true,false);
    mount_data(a,"ro");submit(a);assert(state_read().auth==1&&!state_read().mounts&&!a->android_secret&&!a->android_pending&&!a->successful);
    assert(!strcmp(a->status,"CREDENTIAL_REJECTED")&&!current_volume(a)->mounted);
    assert(!strcmp(a->message,T("Incorrect Android password or PIN. Restart recovery before another attempt. No format was started.")));tests++;app_free(a);

    const char*retry_message="The Android password was not accepted. Data was not formatted. Check the refreshed data state, then try again without restarting recovery.";
    a=app_new("synthetic-session-wrong-preserved-once",ANDROID_PASSWORD_EACH_MOUNT,true,false);
    mount_data(a,"ro");submit(a);
    assert(!strcmp(a->message,T(retry_message))&&!a->successful&&android_volume_retained(current_volume(a)));
    assert(!a->android_secret&&!a->android_pending&&!a->job.pid&&state_read().auth==1&&!state_read().mounts&&!state_read().formats);
    /* A second user action owns a new password FD; the failed credential was not replayed. */
    mount_data(a,"rw");assert(a->android_secret&&!a->job.pid);submit(a);
    assert(state_read().auth==2&&state_read().mounts==1&&!state_read().prepare&&files_writable(a));tests++;app_free(a);

    const char*closed_errors[]={"synthetic-session-wrong-untyped","synthetic-session-wrong-numeric",
        "synthetic-session-wrong-retry-denied","synthetic-session-wrong-reboot","synthetic-session-wrong-preserved-legacy"};
    for(size_t n=0;n<sizeof(closed_errors)/sizeof(closed_errors[0]);n++){
        bool legacy=strstr(closed_errors[n],"legacy")!=NULL;
        a=app_new(closed_errors[n],ANDROID_PASSWORD_EACH_MOUNT,!legacy,legacy);
        mount_data(a,"ro");if(a->job.pid)assert(await_job(a));submit(a);
        assert(!strcmp(a->message,T("Incorrect Android password or PIN. Restart recovery before another attempt. No format was started.")));
        assert(state_read().auth==1&&!state_read().mounts&&!state_read().formats&&!a->job.pid&&!a->android_secret);tests++;app_free(a);
    }

    a=app_new("synthetic-session-wrong-preserved-once",ANDROID_PASSWORD_STARTUP,false,true);screen(a,HOME);
    android_startup_tick(a);assert(await_job(a)&&a->android_secret);submit(a);
    assert(!strcmp(a->message,T(retry_message))&&a->android_startup_stage==AS_IDLE&&!a->job.pid&&state_read().auth==1);
    screen(a,HOME);for(int n=0;n<8;n++){android_startup_tick(a);}assert(!a->job.pid&&!a->android_secret&&state_read().auth==1);
    mount_data(a,"ro");submit(a);assert(state_read().auth==2&&state_read().prepare==1&&state_read().mounts==1&&current_volume(a)->mounted);tests++;app_free(a);

    a=app_new("synthetic-session-wrong-preserved-once",ANDROID_PASSWORD_FIRST_ACCESS,true,false);
    mount_data(a,"rw");assert(await_job(a));
    assert(android_format_start(a,"f2fs",false,FILE_VOLUME)&&await_job(a)&&a->android_secret);submit(a);
    assert(!strcmp(a->message,T(retry_message))&&a->android_format_stage==AF_IDLE&&!android_format_ready(a)&&!a->android_format_grant[0]);
    assert(state_read().auth==1&&!state_read().formats&&!a->job.pid&&android_volume_retained(current_volume(a)));
    assert(android_format_start(a,"f2fs",false,FILE_VOLUME)&&await_job(a)&&a->android_secret);submit(a);
    assert(android_format_ready(a)&&state_read().auth==2&&!state_read().formats);
    android_format_abandon(a);android_format_tick(a);assert(await_job(a)&&state_read().revoke==1&&!state_read().formats);tests++;app_free(a);

    a=app_new("synthetic-session-good",ANDROID_PASSWORD_EACH_MOUNT,true,false);
    mount_data(a,"ro");assert(files_action(a,A_BACK)&&!a->android_secret&&a->android_cancel_requested);
    android_cancel_tick(a);assert(await_job(a)&&state_read().cancel==1&&!state_read().auth&&android_volume_retained(current_volume(a)));tests++;app_free(a);

    a=app_new("synthetic-session-busy",ANDROID_PASSWORD_FIRST_ACCESS,true,false);
    mount_data(a,"rw");assert(await_job(a));unmount_data(a);
    assert(!strcmp(a->status,"VOLUME_BUSY")&&current_volume(a)->mounted&&files_writable(a)&&state_read().mounts==1);tests++;app_free(a);

    a=app_new("synthetic-session-good",ANDROID_PASSWORD_FIRST_ACCESS,true,false);
    current_volume(a)->mount_credential_known=false;FileRequest q=file_request(a,J_FS_MOUNT);copy(q.mode,sizeof(q.mode),"ro");
    assert(!android_mount_begin(a,&q)&&!a->job.pid&&!a->android_secret);tests++;app_free(a);

    a=app_new("synthetic-session-good",ANDROID_PASSWORD_STARTUP,false,true);screen(a,HOME);a->locked=true;
    android_startup_tick(a);assert(!a->job.pid&&!a->android_startup_handled&&access(test_marker_path,F_OK)<0);tests++;
    a->locked=false;android_startup_tick(a);assert(a->job.pid&&a->android_startup_handled&&await_job(a)&&a->android_secret);
    assert(state_read().prepare==1&&a->android_startup_stage==AS_AUTHENTICATING);submit(a);
    assert(a->screen==HOME&&a->android_startup_stage==AS_IDLE&&!a->job.pid&&state_read().auth==1&&state_read().mounts==1&&state_read().unmounts==1);
    assert(!current_volume(a)->mounted&&android_volume_retained(current_volume(a)));tests++;
    for(int n=0;n<8;n++){android_startup_tick(a);}assert(!a->job.pid&&state_read().auth==1);tests++;
    mount_data(a,"rw");assert(await_job(a)&&!a->android_secret&&state_read().auth==1&&state_read().mounts==2);tests++;app_free(a);

    a=app_new("synthetic-session-good",ANDROID_PASSWORD_STARTUP,false,true);screen(a,HOME);android_startup_tick(a);assert(await_job(a)&&a->android_secret);
    assert(files_action(a,A_BACK)&&a->android_startup_stage==AS_IDLE);android_cancel_tick(a);assert(await_job(a));
    screen(a,HOME);for(int n=0;n<8;n++){android_startup_tick(a);}assert(!a->job.pid&&!state_read().auth&&state_read().cancel==1);tests++;
    a->android_startup_handled=false;android_startup_tick(a);assert(a->android_startup_handled&&!a->job.pid);tests++;
    assert(!current_volume(a)->auth_generation&&!current_volume(a)->authentication_id[0]);
    assert(android_format_start(a,"f2fs",false,FILE_VOLUME)&&await_job(a)&&a->android_secret);submit(a);
    assert(android_format_ready(a)&&state_read().auth==1&&!state_read().formats);
    android_format_abandon(a);android_format_tick(a);assert(await_job(a)&&state_read().revoke==1&&!state_read().formats);tests++;app_free(a);

    a=app_new("synthetic-session-legacy",ANDROID_PASSWORD_STARTUP,false,true);screen(a,HOME);
    android_startup_tick(a);assert(await_job(a)&&a->android_secret&&!current_volume(a)->session_reusable&&a->android_startup_stage==AS_IDLE);
    submit(a);assert(a->screen==FILE_BROWSER&&current_volume(a)->mounted&&state_read().auth==1&&!state_read().unmounts);
    screen(a,HOME);android_startup_tick(a);assert(!a->job.pid&&state_read().auth==1);tests++;app_free(a);

    a=app_new("synthetic-session-good",ANDROID_PASSWORD_FIRST_ACCESS,false,true);screen(a,HOME);
    android_startup_tick(a);assert(!a->job.pid&&!a->android_secret&&!state_read().prepare&&access(test_marker_path,F_OK)<0);tests++;app_free(a);

    a=app_new("synthetic-session-good",ANDROID_PASSWORD_FIRST_ACCESS,true,false);
    a->android_policy_needs_refresh=true;SyntheticState changed=state_read();changed.policy=ANDROID_PASSWORD_EACH_MOUNT;state_write(changed);
    mount_data(a,"ro");assert(await_job(a)&&a->android_secret&&!state_read().mounts&&a->android_password_policy==ANDROID_PASSWORD_EACH_MOUNT);
    assert(files_action(a,A_BACK));android_cancel_tick(a);assert(await_job(a));tests++;app_free(a);

    a=app_new("synthetic-session-good",ANDROID_PASSWORD_FIRST_ACCESS,true,false);mount_data(a,"rw");assert(await_job(a));
    assert(android_format_start(a,"f2fs",false,FILE_VOLUME)&&await_job(a)&&a->android_secret&&a->fs_pending.kind==J_ANDROID_FORMAT_AUTH);
    assert(a->android_format_reusable&&a->android_format_auth_before==1);submit(a);
    assert(android_format_ready(a)&&a->screen==FILE_CONFIRM&&state_read().auth==1&&!state_read().formats&&!current_volume(a)->mount_mode_unconfirmed);
    shot(a,"session-fresh-format-confirmation-uk");screen(a,FILE_VOLUME);android_format_tick(a);assert(await_job(a)&&state_read().revoke==1&&!state_read().formats);tests++;app_free(a);

    a=app_new("synthetic-session-good",ANDROID_PASSWORD_FIRST_ACCESS,true,false);
    assert(android_format_start(a,"ext4",false,FILE_VOLUME)&&await_job(a)&&a->android_secret);submit(a);
    assert(android_format_ready(a)&&state_read().auth==1&&!state_read().formats);android_format_abandon(a);android_format_tick(a);assert(await_job(a));tests++;app_free(a);

    FileVolume baseline={.session_reusable=true};assert(android_format_session_baseline(&baseline));tests++;
    baseline.mounted=true;assert(!android_format_session_baseline(&baseline));tests++;
    baseline.mounted=false;baseline.auth_generation=1;assert(!android_format_session_baseline(&baseline));tests++;
    copy(baseline.authentication_id,sizeof(baseline.authentication_id),"00000000000000000000000000000001");assert(android_format_session_baseline(&baseline));tests++;
    baseline.auth_generation=0;assert(!android_format_session_baseline(&baseline));tests++;
    a=calloc(1,sizeof(*a));assert(a);a->android_format_reusable=true;a->android_format_auth_before=1;a->android_format_mount_before=3;
    const char*id="00000000000000000000000000000002";
    copy(a->android_format_authentication_before,sizeof(a->android_format_authentication_before),"00000000000000000000000000000001");
    epoch_case(a,"2","4","2","4",id,true);tests++;
    const char*bad[]={"0","1","-1","true","\"2\"","2.0","18446744073709551615"};
    for(size_t n=0;n<sizeof(bad)/sizeof(bad[0]);n++){epoch_case(a,bad[n],"4",bad[n],"4",id,false);tests++;}
    epoch_case(a,"2","4","3","4",id,false);tests++;epoch_case(a,"2","4","2","5",id,false);tests++;
    epoch_case(a,"2","3","2","3",id,false);tests++;epoch_case(a,"2","4","2","4","00000000000000000000000000000001",false);tests++;
    copy(a->android_format_authentication_before,sizeof(a->android_format_authentication_before),id);epoch_case(a,"2","4","2","4",id,false);tests++;free(a);

    a=app_new("synthetic-session-good",ANDROID_PASSWORD_EACH_MOUNT,true,false);a->device=false;screen(a,ANDROID_PASSWORD_SETTINGS);
    for(unsigned int n=0;n<ANDROID_PASSWORD_POLICY_COUNT;n++){action(a,A_ANDROID_PASSWORD_MODE+(int)n);assert(a->android_password_policy==n&&!a->android_secret&&!a->job.pid);}
    settings_reset(a);assert(a->android_password_policy==ANDROID_PASSWORD_FIRST_ACCESS);a->toast[0]=0;shot(a,"android-password-settings-uk");tests++;app_free(a);

    /* Mounting at start (automount_ui.h, 2026-11-20): automount.py leaves encrypted data to the
       interface, which unlocks it as the startup policy does and leaves it mounted in the chosen
       mode. Nothing is unmounted, and the startup policy does not prompt a second time. */
    a=app_new("synthetic-session-good",ANDROID_PASSWORD_STARTUP,false,true);screen(a,HOME);
    {const char reply[]="{\"ok\":true,\"operation\":\"automount\",\"results\":[{\"id\":\"sdcard-p1\",\"wanted\":\"rw\",\"result\":\"mounted\",\"mode\":\"rw\"},"
                        "{\"id\":\"userdata\",\"wanted\":\"rw\",\"result\":\"needs_password\"}],\"needs_password\":true}";
     Json j;JsonToken tokens[64];assert(json_parse(&j,reply,tokens,64)>0);
     assert(complete_automount(a,&j,true)==J_FS_INVENTORY&&a->android_startup_keep&&a->android_startup_rw&&a->android_startup_handled);}
    assert(start_files_job(a,J_FS_INVENTORY)&&await_job(a)&&a->android_secret);shot(a,"automount-password-uk");submit(a);
    assert(a->android_startup_stage==AS_IDLE&&a->screen==HOME&&current_volume(a)->mounted&&files_writable(a));
    assert(state_read().prepare==1&&state_read().auth==1&&state_read().mounts==1&&!state_read().unmounts);
    assert(!strcmp(a->toast,T("Android data is mounted for writing.")));
    for(int n=0;n<8;n++)android_startup_tick(a);
    assert(!a->job.pid&&!a->android_secret&&state_read().auth==1&&!state_read().unmounts);tests++;app_free(a);
    a=app_new("synthetic-session-good",ANDROID_PASSWORD_EACH_MOUNT,false,true);screen(a,HOME);
    {const char reply[]="{\"ok\":true,\"results\":[{\"id\":\"userdata\",\"wanted\":\"ro\",\"result\":\"needs_password\"}],\"needs_password\":true}";
     Json j;JsonToken tokens[32];assert(json_parse(&j,reply,tokens,32)>0);
     /* Each-mount policy: offered on the home page, started by a tap. */
     assert(complete_automount(a,&j,true)==J_NONE&&a->automount_unlock_offer&&!a->android_startup_rw&&!a->job.pid);}
    action(a,A_AUTOMOUNT_UNLOCK);assert(await_job(a)&&a->android_secret);submit(a);
    assert(a->screen==HOME&&current_volume(a)->mounted&&!files_writable(a)&&!state_read().unmounts&&state_read().mounts==1);
    assert(!strcmp(a->toast,T("Android data is mounted read-only.")));tests++;app_free(a);
    /* Unlocked already in this recovery session (first access): mounted with no prompt. */
    a=app_new("synthetic-session-good",ANDROID_PASSWORD_FIRST_ACCESS,true,false);screen(a,HOME);
    {const char reply[]="{\"ok\":true,\"results\":[{\"id\":\"userdata\",\"wanted\":\"rw\",\"result\":\"needs_password\"}],\"needs_password\":true}";
     Json j;JsonToken tokens[32];assert(json_parse(&j,reply,tokens,32)>0);assert(complete_automount(a,&j,true)==J_NONE&&a->automount_unlock_offer);}
    action(a,A_AUTOMOUNT_UNLOCK);assert(await_job(a)&&!a->android_secret);
    assert(a->screen==HOME&&files_writable(a)&&!state_read().auth&&state_read().mounts==1&&!state_read().unmounts);tests++;app_free(a);

    unlink(test_marker_path);unlink(test_state_path);printf("Android session UI: %u scenarios PASS; synthetic backend only, physical mounts/formats 0\n",tests);return 0;
}
