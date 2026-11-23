/* Offline UI regression: the child below only reads/writes its temporary state
 * file. It never opens a block device, calls Android, mounts or formats anything. */
#define main recovery_ui_original_main
#include "recovery_ui.c"
#undef main
#define RAW "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define PREPARED "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define MOUNTED "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
#define GRANT "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
#define SAMPLE " synthetic pass "
#define RUN "11112222333344445555666677778888"
typedef struct {int phase,inventory,prepare,auth,cancel,revoke,format_attempts,erases,resets;} TestState;
static char state_path[PATH_MAX];
static TestState state_read(void){TestState s={0};FILE*f=fopen(getenv("A22X_UI_FORMAT_TEST_STATE"),"rb");assert(f);assert(fread(&s,sizeof(s),1,f)==1);assert(!fclose(f));return s;}
static void state_write(TestState s){FILE*f=fopen(getenv("A22X_UI_FORMAT_TEST_STATE"),"wb");assert(f);assert(fwrite(&s,sizeof(s),1,f)==1);assert(!fclose(f));}
static const char*arg_value(int argc,char**argv,const char*key){for(int n=2;n+1<argc;n++)if(!strcmp(argv[n],key))return argv[n+1];return "";}
static bool arg_has(int argc,char**argv,const char*key){for(int n=2;n<argc;n++)if(!strcmp(argv[n],key))return true;return false;}
static int fail(const char*code){printf("{\"ok\":false,\"error\":{\"code\":\"%s\",\"message\":\"Synthetic refusal\"}}\n",code);return 1;}
static void inventory(TestState s,const char*scenario){
    bool plain=strstr(scenario,"plain")!=NULL,unavailable=strstr(scenario,"unavailable")!=NULL;
    bool mounted=s.phase==2||strstr(scenario,"mounted")!=NULL;
    bool restarted=s.phase==3||strstr(scenario,"restart")!=NULL;
    const char*auth=plain?"not_required":unavailable?"unavailable":mounted||restarted?"restart_required":"required";
    const char*state=plain?"":mounted?"mounted":restarted?"reboot_required":s.phase==1?"awaiting_credential":"locked";
    const char*token=mounted?MOUNTED:s.phase==1?PREPARED:RAW;
    printf("{\"ok\":true,\"volumes\":[{\"id\":\"userdata\",\"label\":\"Android data (synthetic)\",\"fs_type\":\"%s\",\"volume_token\":\"%s\",\"physical_volume_token\":\"%s\",\"format_auth_state\":\"%s\",\"decrypt_state\":\"%s\",\"credential_type\":\"%s\",\"credential_required\":%s,\"preparation_required\":%s,\"decrypt_supported\":true,\"mounted\":%s,\"read_only\":true,\"mountable\":%s,\"write_supported\":false,\"decrypt_write_supported\":%s,\"access_modes\":[\"ro\",\"rw\"],\"android_user_id\":0,\"size_bytes\":120000000000,\"mountpoint\":\"%s\"}]}\n",
        plain?"ext4":"f2fs",token,RAW,auth,state,s.phase==1||mounted?"password":"unknown",plain||mounted?"false":"true",s.phase==0&&!plain&&!mounted?"true":"false",mounted?"true":"false",plain||mounted?"true":"false",s.phase==1?"true":"false",mounted?"/mnt/android-data":"");
}
static int fake_backend(int argc,char**argv){
    const char*scenario=argv[1],*op="";
    for(int n=2;n<argc;n++){if(!strcmp(argv[n],SAMPLE)||strstr(argv[n],"synthetic pass"))return 90;
        if(!op[0]&&(!strcmp(argv[n],"inventory")||!strcmp(argv[n],"prepare-android")||!strcmp(argv[n],"format-authorize")||!strcmp(argv[n],"format-cancel")||!strcmp(argv[n],"cancel-android-unlock")||!strcmp(argv[n],"format")||!strcmp(argv[n],"reset-data")))op=argv[n];}
    if(!arg_has(argc,argv,"--device"))return 91;
    const char*token=arg_value(argc,argv,"--expected-volume-token"),*grant=arg_value(argc,argv,"--format-authorization"),*purpose=arg_value(argc,argv,"--purpose"),*fs=arg_value(argc,argv,"--fs");
    TestState s=state_read();
    if(!strcmp(op,"inventory")){s.inventory++;state_write(s);inventory(s,scenario);return 0;}
    if(!strcmp(op,"prepare-android")){
        if(strcmp(token,RAW)||arg_has(argc,argv,"--credential-fd")||strcmp(arg_value(argc,argv,"--android-user"),"0"))return 92;
        s.prepare++;s.phase=1;state_write(s);
        printf("{\"ok\":true,\"credential_type\":\"password\",\"ce_authenticated\":false,\"volume\":{\"id\":\"userdata\",\"decrypt_state\":\"awaiting_credential\",\"credential_type\":\"password\",\"preparation_required\":false,\"credential_required\":true,\"ce_authenticated\":false,\"mounted\":false,\"decrypt_write_supported\":true,\"access_modes\":[\"ro\",\"rw\"],\"volume_token\":\"%s\",\"physical_volume_token\":\"%s\",\"decrypt_run_id\":\"%s\"}}\n",PREPARED,RAW,RUN);return 0;
    }
    if(!strcmp(op,"cancel-android-unlock")){
        if(strcmp(token,PREPARED))return 93;
        s.cancel++;s.phase=3;state_write(s);
        puts("{\"ok\":true,\"reboot_required\":true,\"ce_authenticated\":false,\"volume\":{}}");return 0;
    }
    if(!strcmp(op,"format-authorize")){
        int fd=atoi(arg_value(argc,argv,"--credential-fd"));
        if(fd<64||strcmp(token,PREPARED)||strcmp(arg_value(argc,argv,"--android-user"),"0")||strcmp(fs,"f2fs")||(!strcmp(purpose,"format")?false:strcmp(purpose,"android-reset")!=0)||arg_has(argc,argv,"--confirm"))return 94;
        unsigned char frame[300]={0};ssize_t n,got=0;while(got<(ssize_t)sizeof(frame)&&(n=read(fd,frame+got,sizeof(frame)-(size_t)got))>0)got+=n;
        s.auth++;bool correct=got==(ssize_t)(4+strlen(SAMPLE))&&frame[0]==strlen(SAMPLE)&&!frame[1]&&!frame[2]&&!frame[3]&&!memcmp(frame+4,SAMPLE,strlen(SAMPLE));
        s.phase=correct?2:3;state_write(s);if(!correct)return fail("CREDENTIAL_REJECTED");
        printf("{\"ok\":true,\"format_authorization\":\"%s\",\"format_purpose\":\"%s\",\"format_fs\":\"%s\",\"format_volume_token\":\"%s\",\"expires_in_seconds\":120,\"authentication_performed\":%s,\"authentication_run_id\":\"%s\",\"ce_authenticated\":true,\"fscrypt_policy_verified\":true,\"volume\":{\"id\":\"userdata\",\"decrypt_state\":\"mounted\",\"mounted\":true,\"read_only\":true,\"write_supported\":false,\"current_access_mode\":\"ro\",\"mount_owner\":\"android-decrypt\",\"credential_type\":\"%s\",\"android_user_id\":%u,\"ce_authenticated\":%s,\"fscrypt_policy_verified\":true,\"physical_volume_token\":\"%s\",\"decrypt_run_id\":\"%s\",\"volume_token\":\"%s\"}}\n",
            GRANT,strstr(scenario,"badpurpose")?"wrong":purpose,fs,strstr(scenario,"badtarget")?MOUNTED:RAW,strstr(scenario,"oldauth")?"false":"true",RUN,
            strstr(scenario,"nestedtype")?"pattern":"password",strstr(scenario,"nesteduser")?10u:0u,strstr(scenario,"nestedce")?"false":"true",strstr(scenario,"nestedtarget")?MOUNTED:RAW,strstr(scenario,"nestedrun")?"different-run":RUN,MOUNTED);return 0;
    }
    if(!strcmp(op,"format-cancel")){
        if(strcmp(grant,GRANT)||arg_has(argc,argv,"--volume"))return 95;
        s.revoke++;state_write(s);
        puts("{\"ok\":true,\"format_authorization_cancelled\":true,\"data_erased\":false,\"mount_changed\":false}");return 0;
    }
    if(!strcmp(op,"format")||!strcmp(op,"reset-data")){
        s.format_attempts++;state_write(s);
        bool plain=strstr(scenario,"plain")!=NULL,reset=!strcmp(op,"reset-data");
        if(!arg_has(argc,argv,"--confirm")||(!plain&&strcmp(grant,GRANT))||(plain&&grant[0])||(!reset&&(strcmp(token,RAW)||strcmp(fs,"f2fs"))))return 96;
        if(strstr(scenario,"busy"))return fail("FORMAT_CLEANUP_FAILED");
        s.erases++;if(reset)s.resets++;s.phase=4;state_write(s);
        if(reset&&strstr(scenario,"partial")){puts("{\"ok\":false,\"error\":{\"code\":\"DATA_RESET_CACHE_FAILED\",\"message\":\"Synthetic partial reset\",\"details\":{\"data_erased\":true}}}");return 1;}
        puts("{\"ok\":true,\"data_erased\":true,\"volume\":{\"id\":\"userdata\",\"mounted\":false}}");return 0;
    }
    return 97;
}
static App*app_new(const char*scenario){
    state_write((TestState){0});
    App*a=calloc(1,sizeof(*a));assert(a);a->pixels=calloc((size_t)NW*NH,sizeof(uint32_t));assert(a->pixels);
    a->device=true;a->screen=FILE_VOLUME;a->volume_index=-1;a->focus=-1;
    copy(a->python,sizeof(a->python),"/proc/self/exe");copy(a->filesystem_helper,sizeof(a->filesystem_helper),scenario);copy(a->samsung_helper,sizeof(a->samsung_helper),scenario);copy(a->volume_id,sizeof(a->volume_id),"userdata");a->fs_inventory_destination=FILE_VOLUME;
    assert(start_files_job(a,J_FS_INVENTORY)&&await_job(a));assert(current_volume(a));return a;
}
static void app_free(App*a){assert(!a->job.pid);android_secret_clear(a);free(a->pixels);free(a);}
static void shot(App*a,const char*name){const char*dir=getenv("A22X_UI_FORMAT_TEST_SHOTS");if(!dir)return;char path[PATH_MAX];snprintf(path,sizeof(path),"%s/%s.ppm",dir,name);render(a);assert(write_ppm(a,path));}
static void begin_password(App*a,bool reset){
    assert(android_format_start(a,"f2fs",reset,reset?WIPE_REVIEW:FILE_VOLUME));
    pid_t pid=a->job.pid;assert(!android_format_start(a,"f2fs",reset,FILE_VOLUME)&&a->job.pid==pid);
    assert(await_job(a));assert(a->screen==FILE_PROMPT&&a->android_secret&&a->fs_pending.kind==J_ANDROID_FORMAT_AUTH&&!a->android_pattern_mode&&!screenshot_allowed(a));
    TestState s=state_read();assert(s.inventory>=2&&s.prepare==1&&!s.auth&&!s.erases);
}
static void submit(App*a,const char*password){copy(a->android_secret,257,password);accept_file_prompt(a);assert(a->job.pid&&a->job.kind==J_ANDROID_FORMAT_AUTH&&!a->android_secret);pid_t pid=a->job.pid;accept_file_prompt(a);assert(a->job.pid==pid);assert(await_job(a));}
static void revoke_grant(App*a){android_format_tick(a);assert(a->job.pid&&a->job.kind==J_ANDROID_FORMAT_CANCEL);assert(await_job(a));assert(state_read().revoke==1&&!state_read().erases);}
int main(int argc,char**argv){
    if(argc>1&&!strncmp(argv[1],"synthetic-format-",17))return fake_backend(argc,argv);
    copy(state_path,sizeof(state_path),"/tmp/a22x-ui-format-test-XXXXXX");int state_fd=mkstemp(state_path);assert(state_fd>=0);close(state_fd);assert(!setenv("A22X_UI_FORMAT_TEST_STATE",state_path,1));state_write((TestState){0});ui_language=1;
    assert(!strcmp(tr(storage_result_title("FORMAT_RESTART_REQUIRED")),"Потрібен перезапуск recovery"));
    const char*states[]={"VOLUME_BUSY","DECRYPT_OUTCOME_UNKNOWN","VOLUME_CHANGED","FORMAT_AUTH_UNAVAILABLE","FORMAT_AUTH_EXPIRED","FORMAT_VOLUME_MOUNTED","CREDENTIAL_REJECTED","DATA_RESET_CACHE_FAILED"};
    for(size_t n=0;n<sizeof(states)/sizeof(states[0]);n++){const char*title=storage_result_title(states[n]);assert(title&&strcmp(title,states[n])&&strcmp(tr(title),title));}
    assert(!storage_result_title("SYNTHETIC_UNRELATED_ERROR"));
    App*a=app_new("synthetic-format-good");shot(a,"files-locked-uk");
    FileRequest denied=file_request(a,J_FS_FORMAT);copy(denied.mode,sizeof(denied.mode),"f2fs");assert(!start_files_request(a,&denied)&&!state_read().format_attempts);
    begin_password(a,false);shot(a,"format-password-uk");submit(a,SAMPLE);
    assert(a->screen==FILE_CONFIRM&&android_format_ready(a)&&state_read().auth==1&&!state_read().erases);shot(a,"format-review-uk");
    render(a);assert(test_press(a,A_FS_CONFIRM,50)&&!a->job.pid&&!state_read().format_attempts);
    render(a);assert(test_press(a,A_FS_CONFIRM,5100)&&a->job.pid&&!a->android_format_grant[0]);pid_t pid=a->job.pid;assert(files_action(a,A_FS_CONFIRM)&&a->job.pid==pid);
    assert(await_job(a)&&state_read().erases==1&&state_read().format_attempts==1&&!android_format_ready(a));app_free(a);

    a=app_new("synthetic-format-good");begin_password(a,true);submit(a,SAMPLE);
    assert(a->screen==WIPE_REVIEW&&android_format_ready(a)&&!state_read().erases);render(a);assert(test_press(a,A_WIPE_CONFIRM,5100)&&a->job.pid);assert(await_job(a)&&state_read().erases==1&&state_read().resets==1&&!android_format_ready(a));app_free(a);

    a=app_new("synthetic-format-good");begin_password(a,false);submit(a,"wrong");
    assert(a->screen==RESULT&&!a->successful&&!strcmp(a->status,"CREDENTIAL_REJECTED")&&!android_format_ready(a)&&!state_read().format_attempts&&state_read().auth==1);app_free(a);

    a=app_new("synthetic-format-good");begin_password(a,false);assert(files_action(a,A_BACK)&&!a->android_secret&&!android_format_ready(a)&&a->android_cancel_requested);android_cancel_tick(a);assert(await_job(a)&&state_read().cancel==1&&!state_read().auth&&!state_read().erases);app_free(a);

    a=app_new("synthetic-format-good");begin_password(a,false);submit(a,SAMPLE);assert(files_action(a,A_BACK)&&!android_format_ready(a));revoke_grant(a);assert(current_volume(a)->mounted&&current_volume(a)->read_only);shot(a,"files-ro-uk");current_volume(a)->read_only=false;current_volume(a)->write_supported=true;shot(a,"files-rw-uk");app_free(a);

    a=app_new("synthetic-format-good");begin_password(a,false);submit(a,SAMPLE);lock_show(a);assert(a->locked&&!android_format_ready(a));revoke_grant(a);assert(a->screen==LOCKSCREEN);app_free(a);

    a=app_new("synthetic-format-good");begin_password(a,false);copy(a->android_secret,257,SAMPLE);accept_file_prompt(a);screen(a,HOME);assert(await_job(a)&&a->screen==HOME&&!android_format_ready(a));revoke_grant(a);assert(a->screen==HOME);app_free(a);

    a=app_new("synthetic-format-good");begin_password(a,false);submit(a,SAMPLE);a->android_format_deadline=milliseconds()-1;android_format_tick(a);assert(a->screen==RESULT&&!strcmp(a->status,"FORMAT_AUTH_EXPIRED")&&!android_format_ready(a));shot(a,"format-expired-uk");revoke_grant(a);app_free(a);

    const char*invalid[]={"synthetic-format-badpurpose","synthetic-format-badtarget","synthetic-format-oldauth","synthetic-format-nestedtarget","synthetic-format-nestedrun","synthetic-format-nestedce","synthetic-format-nestedtype","synthetic-format-nesteduser"};
    for(size_t n=0;n<sizeof(invalid)/sizeof(invalid[0]);n++){a=app_new(invalid[n]);begin_password(a,false);submit(a,SAMPLE);assert(!android_format_ready(a)&&!strcmp(a->status,"FORMAT_AUTH_NOT_VERIFIED")&&!state_read().format_attempts);revoke_grant(a);app_free(a);}
    const char*blocked[]={"synthetic-format-mounted","synthetic-format-restart","synthetic-format-unavailable","synthetic-format-mounted-unavailable","synthetic-format-plain-mounted"};
    for(size_t n=0;n<sizeof(blocked)/sizeof(blocked[0]);n++){a=app_new(blocked[n]);assert(android_format_start(a,"f2fs",false,FILE_VOLUME)&&await_job(a));assert(a->screen==RESULT&&!android_format_ready(a)&&!state_read().auth&&!state_read().prepare&&!state_read().erases);if(n==0)shot(a,"format-restart-needed-uk");if(n==3)assert(!strcmp(a->status,"FORMAT_AUTH_UNAVAILABLE"));if(n==4)assert(!strcmp(a->status,"FORMAT_VOLUME_MOUNTED"));app_free(a);}

    a=app_new("synthetic-format-plain");assert(android_format_start(a,"f2fs",false,FILE_VOLUME)&&await_job(a));assert(android_format_ready(a)&&a->android_format_unprotected&&!state_read().auth);render(a);assert(test_press(a,A_FS_CONFIRM,5100)&&await_job(a)&&state_read().erases==1);app_free(a);
    a=app_new("synthetic-format-busy");begin_password(a,false);submit(a,SAMPLE);render(a);assert(test_press(a,A_FS_CONFIRM,5100)&&await_job(a));assert(!a->successful&&a->screen==RESULT&&!state_read().erases&&state_read().format_attempts==1&&current_volume(a)->mounted);shot(a,"format-busy-uk");app_free(a);
    /* A request after Android could not open its data still asks for the password (--prompt_and_wipe_data);
       one Settings asked with --wipe_data needs none since 2026-11-21 (wipe_ui.h android_asked_reset). */
    a=app_new("synthetic-format-partial");begin_password(a,true);submit(a,SAMPLE);a->reset_asked=a->reset_page=a->reset_prompt=true;render(a);assert(test_press(a,A_WIPE_CONFIRM,5100)&&await_job(a));assert(!a->successful&&a->screen==RESULT&&!strcmp(a->status,"DATA_RESET_CACHE_FAILED")&&state_read().erases==1&&!a->reset_asked&&!a->reset_page&&!android_format_ready(a)&&!current_volume(a)->mounted);app_free(a);
    assert(!unlink(state_path));puts("android-format synthetic FD, password, grant, expiry, cancellation, hold and refusal flows PASS");return 0;
}
