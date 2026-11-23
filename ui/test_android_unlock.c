#define ANDROID_PATTERN_WIRE_VERIFIED 1
#define main recovery_ui_original_main
#include "recovery_ui.c"
#undef main

#define RAW_TOKEN "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define PENDING_TOKEN "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
static int backend(int argc,char**argv){
    int fd=-1;bool user=false,token=false;const char*operation="",*given_token="";bool has_device=false,confirmed=false;const char*mode="";
    bool flow=argc>1&&!strncmp(argv[1],"synthetic-flow-",15);bool flow_pattern=flow&&strstr(argv[1],"pattern")!=NULL;
    for(int i=1;i+1<argc;i++){
        if(!strcmp(argv[i],"--device"))has_device=true;
        if(!strcmp(argv[i],"--mode"))mode=argv[i+1];
        if(!strcmp(argv[i],"--confirm"))confirmed=true;
        if(!strcmp(argv[i],"prepare-android")||!strcmp(argv[i],"cancel-android-unlock")||!strcmp(argv[i],"mount")||!strcmp(argv[i],"inventory"))operation=argv[i];
        if(!strcmp(argv[i],"--expected-volume-token"))given_token=argv[i+1];
        if(!strcmp(argv[i],"--credential-fd"))fd=atoi(argv[i+1]);
        if(!strcmp(argv[i],"--android-user")&&!strcmp(argv[i+1],"0"))user=true;
        if(!strcmp(argv[i],"--expected-volume-token")&&!strcmp(argv[i+1],"token"))token=true;
    }
    if(argc>1&&!strcmp(argv[argc-1],"inventory"))operation="inventory";
    if(flow&&!strcmp(operation,"prepare-android")){if(!has_device||!user||fd!=-1||mode[0]||confirmed||strcmp(given_token,RAW_TOKEN))return 4;
        const char*type=flow_pattern?"pattern":"password";printf("{\"ok\":true,\"credential_type\":\"%s\",\"ce_authenticated\":false,\"volume\":{\"id\":\"userdata\",\"decrypt_state\":\"awaiting_credential\",\"credential_type\":\"%s\",\"preparation_required\":false,\"credential_required\":true,\"ce_authenticated\":false,\"mounted\":false,\"decrypt_write_supported\":%s,\"access_modes\":[\"ro\"%s],\"volume_token\":\"%s\",\"physical_volume_token\":\"%s\"}}\n",type,type,flow_pattern?"false":"true",flow_pattern?"":",\"rw\"",PENDING_TOKEN,RAW_TOKEN);return 0;}
    if(flow&&!strcmp(operation,"cancel-android-unlock")){if(!has_device||!user||fd!=-1||strcmp(given_token,PENDING_TOKEN))return 5;puts("{\"ok\":true,\"reboot_required\":true,\"ce_authenticated\":false,\"volume\":{}} ");return 0;}
    if(flow&&!strcmp(operation,"inventory")){puts("{\"ok\":true,\"volumes\":[]}");return 0;}
    if(flow){token=!strcmp(given_token,PENDING_TOKEN)&&has_device;bool rw=strstr(argv[1],"-rw")!=NULL;if(strcmp(mode,rw?"rw":"ro")||confirmed!=rw)return 9;}
    if(flow&&strstr(argv[1],"expired")&&!strcmp(operation,"mount")){if(!token||!user||fd<64)return 8;puts("{\"ok\":false,\"error\":{\"code\":\"VOLUME_CHANGED\",\"message\":\"expired\"}}");return 1;}
    unsigned char frame[268]={0};ssize_t got=0,n;
    while(got<(ssize_t)sizeof(frame)&&(n=read(fd,frame+got,sizeof(frame)-(size_t)got))>0)got+=n;
    const char sample[]=" p\xC3\xA4ss ";
    const unsigned char synthetic_pattern[]={'1','2','3','6','9'};
    bool pattern=(argc>1&&!strcmp(argv[1],"synthetic-pattern"))||flow_pattern;
    const void*expected=pattern?(const void*)synthetic_pattern:(const void*)sample;size_t size=pattern?sizeof(synthetic_pattern):sizeof(sample)-1;
    size_t offset=pattern?12:4;bool header=pattern?(!memcmp(frame,"A22C",4)&&frame[4]==1&&!frame[5]&&!frame[6]&&!frame[7]&&frame[8]==size&&!frame[9]&&!frame[10]&&!frame[11]):(frame[0]==size&&!frame[1]&&!frame[2]&&!frame[3]);bool ok=fd>=64&&user&&token&&got==(ssize_t)(offset+size)&&header&&!memcmp(frame+offset,expected,size);
    if(flow&&ok)printf("{\"ok\":true,\"ce_authenticated\":true,\"volume\":{\"mounted\":true,\"decrypt_state\":\"mounted\",\"read_only\":%s,\"write_supported\":%s}}\n",!strcmp(mode,"rw")?"false":"true",!strcmp(mode,"rw")?"true":"false");else puts(ok?"{\"ok\":true}":"{\"ok\":false}");return ok?0:1;
}
int main(int argc,char**argv){
    if(argc>1&&(!strcmp(argv[1],"synthetic-backend")||!strcmp(argv[1],"synthetic-pattern")||!strncmp(argv[1],"synthetic-flow-",15)))return backend(argc,argv);
    App*a=calloc(1,sizeof(*a));assert(a);a->pixels=calloc((size_t)NW*NH,sizeof(uint32_t));assert(a->pixels);
    copy(a->python,sizeof(a->python),"/proc/self/exe");copy(a->filesystem_helper,sizeof(a->filesystem_helper),"synthetic-backend");copy(a->fixture,sizeof(a->fixture),"fixture");
    a->volume_count=1;a->volume_index=0;copy(a->volume_id,sizeof(a->volume_id),"userdata");a->screen=FILE_VOLUME;FileVolume*v=&a->volumes[0];
    copy(v->id,sizeof(v->id),"userdata");copy(v->token,sizeof(v->token),"token");copy(v->credential_type,sizeof(v->credential_type),"password");copy(v->decrypt_state,sizeof(v->decrypt_state),"awaiting_credential");v->credential_required=v->decrypt_supported=v->write_supported=true;
    FileRequest q=file_request(a,J_FS_MOUNT);copy(q.mode,sizeof(q.mode),"ro");
    a->android_pending=true;assert(android_unlock_begin(a,&q));assert(a->screen==FILE_PROMPT&&!screenshot_allowed(a));
    insert_character(a,'x');insert_character(a,0x00e4);insert_character(a,'z');move_text_cursor(a,A_FS_LEFT);erase_character(a);assert(!strcmp(a->android_secret,"xz")&&a->prompt_cursor==1);insert_character(a,0x00e4);assert(!strcmp(a->android_secret,"x\xc3\xa4z"));
    pid_t child=fork();assert(child>=0);if(!child){unsigned char vec;int rc=mincore(a->android_secret,4096,&vec);_exit(rc==-1&&errno==ENOMEM?0:1);}int status;assert(waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0);
    assert(files_action(a,A_BACK)&&a->screen==FILE_VOLUME&&!a->android_secret&&!a->job.pid);
    a->android_retry_until=milliseconds()+20000;assert(!android_unlock_begin(a,&q));a->android_retry_until=0;
    a->android_pending=true;assert(android_unlock_begin(a,&q));const char sample[]=" p\xC3\xA4ss ";copy(a->android_secret,257,sample);a->prompt_cursor=strlen(sample);
    render(a);assert(write_ppm(a,"/tmp/android-unlock-synthetic-preview.ppm"));
    accept_file_prompt(a);assert(!a->android_secret&&a->android_fd==0&&a->job.pid>0);pid_t job=a->job.pid;
    accept_file_prompt(a);assert(a->job.pid==job);
    assert(waitpid(job,&status,0)==job&&WIFEXITED(status)&&WEXITSTATUS(status)==0);
    char output[128]={0};ssize_t n=read(a->job.fdout,output,sizeof(output)-1);assert(n>0&&strstr(output,"\"ok\":true"));close(a->job.fdout);close(a->job.fderr);free(a->job.output);a->job.pid=0;
    a->screen=FILE_VOLUME;a->android_pending=true;assert(android_unlock_begin(a,&q));insert_character(a,'a');screen(a,HOME);assert(!a->android_secret);
    a->screen=FILE_VOLUME;a->android_pending=true;assert(android_unlock_begin(a,&q));insert_character(a,'a');lock_show(a);assert(!a->android_secret&&a->lock_return==FILE_VOLUME);
    a->locked=false;a->screen=FILE_VOLUME;copy(v->credential_type,sizeof(v->credential_type),"pattern");copy(a->filesystem_helper,sizeof(a->filesystem_helper),"synthetic-pattern");
    a->android_pending=true;assert(android_unlock_begin(a,&q)&&a->android_pattern_mode&&!screenshot_allowed(a));
    pattern_add(a,0);pattern_add(a,2);assert(a->android_pattern_len==3&&a->android_secret[0]==0&&a->android_secret[1]==1&&a->android_secret[2]==2);
    pattern_wipe(a);pattern_add(a,0);pattern_add(a,8);assert(a->android_pattern_len==3&&a->android_secret[1]==4);
    pattern_wipe(a);pattern_add(a,4);pattern_add(a,0);pattern_add(a,8);assert(a->android_pattern_len==3&&a->android_secret[0]==4&&a->android_secret[1]==0&&a->android_secret[2]==8);
    pattern_wipe(a);pattern_add(a,0);pattern_add(a,5);pattern_add(a,5);assert(a->android_pattern_len==2&&a->android_secret[1]==5);
    pattern_wipe(a);for(int node=0;node<9;node++)pattern_add(a,node);pattern_add(a,8);pattern_add(a,9);assert(a->android_pattern_len==9&&pattern_valid((unsigned char*)a->android_secret,9));pattern_wipe(a);for(int node=0;node<9;node++)assert(a->android_secret[node]==0);
    pattern_add(a,0);pattern_add(a,5);accept_file_prompt(a);assert(!a->job.pid&&a->android_secret);pattern_wipe(a);
    const unsigned char duplicate[]={0,1,1,2},missing_mid[]={0,2,3,4},out_of_range[]={0,1,2,9};
    memcpy(a->android_secret,duplicate,4);a->android_pattern_len=4;assert(!pattern_valid((unsigned char*)a->android_secret,4));accept_file_prompt(a);assert(!a->job.pid);
    memcpy(a->android_secret,missing_mid,4);assert(!pattern_valid((unsigned char*)a->android_secret,4));accept_file_prompt(a);assert(!a->job.pid);
    memcpy(a->android_secret,out_of_range,4);assert(!pattern_valid((unsigned char*)a->android_secret,4));accept_file_prompt(a);assert(!a->job.pid);pattern_wipe(a);
    pointer(a,true,160,530,100);pointer(a,true,560,530,110);pointer(a,true,560,930,120);pointer(a,false,560,930,130);
    assert(a->android_pattern_len==5&&!a->android_pattern_drag&&!a->job.pid&&pattern_valid((unsigned char*)a->android_secret,a->android_pattern_len));
    render(a);assert(write_ppm(a,"/tmp/android-pattern-synthetic-preview.ppm"));
    render(a);assert(test_press(a,A_ANDROID_PATTERN_CLEAR,50)&&!a->android_pattern_len);
    pointer(a,true,160,530,200);pointer(a,true,360,530,210);pointer(a,false,360,530,220);assert(!a->android_pattern_len&&a->android_pattern_short&&!a->job.pid);
    pointer(a,true,160,530,300);pointer(a,true,560,530,310);pointer(a,true,560,930,320);pointer(a,false,560,930,330);
    render(a);assert(test_press(a,A_FS_PROMPT_NEXT,50));assert(!a->android_secret&&a->job.pid>0);job=a->job.pid;accept_file_prompt(a);assert(a->job.pid==job);
    assert(waitpid(job,&status,0)==job&&WIFEXITED(status)&&WEXITSTATUS(status)==0);n=read(a->job.fdout,output,sizeof(output)-1);assert(n>0&&strstr(output,"\"ok\":true"));close(a->job.fdout);close(a->job.fderr);free(a->job.output);a->job.pid=0;
    a->screen=FILE_VOLUME;a->android_pending=true;assert(android_unlock_begin(a,&q));pattern_add(a,0);assert(files_action(a,A_BACK)&&!a->android_secret);
    a->screen=FILE_VOLUME;a->android_pending=true;assert(android_unlock_begin(a,&q));pattern_add(a,0);screen(a,HOME);assert(!a->android_secret);
    android_secret_clear(a);a->android_pending=a->android_cancel_requested=a->android_auth_started=false;a->locked=false;a->device=true;
    for(int scenario=0;scenario<8;scenario++){
        a->screen=FILE_VOLUME;a->volume_count=1;a->volume_index=0;copy(a->volume_id,sizeof(a->volume_id),"userdata");v=&a->volumes[0];memset(v,0,sizeof(*v));copy(v->id,sizeof(v->id),"userdata");copy(v->token,sizeof(v->token),RAW_TOKEN);copy(v->credential_type,sizeof(v->credential_type),"unknown");copy(v->decrypt_state,sizeof(v->decrypt_state),"locked");v->credential_required=v->decrypt_supported=v->preparation_required=true;
        v->decrypt_write_supported=false;v->access_modes_known=v->access_ro=true;v->access_rw=scenario>=6;copy(a->filesystem_helper,sizeof(a->filesystem_helper),scenario==7?"synthetic-flow-password-rw":(scenario==6?"synthetic-flow-pattern-rw":(scenario==1?"synthetic-flow-password":(scenario==3?"synthetic-flow-pattern-expired":"synthetic-flow-pattern"))));a->android_cancel_requested=a->android_pending=a->android_auth_started=false;render(a);assert(test_button(a,A_FS_MOUNT_RO)->enabled);assert(test_button(a,A_FS_MOUNT_RW)->enabled==(scenario>=6));
        if(scenario>=6){assert(test_press(a,A_FS_MOUNT_RW,50)&&a->screen==FILE_CONFIRM);render(a);assert(test_press(a,A_FS_CONFIRM,50));}else assert(test_press(a,A_FS_MOUNT_RO,50));assert(a->job.pid&&a->job.kind==J_ANDROID_PREPARE&&!a->android_secret);
        if(scenario==4)screen(a,HOME);else if(scenario==5)lock_show(a);
        assert(await_job(a));
        if(scenario==4||scenario==5){assert(!a->android_secret&&a->android_pending&&a->android_cancel_requested);android_cancel_tick(a);assert(a->job.pid&&a->job.kind==J_ANDROID_CANCEL);assert(await_job(a));assert(!a->android_pending);a->locked=false;continue;}
        if(scenario==6){assert(a->screen==RESULT&&!strcmp(a->status,"ANDROID_WRITE_NOT_AVAILABLE")&&a->android_pending&&!a->android_secret&&!a->job.pid);android_cancel_schedule(a);android_cancel_tick(a);assert(await_job(a)&&!a->android_pending);continue;}
        assert(a->screen==FILE_PROMPT&&a->android_pending&&!strcmp(v->token,PENDING_TOKEN)&&a->android_secret&&!a->job.pid);assert(a->android_pattern_mode==(scenario!=1&&scenario!=7));assert(!strcmp(a->fs_pending.mode,scenario>=6?"rw":"ro"));
        if(scenario==2){pattern_add(a,0);assert(files_action(a,A_BACK)&&!a->android_secret&&a->android_cancel_requested);android_cancel_tick(a);assert(a->job.pid&&a->job.kind==J_ANDROID_CANCEL);assert(await_job(a));assert(!a->android_pending&&!a->android_cancel_requested);continue;}
        if(scenario!=1&&scenario!=7){pattern_add(a,0);pattern_add(a,2);pattern_add(a,8);}else copy(a->android_secret,257," p\xC3\xA4ss ");
        assert(!a->job.pid);accept_file_prompt(a);assert(a->job.pid&&a->job.kind==J_FS_MOUNT&&!a->android_secret&&!a->android_cancel_requested);assert(await_job(a));assert(!a->android_pending&&!a->android_cancel_requested);if(scenario==3)assert(!a->successful&&!strcmp(a->status,"VOLUME_CHANGED")&&!strcmp(a->last_backend_operation,"files-inventory"));
    }
    /* Reject a claimed success if observed access disagrees or is missing. */
    {Json j;JsonToken toks[128];const char*bad[]={
        "{\"ce_authenticated\":true,\"volume\":{\"mounted\":true,\"decrypt_state\":\"mounted\",\"read_only\":true,\"write_supported\":false}}",
        "{\"ce_authenticated\":true,\"volume\":{\"mounted\":true,\"decrypt_state\":\"mounted\",\"write_supported\":true}}",
        "{\"ce_authenticated\":true,\"volume\":{\"mounted\":true,\"decrypt_state\":\"mounted\",\"read_only\":false,\"write_supported\":false}}"};
     for(size_t i=0;i<3;i++){assert(json_parse(&j,bad[i],toks,128)>0);a->android_auth_started=true;copy(a->fs_request.mode,sizeof(a->fs_request.mode),"rw");assert(complete_files_job(a,&j,J_FS_MOUNT)==J_FS_INVENTORY);assert(!a->successful&&!strcmp(a->status,"INVALID_DECRYPT_RESULT"));}}
    /* A read-only Android mount cannot be promoted in this recovery boot. */
    a->volume_count=1;a->volume_index=0;v=&a->volumes[0];memset(v,0,sizeof(*v));copy(v->id,sizeof(v->id),"userdata");copy(v->decrypt_state,sizeof(v->decrypt_state),"mounted");v->mounted=v->read_only=v->write_supported=v->mountable=true;a->screen=FILE_VOLUME;render(a);assert(!test_button(a,A_FS_MOUNT_RW)->enabled);assert(files_action(a,A_FS_MOUNT_RW)&&!a->job.pid&&a->screen==FILE_VOLUME);
    free(a->pixels);free(a);puts("android-unlock two-phase synthetic CLI/FD/lifecycle PASS");return 0;
}
