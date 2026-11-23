/* Real UI save/fork/CLI route; persistence is restricted to owned fixture files. */
#define main recovery_ui_original_main
#include "recovery_ui.c"
#undef main

static void finish_child(App*a){
    uint64_t until=milliseconds()+8000;
    while(a->settings_pid&&milliseconds()<until){
        a->now=milliseconds();settings_poll(a);
        struct timespec pause={0,1000000};nanosleep(&pause,NULL);
    }
    assert(!a->settings_pid);
}
static void mode(const char*value){assert(!setenv("A22X_POLICY_FIXTURE_MODE",value,1));}
static void choose(App*a,unsigned int policy){
    a->screen=ANDROID_PASSWORD_SETTINGS;a->now=milliseconds();
    action(a,A_ANDROID_PASSWORD_MODE+(int)policy);
    assert(a->android_password_policy==policy&&a->settings_dirty&&!a->job.pid);
}
static void save_async(App*a){settings_save(a,false);assert(a->settings_pid>0);finish_child(a);}
static void retry_save(App*a){
    assert(a->settings_dirty);a->now=a->settings_retry_at+SETTINGS_DELAY_MS+1;
    a->settings_changed_at=a->now-SETTINGS_DELAY_MS;settings_flush(a);
    assert(a->settings_pid>0);finish_child(a);
}
static void expect(App*a,const char*policy,int brightness){
    char data[8192],value[32],*args[]={a->python,"-B",(char*)settings_helper,"status",NULL};
    assert(!settings_run(a,args,data,sizeof(data)));
    JsonToken tokens[192];Json j;assert(json_parse(&j,data,tokens,192)>0);
    jstring(&j,0,"android_password_policy",value,sizeof(value));
    if(strcmp(value,policy)){fprintf(stderr,"policy: wanted %s, observed %s\n",policy,value);abort();}
    if(brightness>=0)assert((int)json_uint(&j,json_get(&j,0,"brightness"),999)==brightness);
}
static void external_policy(App*a,const char*policy){
    char*args[]={a->python,"-B",(char*)settings_helper,"set","--android-password-policy",(char*)policy,NULL};
    assert(!settings_run(a,args,NULL,0));
}
static void wait_entered(const char*root){
    char path[PATH_MAX];snprintf(path,sizeof(path),"%s/entered",root);
    uint64_t until=milliseconds()+8000;
    while(access(path,F_OK)&&milliseconds()<until){struct timespec pause={0,1000000};nanosleep(&pause,NULL);}
    assert(!access(path,F_OK));assert(!unlink(path));
}
static void release_child(const char*root){
    char path[PATH_MAX];snprintf(path,sizeof(path),"%s/release",root);
    int fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);assert(fd>=0);close(fd);
}
int main(int argc,char**argv){
    assert(argc==4);
    App*a=calloc(1,sizeof(*a));assert(a);
    a->device=true;a->lock_mode=1;a->access_mode=true;a->recovery_tz=-1;
    a->screen=ANDROID_PASSWORD_SETTINGS;a->android_startup_handled=true;
    copy(a->python,sizeof(a->python),argv[3]);settings_helper=argv[2];
    unsigned int scenarios=0;

    /* A stale UI snapshot must not overwrite a policy changed by another helper. */
    mode("success");a->android_password_policy=ANDROID_PASSWORD_EACH_MOUNT;
    a->saved_brightness=31;settings_changed(a);save_async(a);
    expect(a,"first_access",31);assert(!a->settings_dirty);scenarios++;

    /* An explicit policy choice is part of the next save. */
    choose(a,ANDROID_PASSWORD_STARTUP);save_async(a);
    expect(a,"startup",31);assert(!a->settings_dirty);scenarios++;

    /* rc=3 already committed RAM: retry persists that current record. */
    mode("busy");choose(a,ANDROID_PASSWORD_FIRST_ACCESS);save_async(a);
    expect(a,"first_access",31);assert(a->settings_dirty&&a->settings_retries==1);
    mode("success");retry_save(a);expect(a,"first_access",31);
    assert(!a->settings_dirty&&!a->settings_retries);scenarios++;

    /* A later external policy wins over a retry of an already accepted choice. */
    mode("busy");choose(a,ANDROID_PASSWORD_EACH_MOUNT);save_async(a);
    expect(a,"each_mount",31);mode("success");external_policy(a,"startup");
    retry_save(a);expect(a,"startup",31);scenarios++;

    /* A child failure before RAM commit retains the explicit choice for retry. */
    mode("fail-before");choose(a,ANDROID_PASSWORD_FIRST_ACCESS);save_async(a);
    expect(a,"startup",31);assert(a->settings_dirty);
    mode("success");retry_save(a);expect(a,"first_access",31);scenarios++;

    /* The result of an older in-flight save cannot clear a newer UI choice. */
    mode("hold-success");choose(a,ANDROID_PASSWORD_STARTUP);settings_save(a,false);
    assert(a->settings_pid>0);pid_t original=a->settings_pid;wait_entered(argv[1]);
    choose(a,ANDROID_PASSWORD_EACH_MOUNT);assert(a->settings_pid==original);
    release_child(argv[1]);finish_child(a);expect(a,"startup",31);assert(a->settings_dirty);
    mode("success");retry_save(a);expect(a,"each_mount",31);scenarios++;

    /* The same ordering applies when the older child fails. */
    mode("hold-failure");choose(a,ANDROID_PASSWORD_FIRST_ACCESS);settings_save(a,false);
    assert(a->settings_pid>0);wait_entered(argv[1]);choose(a,ANDROID_PASSWORD_STARTUP);
    release_child(argv[1]);finish_child(a);expect(a,"each_mount",31);assert(a->settings_dirty);
    mode("success");retry_save(a);expect(a,"startup",31);scenarios++;

    /* An older RAM-only result must not defer or drop a newer choice. */
    mode("hold-busy");choose(a,ANDROID_PASSWORD_FIRST_ACCESS);settings_save(a,false);
    assert(a->settings_pid>0);wait_entered(argv[1]);choose(a,ANDROID_PASSWORD_EACH_MOUNT);
    release_child(argv[1]);finish_child(a);expect(a,"first_access",31);
    assert(a->settings_dirty&&!a->settings_retry_at&&!a->settings_retries);
    mode("success");retry_save(a);expect(a,"each_mount",31);scenarios++;

    /* Power-path settlement must process a failed pending save and keep the choice. */
    mode("fail-before");choose(a,ANDROID_PASSWORD_FIRST_ACCESS);settings_save(a,false);
    assert(a->settings_pid>0);mode("success");settings_settle(a);
    expect(a,"first_access",31);assert(!a->settings_pid&&!a->settings_dirty);scenarios++;

    /* Tapping the shown value explicitly still wins over a stale UI snapshot. */
    external_policy(a,"startup");choose(a,ANDROID_PASSWORD_FIRST_ACCESS);save_async(a);
    expect(a,"first_access",31);scenarios++;

    free(a);
    printf("{\"ok\":true,\"scenarios\":%u,\"physical_device_io\":false}\n",scenarios);
    return 0;
}
