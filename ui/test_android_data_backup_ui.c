/* Headless routing, gating and strict result validation for Android logical backup. */
#define main recovery_ui_program_main
#include "recovery_ui.c"
#undef main
#define CHECK(x) do{if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);return 1;}}while(0)
static void settle_ad(App*a){uint64_t deadline=milliseconds()+10000;while(a->job.pid&&milliseconds()<deadline){a->now=milliseconds();poll_job(a);struct timespec t={0,1000000};nanosleep(&t,NULL);}}
static void reply(App*a,int kind,const char*json,bool ok){Json j;JsonToken t[128];int n=json_parse(&j,json,t,128);assert(n>0);complete_ad_job(a,&j,kind,ok);}
static int portable_workflow(App*a){
    screen(a,BACKUP);action(a,A_BACKUP_ANDROID);
    CHECK(test_press(a,A_AD_MEDIA,50));settle_ad(a);
    CHECK(a->screen==ANDROID_MEDIA_BACKUP&&ad_media_userdata(a));
    CHECK(test_press(a,A_AD_MEDIA_NEXT,50)&&!strcmp(a->ad_media_dest,"sdcard-p1"));
    CHECK(test_press(a,A_AD_MEDIA_BACKUP,50)&&!a->job.pid);
    CHECK(test_press(a,A_AD_MEDIA_BACKUP,1200)&&a->job.kind==J_AD_MEDIA_BACKUP);settle_ad(a);
    CHECK(a->screen==ANDROID_MEDIA_BACKUP&&a->ad_media_saved&&valid_sha256(a->ad_media_sha));
    char path[PATH_LEN];copy(path,sizeof(path),a->ad_media_path);
    CHECK(test_press(a,A_FILES,50));settle_ad(a);
    int index=-1;
    for(int n=0;n<a->volume_count;n++)if(!strcmp(a->volumes[n].id,"sdcard-p1")){index=n;break;}
    CHECK(index>=0&&test_press(a,A_FS_VOLUME_ITEM+index,50));settle_ad(a);
    CHECK(a->screen==FILE_BROWSER&&a->file_count==1&&!strcmp(a->files[0].name,"A22xPortableBackups"));
    CHECK(test_press(a,A_FS_ENTRY,50));settle_ad(a);
    CHECK(a->file_count==1&&!strcmp(a->files[0].path,path));
    CHECK(test_press(a,A_FS_ENTRY_MENU,50));settle_ad(a);
    CHECK(a->screen==FILE_INFO&&test_press(a,A_AD_MEDIA_INSPECT,50));settle_ad(a);
    CHECK(a->screen==ANDROID_MEDIA_RESTORE&&valid_sha256(a->ad_media_sha)&&!a->ad_media_folder[0]);
    CHECK(test_press(a,A_AD_MEDIA_RESTORE,50)&&!a->job.pid);
    CHECK(test_press(a,A_AD_MEDIA_RESTORE,1500)&&a->job.kind==J_AD_MEDIA_RESTORE);settle_ad(a);
    CHECK(a->screen==ANDROID_MEDIA_RESTORE&&!strncmp(a->ad_media_folder,"/media/0/Restored-Android-",26));
    CHECK(test_press(a,A_BACK,50)&&a->screen==FILE_INFO);
    puts("android portable backup and restore UI PASS");return 0;
}
static int model_workflow(App*a,bool migrate,bool apps){
    snprintf(a->workdir,sizeof(a->workdir),"%s/session",a->fixture);
    CHECK(!mkdir(a->workdir,0700)||errno==EEXIST);
    screen(a,BACKUP);action(a,A_BACKUP_ANDROID);
    CHECK(test_press(a,migrate?A_AD_MIGRATE:A_AD_MODEL,50));settle_ad(a);
    CHECK(a->ad_migrate==migrate&&a->ad_model!=migrate&&a->screen==ANDROID_MEDIA_BACKUP&&ad_media_userdata(a));
    CHECK(ad_media_userdata(a)->read_only&&!strcmp(a->ad_media_dest,"sdcard-p1"));
    if(apps){
        CHECK(test_press(a,A_AD_APP_PICK,50)&&a->job.kind==J_AD_APP_LIST);settle_ad(a);
        CHECK(a->screen==ANDROID_APP_BACKUP_PICK&&a->ad_backup_apps_count==8&&a->ad_backup_apps_selected==0);
        CHECK(a->ad_backup_include_apks&&test_press(a,A_AD_APP_PICK_APKS,50)&&!a->ad_backup_include_apks);
        CHECK(test_press(a,A_AD_APP_PICK_APKS,50)&&a->ad_backup_include_apks);
        CHECK(test_press(a,A_AD_APP_ITEM,50)&&a->ad_backup_apps[0].selected&&a->ad_backup_apps_selected==1);
        CHECK(test_press(a,A_AD_APP_PICK_ALL,50)&&a->ad_backup_apps_selected==8);
        CHECK(test_press(a,A_AD_APP_NEXT,50)&&a->ad_backup_apps_page==1);
        CHECK(!strcmp(a->ad_backup_apps[7].package,"org.example.h"));
        CHECK(test_press(a,A_AD_APP_ITEM+1,50)&&!a->ad_backup_apps[7].selected&&a->ad_backup_apps_selected==7);
        CHECK(test_press(a,A_AD_APP_PICK_DONE,50)&&a->screen==ANDROID_MEDIA_BACKUP);
        char original=a->ad_backup_source_token[0];a->ad_backup_source_token[0]=original=='a'?'b':'a';
        render(a);CHECK(!test_button(a,A_AD_MEDIA_BACKUP)->enabled);
        action(a,A_AD_MEDIA_BACKUP);CHECK(a->screen==ANDROID_MEDIA_BACKUP&&!a->job.pid);
        a->ad_backup_source_token[0]=original;
    }
    CHECK(test_press(a,A_AD_MEDIA_BACKUP,1200)&&a->screen==FILE_PROMPT);
    copy(a->fs_prompt,sizeof(a->fs_prompt),"1234567");CHECK(!backup_prompt_ready(a));
    copy(a->fs_prompt,sizeof(a->fs_prompt),"fixture-password");
    CHECK(test_press(a,A_FS_PROMPT_NEXT,50)&&a->job.kind==J_AD_MODEL_BACKUP);
    settle_ad(a);
    CHECK(a->ad_media_saved&&a->screen==ANDROID_MEDIA_BACKUP&&strstr(a->ad_media_path,migrate?".tar.gz.enc":".tar.zst.enc")&&valid_sha256(a->ad_media_sha));
    if(apps)puts("Android private app-data backup UI PASS");
    return 0;
}
static int encrypted_restore_workflow(App*a){
    snprintf(a->workdir,sizeof(a->workdir),"%s/session",a->fixture);
    screen(a,HOME);CHECK(test_press(a,A_FILES,50));settle_ad(a);
    int v=-1,dir=-1,file=-1;
    for(int i=0;i<a->volume_count;i++)if(!strcmp(a->volumes[i].id,"sdcard-p1"))v=i;
    CHECK(v>=0&&test_press(a,A_FS_VOLUME_ITEM+v,50));settle_ad(a);
    for(int i=0;i<a->file_count;i++)if(!strcmp(a->files[i].name,"A22xMigrationBackups"))dir=i;
    CHECK(dir>=0&&test_press(a,A_FS_ENTRY+dir,50));settle_ad(a);
    for(int i=0;i<a->file_count;i++)if(ad_encrypted_media(a->files[i].name))file=i;
    CHECK(file>=0&&test_press(a,A_FS_ENTRY_MENU+file,50));settle_ad(a);
    CHECK(a->screen==FILE_INFO&&test_press(a,A_AD_MEDIA_INSPECT,50)&&a->screen==FILE_PROMPT);
    copy(a->fs_prompt,sizeof(a->fs_prompt),"incorrect-fixture");CHECK(test_press(a,A_FS_PROMPT_NEXT,50));settle_ad(a);
    CHECK(a->screen==FILE_PROMPT&&a->pw_wrong&&a->pw_shake_until&&!a->ad_media_sha[0]);
    copy(a->fs_prompt,sizeof(a->fs_prompt),"fixture-password");CHECK(test_press(a,A_FS_PROMPT_NEXT,50));settle_ad(a);
    CHECK(a->screen==ANDROID_MEDIA_RESTORE&&a->ad_media_files>0&&valid_sha256(a->ad_media_sha));
    CHECK(test_press(a,A_AD_MEDIA_RESTORE,50)&&!a->job.pid);
    CHECK(test_press(a,A_AD_MEDIA_RESTORE,1500)&&a->job.kind==J_AD_MEDIA_RESTORE);settle_ad(a);
    char folder[80];snprintf(folder,sizeof(folder),"/media/0/Restored-Migration-%.24s",a->ad_media_sha);
    CHECK(a->screen==ANDROID_MEDIA_RESTORE&&!strcmp(a->ad_media_folder,folder));
    puts("Encrypted migration restore UI PASS");return 0;
}
static int app_restore_workflow(App*a){
    snprintf(a->workdir,sizeof(a->workdir),"%s/session",a->fixture);
    CHECK(!mkdir(a->workdir,0700)||errno==EEXIST);
    screen(a,HOME);CHECK(test_press(a,A_FILES,50));settle_ad(a);
    int v=-1;
    for(int i=0;i<a->volume_count;i++)if(!strcmp(a->volumes[i].id,"sdcard-p1"))v=i;
    CHECK(v>=0&&test_press(a,A_FS_VOLUME_ITEM+v,50));settle_ad(a);
    CHECK(a->file_count==1&&test_press(a,A_FS_ENTRY,50));settle_ad(a);
    CHECK(a->file_count==1&&test_press(a,A_FS_ENTRY_MENU,50));settle_ad(a);
    CHECK(a->screen==FILE_INFO&&test_press(a,A_AD_APP_INSPECT,50)&&a->screen==FILE_PROMPT);
    copy(a->fs_prompt,sizeof(a->fs_prompt),"wrong-fixture-password");
    CHECK(test_press(a,A_FS_PROMPT_NEXT,50));settle_ad(a);
    CHECK(a->pw_wrong&&a->screen==FILE_PROMPT&&a->pw_retry_kind==J_AD_APP_INSPECT);
    copy(a->fs_prompt,sizeof(a->fs_prompt),"fixture-password");
    CHECK(test_press(a,A_FS_PROMPT_NEXT,50)&&a->job.kind==J_AD_APP_INSPECT);settle_ad(a);
    CHECK(a->screen==ANDROID_MEDIA_RESTORE&&a->ad_media_apps&&a->ad_apps_count==7&&valid_sha256(a->ad_media_sha));
    CHECK(a->ad_apps[0].status==AD_APP_MISSING&&a->ad_apps[0].apk_saved&&a->ad_apps[1].status==AD_APP_SIGNER&&a->ad_apps[2].status==AD_APP_EMPTY);
    render(a);CHECK(!test_button(a,A_AD_APP_ITEM)->enabled&&!test_button(a,A_AD_APP_RESTORE)->enabled);
    CHECK(test_press(a,A_AD_APP_NEXT,50)&&a->ad_apps_page==1);
    CHECK(test_press(a,A_AD_APP_ITEM,50)&&a->ad_apps_selected==6);
    CHECK(!strcmp(ad_selected_app(a)->package,"org.example.g"));
    FileVolume*data=NULL;
    for(int i=0;i<a->volume_count;i++)if(!strcmp(a->volumes[i].id,"userdata"))data=&a->volumes[i];
    CHECK(data);
    char original=data->token[0];data->token[0]=original=='a'?'b':'a';
    render(a);CHECK(!test_button(a,A_AD_APP_RESTORE));
    action(a,A_AD_APP_RESTORE);CHECK(!a->job.pid);
    data->token[0]=original;
    data->read_only=true;render(a);CHECK(!test_button(a,A_AD_APP_RESTORE));
    data->read_only=false;
    CHECK(test_press(a,A_AD_APP_RESTORE,50)&&!a->job.pid);
    CHECK(test_press(a,A_AD_APP_RESTORE,1500)&&a->job.kind==J_AD_APP_RESTORE);settle_ad(a);
    CHECK(a->screen==ANDROID_MEDIA_RESTORE&&a->ad_apps[6].status==AD_APP_RESTORED&&a->ad_apps_selected==-1);
    CHECK(test_press(a,A_BACK,50)&&a->screen==FILE_INFO);
    puts("Android private app-data restore UI PASS");return 0;
}
static int twrp_review_workflow(App*a){
    screen(a,HOME);CHECK(test_press(a,A_FILES,50));settle_ad(a);
    int volume=-1;
    for(int n=0;n<a->volume_count;n++)if(!strcmp(a->volumes[n].id,"sdcard-p1")){volume=n;break;}
    CHECK(volume>=0&&test_press(a,A_FS_VOLUME_ITEM+volume,50));settle_ad(a);
    int entry=-1;
    for(int n=0;n<a->file_count;n++)if(!strcmp(a->files[n].name,"data.f2fs.win")){entry=n;break;}
    CHECK(entry>=0&&test_press(a,A_FS_ENTRY+entry,50));settle_ad(a);
    CHECK(a->screen==FILE_INFO&&test_press(a,A_AD_TWRP_REVIEW,50));settle_ad(a);
    CHECK(a->screen==ANDROID_TWRP_REVIEW&&a->ad_twrp_parts==1&&a->ad_twrp_checked==1);
    CHECK(a->ad_twrp_files==1&&a->ad_twrp_ce_apps==1&&a->ad_twrp_de_apps==0&&a->ad_twrp_bytes>0);
    CHECK(test_press(a,A_BACK,50)&&a->screen==FILE_INFO);
    puts("TWRP Data backup review UI PASS");return 0;
}
int main(int argc,char**argv){
    if(argc!=3&&argc!=4)return 2;
    App*a=calloc(1,sizeof(*a));assert(a);initialize(a);
    copy(a->fixture,sizeof(a->fixture),argv[1]);copy(a->python,sizeof(a->python),argv[2]);snprintf(a->filesystem_helper,sizeof(a->filesystem_helper),"%s/filesystem.py",argv[1]);snprintf(a->distro_helper,sizeof(a->distro_helper),"%s/distro.py",argv[1]);
    if(argc==4){
        if(!strcmp(argv[3],"model")||!strcmp(argv[3],"migrate")||!strcmp(argv[3],"migrate-apps"))
            return model_workflow(a,strcmp(argv[3],"model")!=0,!strcmp(argv[3],"migrate-apps"));
        if(!strcmp(argv[3],"portable"))return portable_workflow(a);
        if(!strcmp(argv[3],"migration-restore"))return encrypted_restore_workflow(a);
        if(!strcmp(argv[3],"app-restore"))return app_restore_workflow(a);
        if(!strcmp(argv[3],"twrp-review"))return twrp_review_workflow(a);
        return 2;
    }
    screen(a,BACKUP);action(a,A_BACKUP_ANDROID);CHECK(a->screen==ANDROID_BACKUP_CHOICE&&!a->job.pid);
    action(a,A_AD_FILES);settle_ad(a);CHECK(a->screen==ANDROID_DATA_BACKUP&&a->ad_known&&!ad_ready(a));
    render(a);CHECK(test_button(a,A_AD_CREATE)&&!test_button(a,A_AD_CREATE)->enabled);action(a,A_AD_CREATE);CHECK(!a->job.pid);
    const char*token="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    char json[2048];snprintf(json,sizeof(json),"{\"ok\":true,\"operation\":\"inspect\",\"can_backup\":true,\"mounted\":true,\"ce_authenticated\":true,\"read_only\":false,\"write_supported\":true,\"volume_token\":\"%s\",\"destination\":\"/media/0/A22xDataBackups\"}",token);reply(a,J_AD_INSPECT,json,true);CHECK(ad_ready(a));
    a->ad_ro=true;render(a);CHECK(!test_button(a,A_AD_CREATE)->enabled);a->ad_ro=false;
    render(a);CHECK(test_button(a,A_AD_CREATE)->enabled);action(a,A_AD_CREATE);CHECK(a->job.pid);settle_ad(a);CHECK(a->ad_verified&&ad_path_ok(a->ad_path)&&valid_sha256(a->ad_sha));
    reply(a,J_AD_INSPECT,json,true);action(a,A_AD_VERIFY);CHECK(a->job.pid);settle_ad(a);CHECK(a->ad_verified);
    a->ad_verified=false;reply(a,J_AD_BACKUP,"{\"ok\":true,\"operation\":\"backup\",\"verified\":false,\"archive\":{\"volume\":\"userdata\",\"path\":\"/media/0/A22xDataBackups/test.tar.zst\",\"bytes\":1,\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}}",true);CHECK(!a->ad_verified&&a->screen==RESULT);
    reply(a,J_AD_BACKUP,"{\"ok\":true,\"operation\":\"backup\",\"verified\":true,\"archive\":{\"volume\":\"userdata\",\"path\":\"/media/0/A22xDataBackups/test.tar.zst\",\"bytes\":1,\"sha256\":\"bad\"}}",true);CHECK(!a->ad_verified);
    CHECK(!ad_path_ok("/media/0/A22xDataBackups/../evil.tar.zst"));CHECK(!ad_path_ok("/media/0/A22xDataBackups/x/y.tar.zst"));
    puts("android data backup UI PASS");return 0;
}
