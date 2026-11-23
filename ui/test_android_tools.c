/* SPDX-License-Identifier: MIT — fail-closed Android report/module UI tests. */
#define main recovery_ui_program_main
#include "recovery_ui.c"
#undef main
#define TEST_SHA "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define TEST_TOKEN "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define TEST_FRAMEWORK "\"framework\":{\"id\":\"magisk\",\"version\":\"31.0\",\"version_code\":31000,\"status\":\"supported\",\"adapter\":\"magisk-31.0-markers-v1\",\"reason\":\"\"}"
#define TEST_ACCESS "\"access\":{\"mounted\":true,\"authenticated\":true,\"read_only\":false,\"write_supported\":true,\"volume_token\":\"" TEST_TOKEN "\"}"
static Json parsed_doc(const char*s,JsonToken*t){Json j;assert(json_parse(&j,s,t,2048)>0);return j;}
static void inventory_json(char*out,size_t size){
    snprintf(out,size,"{\"ok\":true,\"operation\":\"inventory\"," TEST_FRAMEWORK "," TEST_ACCESS ",\"can_mutate\":true,\"modules\":[{\"id\":\"example\",\"name\":\"Example module\",\"version\":\"1\",\"status\":\"enabled\",\"disabled\":false,\"remove_pending\":false,\"pending_update\":false,\"actions\":[\"disable\",\"remove\"]}]}");
}
static void plan_json(char*out,size_t size){
    snprintf(out,size,"{\"ok\":true,\"operation\":\"preview\",\"plan\":{\"schema\":\"a22x.android-modules.plan.v1\",\"action\":\"disable\",\"module_id\":\"example\",\"allowed\":true,\"plan_sha256\":\"" TEST_SHA "\"," TEST_FRAMEWORK "," TEST_ACCESS ",\"changes\":[{\"id\":\"example\",\"path\":\"/adb/modules/example\",\"marker\":\"disable\",\"before\":false,\"after\":true}]}}");
}
static void replace_once(char*s,size_t capacity,const char*from,const char*to){
    char*p=strstr(s,from);assert(p);size_t n=strlen(s),old=strlen(from),next=strlen(to);assert(n-old+next<capacity);memmove(p+next,p+old,strlen(p+old)+1);memcpy(p,to,next);
}
static void store_text(const char*root,const char*name,const char*text_){
    char path[PATH_LEN];assert(snprintf(path,sizeof(path),"%s/%s",root,name)<(int)sizeof(path));FILE*f=fopen(path,"w");assert(f);assert(fputs(text_,f)>=0);assert(!fclose(f));
}
/* Cross-layer tests pass an actual Python analyzer report, not a hand-written summary. */
static int test_compat_report_file(const char*path){
    FILE*f=fopen(path,"r");if(!f)return 2;char*text_=calloc(JSON_LIMIT+1,1);JsonToken*t=calloc(8192,sizeof(*t));App*a=calloc(1,sizeof(*a));assert(text_&&t&&a);
    size_t length=fread(text_,1,JSON_LIMIT,f);bool bounded=length<JSON_LIMIT||fgetc(f)==EOF;bool read_ok=!ferror(f);fclose(f);Json j;
    initialize(a);a->preview=true;bool ok=bounded&&read_ok&&json_parse(&j,text_,t,8192)>0&&parse_android_compat(a,&j);
    if(ok){screen(a,ANDROID_COMPAT);render(a);assert(!test_button(a,A_SAMSUNG_CONFIRM)&&!test_button(a,A_INSTALL_CONFIRM));}
    printf("{\"ok\":%s,\"checks\":%u}\n",ok?"true":"false",a->compat_count);free(a->pixels);free(a);free(t);free(text_);return ok?0:1;
}
int main(int argc,char**argv){
    if(argc==3&&!strcmp(argv[1],"--compat-report"))return test_compat_report_file(argv[2]);
    if(argc!=1)return 2;
    App*a=calloc(1,sizeof(*a));assert(a);initialize(a);JsonToken*t=calloc(2048,sizeof(*t));assert(t);char text_[8192];
    a->preview=true;assert(preview(a,"android-modules-locked"));render(a);
    assert(!a->modules_can_mutate&&test_button(a,A_MODULE_DATA)&&!test_button(a,A_MODULE_APPLY));
    const char*old_fields[]={"\"authenticated\":true","\"id\":\"magisk\"","\"version\":\"31.0\""};
    const char*new_fields[]={"\"authenticated\":false","\"id\":\"kernelsu\"","\"version\":\"31.2\""};
    for(unsigned int n=0;n<3;n++){
        inventory_json(text_,sizeof(text_));replace_once(text_,sizeof(text_),old_fields[n],new_fields[n]);Json j=parsed_doc(text_,t);
        assert(parse_android_modules(a,&j)&&!a->modules_can_mutate&&!a->modules[0].actions);
    }
    /* KernelSU Next with the reviewed ksud (2026-11-22): its markers can be changed; another build cannot. */
    inventory_json(text_,sizeof(text_));
    replace_once(text_,sizeof(text_),"\"id\":\"magisk\",\"version\":\"31.0\",\"version_code\":31000","\"id\":\"kernelsu\",\"version\":\"v3.4.2-200-g32e25d58\",\"version_code\":33555");
    replace_once(text_,sizeof(text_),"magisk-31.0-markers-v1","kernelsu-next-33555-markers-v1");
    {Json k=parsed_doc(text_,t);assert(parse_android_modules(a,&k)&&a->modules_can_mutate&&a->modules[0].actions);}
    replace_once(text_,sizeof(text_),"33555,","33556,");
    {Json k=parsed_doc(text_,t);assert(parse_android_modules(a,&k)&&!a->modules_can_mutate&&!a->modules[0].actions);}
    const char*bad_old[]={"\"id\":\"example\"","\"status\":\"enabled\"","\"disable\",\"remove\"","\"disabled\":false"};
    const char*bad_new[]={"\"id\":\"../example\"","\"status\":\"garbage\"","\"execute\",\"remove\"","\"disabled\":null"};
    for(unsigned int n=0;n<4;n++){
        inventory_json(text_,sizeof(text_));replace_once(text_,sizeof(text_),bad_old[n],bad_new[n]);Json j=parsed_doc(text_,t);
        assert(!parse_android_modules(a,&j)&&!a->modules_known&&!a->modules_can_mutate);
    }
    /* Invalid directory names are non-actionable diagnostics alongside healthy modules. */
    inventory_json(text_,sizeof(text_));
    replace_once(text_,sizeof(text_),"\"modules\":[","\"modules\":[{\"id\":\"1invalid\",\"name\":\"Invalid directory\",\"status\":\"unsupported\",\"disabled\":false,\"remove_pending\":false,\"pending_update\":false,\"actions\":[],\"reason\":\"Invalid module directory name\"},");
    Json mixed=parsed_doc(text_,t);assert(parse_android_modules(a,&mixed)&&a->modules_known&&a->modules_can_mutate&&a->modules_count==2&&!a->modules[0].actions&&a->modules[1].actions==5);
    a->screen=ANDROID_MODULES;render(a);action(a,A_MODULE_ITEM);render(a);assert(!test_button(a,A_MODULE_DISABLE)->enabled&&!test_button(a,A_MODULE_ENABLE)->enabled);
    action(a,A_MODULE_DISABLE);assert(!a->job.pid&&!a->modules_plan_allowed);
    /* Even a stale in-memory action bit cannot turn a diagnostic ID into an argument. */
    a->modules_target[0]=a->modules_action[0]=0;a->modules[0].actions=1;render(a);assert(!test_button(a,A_MODULE_DISABLE)->enabled);action(a,A_MODULE_DISABLE);assert(!a->job.pid&&!a->modules_plan_allowed&&!a->modules_target[0]&&!a->modules_action[0]&&a->screen==ANDROID_MODULE_DETAIL);a->modules[0].actions=0;
    action(a,A_BACK);render(a);action(a,A_MODULE_ITEM+1);render(a);assert(test_button(a,A_MODULE_DISABLE)->enabled);
    char long_id[201];memset(long_id,'x',sizeof(long_id)-1);long_id[0]='1';long_id[sizeof(long_id)-1]=0;
    replace_once(text_,sizeof(text_),"1invalid",long_id);mixed=parsed_doc(text_,t);assert(parse_android_modules(a,&mixed)&&strlen(a->modules[0].id)==200&&!a->modules[0].actions);
    replace_once(text_,sizeof(text_),"\"actions\":[]","\"actions\":[\"disable\"]");mixed=parsed_doc(text_,t);assert(!parse_android_modules(a,&mixed)&&!a->modules_can_mutate&&!a->modules_known);
    char display_label[64];module_display_label(display_label,sizeof(display_label),"1invalid\n\t\177");assert(!strcmp(display_label,"1invalid???"));
    inventory_json(text_,sizeof(text_));replace_once(text_,sizeof(text_),"\"pending_update\":false","\"pending_update\":true");
    replace_once(text_,sizeof(text_),"\"status\":\"enabled\"","\"status\":\"update-pending\"");Json j=parsed_doc(text_,t);
    assert(parse_android_modules(a,&j)&&a->modules[0].actions==5);
    inventory_json(text_,sizeof(text_));j=parsed_doc(text_,t);assert(parse_android_modules(a,&j)&&a->modules_can_mutate&&a->modules_count==1&&a->modules[0].actions==5);
    a->screen=ANDROID_MODULES;render(a);assert(test_button(a,A_MODULE_ITEM));action(a,A_MODULE_ITEM);assert(a->screen==ANDROID_MODULE_DETAIL&&a->modules_selected==0);
    render(a);assert(test_button(a,A_MODULE_DISABLE)->enabled&&!test_button(a,A_MODULE_ENABLE)->enabled);
    copy(a->modules_action,sizeof(a->modules_action),"disable");copy(a->modules_target,sizeof(a->modules_target),"example");
    const char*plan_old[]={"\"module_id\":\"example\"","\"action\":\"disable\"","\"path\":\"/adb/modules/example\"","\"marker\":\"disable\"","\"before\":false","\"version\":\"31.0\"",TEST_TOKEN};
    const char*plan_new[]={"\"module_id\":\"different\"","\"action\":\"enable\"","\"path\":\"/adb/modules/example/../else\"","\"marker\":\"remove\"","\"before\":true","\"version\":\"31.1\"",TEST_SHA};
    for(unsigned int n=0;n<7;n++){
        plan_json(text_,sizeof(text_));replace_once(text_,sizeof(text_),plan_old[n],plan_new[n]);j=parsed_doc(text_,t);
        assert(!parse_android_module_plan(a,&j)&&!a->modules_plan_allowed);
    }
    plan_json(text_,sizeof(text_));replace_once(text_,sizeof(text_),"\"read_only\":false","\"read_only\":true");j=parsed_doc(text_,t);
    assert(parse_android_module_plan(a,&j)&&!a->modules_plan_allowed);a->screen=ANDROID_MODULE_CONFIRM;render(a);assert(!test_button(a,A_MODULE_APPLY)->enabled);
    plan_json(text_,sizeof(text_));replace_once(text_,sizeof(text_),"\"allowed\":true","\"allowed\":false");j=parsed_doc(text_,t);
    assert(parse_android_module_plan(a,&j)&&!a->modules_plan_allowed);render(a);assert(!test_button(a,A_MODULE_APPLY)->enabled);
    plan_json(text_,sizeof(text_));replace_once(text_,sizeof(text_),"}]}}","},{\"id\":\"example\",\"path\":\"/adb/modules/example\",\"marker\":\"disable\",\"before\":false,\"after\":true}]}}");j=parsed_doc(text_,t);
    assert(!parse_android_module_plan(a,&j)&&!a->modules_plan_allowed);
    plan_json(text_,sizeof(text_));replace_once(text_,sizeof(text_),"/adb/modules/example","/adb/modules_update/example");j=parsed_doc(text_,t);assert(parse_android_module_plan(a,&j)&&a->modules_plan_allowed);
    render(a);assert(test_button(a,A_MODULE_APPLY)->enabled&&test_button(a,A_MODULE_APPLY)->hold_ms==1000);
    action(a,A_BACK);assert(a->screen==ANDROID_MODULE_DETAIL&&!a->modules_plan_allowed&&!a->modules_plan_sha[0]);assert(!start_android_tools_job(a,J_MODULE_APPLY));
    const char*report="{\"ok\":true,\"schema\":\"a22x.android-compat.v1\",\"status\":\"unknown\",\"preserve_allowed\":false,\"manifest_sha256\":\"" TEST_SHA "\",\"rollback\":{\"before_first_boot\":\"unknown\",\"after_first_boot\":\"not_guaranteed\"},\"checks\":[{\"id\":\"TARGET_PROFILE_UNKNOWN\",\"status\":\"unknown\",\"reason\":\"The target profile has not been qualified.\"}]}";
    j=parsed_doc(report,t);assert(parse_android_compat(a,&j)&&a->compat_known&&a->compat_count==1);a->screen=ANDROID_COMPAT;render(a);
    assert(!test_button(a,A_SAMSUNG_CONFIRM)&&!test_button(a,A_INSTALL_CONFIRM)&&!test_button(a,A_MODULE_APPLY));
    copy(text_,sizeof(text_),report);replace_once(text_,sizeof(text_),"\"preserve_allowed\":false","\"preserve_allowed\":true");j=parsed_doc(text_,t);assert(!parse_android_compat(a,&j)&&!a->compat_known);
    j=parsed_doc("{\"ok\":true,\"schema\":\"a22x.android-compat.v1\",\"status\":\"supported\"}",t);assert(!parse_android_compat(a,&j)&&!a->compat_known);
    a->modules_plan_allowed=true;copy(a->modules_plan_sha,sizeof(a->modules_plan_sha),"old");complete_android_tools_job(a,&j,J_MODULE_PREVIEW,true);
    assert(a->screen==RESULT&&!a->modules_plan_allowed&&!a->modules_known&&!a->modules_plan_sha[0]);
    assert(preview(a,"android"));a->page_scroll=0;render(a);assert(page_scrolls(a)&&test_button(a,A_ANDROID_COMPAT)&&test_button(a,A_MODULES));
    assert(preview(a,"android-module-confirm"));render(a);assert(test_button(a,A_MODULE_APPLY)->hold_ms==1000);screen(a,HOME);assert(!a->modules_plan_allowed&&!a->modules_plan_sha[0]);
    a->screen=FILE_BROWSER;a->nav_depth=3;a->nav_trail[0]=HOME;a->nav_trail[1]=ANDROID_MENU;a->nav_trail[2]=FILE_BROWSER;
    a->compat_pick=a->rom_pick=a->flash_pick=true;assert(source_back(a));assert(a->screen==ANDROID_MENU&&a->compat_pick&&a->source_sheet);
    action(a,A_SOURCE_CANCEL);assert(!a->compat_pick&&!a->rom_pick&&!a->source_sheet);
    a->modules_data_route=a->modules_data_open=true;copy(a->volume_id,sizeof(a->volume_id),"sdcard-p1");copy(a->fs_selected.path,sizeof(a->fs_selected.path),"/stale");
    j=parsed_doc("{\"ok\":true,\"volumes\":[{\"id\":\"sdcard-p1\"},{\"id\":\"userdata\",\"mounted\":false,\"mountable\":true}]}",t);
    assert(complete_files_job(a,&j,J_FS_INVENTORY)==J_NONE&&a->screen==FILE_VOLUME&&current_volume(a)&&!strcmp(current_volume(a)->id,"userdata")&&!a->fs_selected.path[0]);
    action(a,A_BACK);assert(a->screen==ANDROID_MODULES&&!a->modules_data_route);
    /* Real asynchronous argv/JSON flow with a host-only helper. No device I/O. */
    char fixture[]="/tmp/a22x-android-tools-ui-XXXXXX";assert(mkdtemp(fixture));
    inventory_json(text_,sizeof(text_));store_text(fixture,"inventory.json",text_);j=parsed_doc(text_,t);assert(parse_android_modules(a,&j));
    plan_json(text_,sizeof(text_));store_text(fixture,"preview.json",text_);
    store_text(fixture,"helper.py",
        "import json,sys,time\nfrom pathlib import Path\n"
        "assert sys.argv[1]=='--fixture'\np=Path(sys.argv[2]);op=sys.argv[3]\n"
        "if op=='preview':\n assert sys.argv[4:]==['--action','disable','--module-id','example']\n time.sleep(.05)\n"
        "elif op=='apply':\n assert sys.argv[4:]==['--action','disable','--module-id','example','--expected-plan','" TEST_SHA "','--confirm']\n"
        " with (p/'applied').open('a') as f:f.write('1')\n"
        " print(json.dumps({'ok':True,'operation':'apply','status':'applied','changed':1,'journal':{'status':'applied'},'plan_sha256':'" TEST_SHA "'}));sys.exit(0)\n"
        "else:assert op=='inventory' and len(sys.argv)==4\n"
        "print((p/(op+'.json')).read_text())\n");
    a->preview=a->device=false;copy(a->fixture,sizeof(a->fixture),fixture);snprintf(a->modules_helper,sizeof(a->modules_helper),"%s/helper.py",fixture);copy(a->python,sizeof(a->python),"/usr/bin/python3");
    a->modules_selected=0;a->screen=ANDROID_MODULE_DETAIL;action(a,A_MODULE_DISABLE);assert(a->job.kind==J_MODULE_PREVIEW&&await_job(a)&&a->screen==ANDROID_MODULE_CONFIRM&&a->modules_plan_allowed);
    assert(test_press(a,A_MODULE_APPLY,999)&&!a->job.pid&&a->screen==ANDROID_MODULE_CONFIRM);
    assert(test_press(a,A_MODULE_APPLY,1000)&&await_job(a)&&a->screen==ANDROID_MODULES&&!a->modules_plan_allowed&&a->modules_known);
    char path[PATH_LEN];snprintf(path,sizeof(path),"%s/applied",fixture);struct stat st;assert(!stat(path,&st)&&st.st_size==1);
    a->modules_selected=0;screen(a,ANDROID_MODULE_DETAIL);action(a,A_MODULE_DISABLE);assert(a->job.kind==J_MODULE_PREVIEW);render(a);nav_home(a);assert(a->screen==HOME);
    assert(await_job(a)&&a->screen==HOME&&!a->modules_plan_allowed&&!a->modules_plan_sha[0]);assert(!stat(path,&st)&&st.st_size==1);
    store_text(fixture,"files-helper.py","import json,sys,time\nassert sys.argv[1]=='--fixture' and sys.argv[3:] == ['inventory']\ntime.sleep(.05)\nprint(json.dumps({'ok':True,'volumes':[]}))\n");
    snprintf(a->filesystem_helper,sizeof(a->filesystem_helper),"%s/files-helper.py",fixture);
    for(unsigned int cancel=0;cancel<2;cancel++){
        screen(a,ANDROID_MENU);a->fs_inventory_destination=FILE_VOLUMES;
        action(a,A_ANDROID_COMPAT);assert(a->job.kind==J_FS_INVENTORY&&a->source_sheet&&a->compat_pick);
        render(a);action(a,cancel?A_BACK:A_SOURCE_CANCEL);
        assert(a->screen==ANDROID_MENU&&!a->source_sheet&&!a->compat_pick&&!a->rom_pick);
        assert(await_job(a)&&a->screen==ANDROID_MENU&&!a->source_sheet&&!a->compat_pick&&!a->rom_pick&&!a->job.pid);
    }
    /* Choosing a different source retains analyzer mode until explicit cancel. */
    a->screen=FILE_BROWSER;a->nav_depth=3;a->nav_trail[0]=HOME;a->nav_trail[1]=ANDROID_MENU;a->nav_trail[2]=FILE_BROWSER;
    a->compat_pick=a->rom_pick=a->flash_pick=true;assert(source_back(a));assert(a->compat_pick&&a->source_sheet);assert(await_job(a)&&a->screen==ANDROID_MENU&&a->compat_pick&&a->source_sheet);
    action(a,A_SOURCE_CANCEL);assert(!a->compat_pick&&!a->source_sheet&&!a->rom_pick&&a->screen==ANDROID_MENU);
    const char*files[]={"helper.py","files-helper.py","inventory.json","preview.json","applied"};for(unsigned int n=0;n<5;n++){snprintf(path,sizeof(path),"%s/%s",fixture,files[n]);assert(!unlink(path));}assert(!rmdir(fixture));
    puts("{\"ok\":true,\"scope\":\"Android compatibility and module UI contract\",\"hardware\":false,\"fail_closed\":true,\"async_plan_binding\":true}");free(t);free(a->pixels);free(a);return 0;
}
