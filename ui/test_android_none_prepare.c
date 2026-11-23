#define main recovery_ui_original_main
#include "recovery_ui.c"
#undef main

#define RAW "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define MOUNTED "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
static const char response[] =
    "{\"credential_type\":\"none\",\"android_user_id\":0,\"ce_authenticated\":true,\"fscrypt_policy_verified\":true,"
    "\"volume\":{\"id\":\"userdata\",\"decrypt_state\":\"mounted\",\"credential_type\":\"none\","
    "\"volume_token\":\"" MOUNTED "\",\"physical_volume_token\":\"" RAW "\","
    "\"ce_authenticated\":true,\"fscrypt_policy_verified\":true,\"mounted\":true,\"read_only\":true,"
    "\"write_supported\":false,\"credential_required\":false,\"preparation_required\":false,\"mount_owner\":\"android-decrypt\"}}";

static App *fresh(void){
    App*a=calloc(1,sizeof(*a));assert(a);a->screen=FILE_VOLUME;a->volume_count=1;a->volume_index=0;
    copy(a->volume_id,sizeof(a->volume_id),"userdata");copy(a->volumes[0].id,sizeof(a->volumes[0].id),"userdata");
    copy(a->android_mount_request.volume,sizeof(a->android_mount_request.volume),"userdata");
    copy(a->android_mount_request.volume_token,sizeof(a->android_mount_request.volume_token),RAW);return a;
}
static void replace(char*out,size_t size,const char*from,const char*to,int occurrence){
    char*at=out;while(occurrence--){at=strstr(at,from);assert(at);at+=strlen(from);}at=strstr(at,from);assert(at);
    char tail[4096];copy(tail,sizeof(tail),at+strlen(from));size_t prefix=(size_t)(at-out);
    assert(prefix+strlen(to)+strlen(tail)<size);strcpy(at,to);strcat(out,tail);
}
static void check(const char*text,bool accepted,bool abandoned,bool locked){
    JsonToken tok[128];Json j;assert(json_parse(&j,text,tok,128)>0);App*a=fresh();
    a->android_prepare_abandoned=abandoned;a->locked=locked;
    assert(complete_files_job(a,&j,J_ANDROID_PREPARE)==J_FS_INVENTORY);
    assert(!a->android_pending&&!a->android_cancel_requested&&!a->android_secret&&a->screen!=FILE_PROMPT&&!a->job.pid);
    if(accepted){
        assert(!a->android_cancel_from_inventory);
        assert(a->fs_inventory_destination==((abandoned||locked)?FILE_VOLUME:FILE_BROWSER));
        assert(a->android_refresh_pending==(abandoned||locked));
        const char inventory[]="{\"volumes\":[{\"id\":\"userdata\",\"volume_token\":\"" MOUNTED "\",\"mounted\":true,\"read_only\":true,\"write_supported\":false}]}";
        assert(json_parse(&j,inventory,tok,128)>0);
        assert(complete_files_job(a,&j,J_FS_INVENTORY)==((abandoned||locked)?J_NONE:J_FS_LIST));
        assert(!a->android_pending&&!a->android_cancel_requested&&!a->android_secret&&!a->job.pid);
    }else assert(a->android_refresh_pending&&a->android_cancel_from_inventory&&!strcmp(a->status,"INVALID_PREPARE_RESULT"));
    free(a);
}
int main(void){
    check(response,true,false,false);check(response,true,true,false);check(response,true,false,true);
    struct {const char*from,*to;int occurrence;} bad[]={
        {"\"credential_type\":\"none\"","\"credential_type\":\"password\"",0},
        {"\"credential_type\":\"none\"","\"credential_type\":\"password\"",1},
        {"\"android_user_id\":0","\"android_user_id\":null",0},
        {"\"ce_authenticated\":true","\"ce_authenticated\":false",0},
        {"\"ce_authenticated\":true","\"ce_authenticated\":null",1},
        {"\"fscrypt_policy_verified\":true","\"fscrypt_policy_verified\":false",0},
        {"\"fscrypt_policy_verified\":true","\"fscrypt_policy_verified\":null",1},
        {"\"id\":\"userdata\"","\"id\":\"other\"",0},
        {"\"decrypt_state\":\"mounted\"","\"decrypt_state\":\"locked\"",0},
        {"\"mounted\":true","\"mounted\":false",0},
        {"\"read_only\":true","\"read_only\":null",0},
        {"\"write_supported\":false","\"write_supported\":true",0},
        {"\"credential_required\":false","\"credential_required\":null",0},
        {"\"preparation_required\":false","\"preparation_required\":true",0},
        {"\"mount_owner\":\"android-decrypt\"","\"mount_owner\":\"other\"",0},
        {MOUNTED,RAW,0},{MOUNTED,"invalid",0},{RAW,MOUNTED,0}
    };
    for(size_t i=0;i<sizeof(bad)/sizeof(bad[0]);i++){char text[4096];copy(text,sizeof(text),response);replace(text,sizeof(text),bad[i].from,bad[i].to,bad[i].occurrence);check(text,false,false,false);}
    puts("android NONE prepare response validation PASS");return 0;
}
