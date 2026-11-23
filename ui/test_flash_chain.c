/* SPDX-License-Identifier: MIT — the real job pipeline of "Flash it to BOOT" (2026-11-10, found on
   the phone): the list of partitions, then the check of the kept stock BOOT its completion starts.
   The dispatcher freed the reply after the handler, which by then was the new job's: the check
   "did not return a result". A stand-in "python" prints the replies of flash.py. */
#define main recovery_ui_program_main
#include "recovery_ui.c"
#undef main
static const char*targets_reply="{\"ok\":true,\"operation\":\"targets\",\"targets\":[{\"label\":\"boot\",\"title\":\"Kernel and ramdisk\",\"size_bytes\":33554432},"
    "{\"label\":\"recovery\",\"title\":\"This recovery\",\"size_bytes\":41943040}],\"super_free_bytes\":0}";
static const char*check_reply="{\"ok\":true,\"operation\":\"check\",\"target\":{\"label\":\"boot\",\"size_bytes\":33554432,\"offline\":true},"
    "\"image\":{\"name\":\"stock-A226BXXSBDZC3-5df570768942.img\",\"kind\":\"Android boot image\",\"sha256\":\"5df57076894215c64e0f7d4d3b722a8eb948355ad301efbc319122f8698916d6\","
    "\"identity\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"file_bytes\":33554432,\"payload_bytes\":33554432,\"compression\":\"none\",\"format\":\"raw\"},"
    "\"warnings\":[],\"rollback_volume\":null,\"identical\":false}";
static bool argv_file(const char*dir,const char*name,const char*wanted,bool present){
    char path[PATH_LEN],body[4096]={0};snprintf(path,sizeof(path),"%s/%s",dir,name);
    FILE*f=fopen(path,"r");if(!f)return false;size_t got=fread(body,1,sizeof(body)-1,f);fclose(f);
    return got>0&&((strstr(body,wanted)!=NULL)==present);
}
int main(int argc,char**argv){
    if(argc!=2)return 2;
    char script[PATH_LEN];snprintf(script,sizeof(script),"%s/fake-python",argv[1]);
    FILE*f=fopen(script,"w");if(!f)return 2;
    fprintf(f,"#!/bin/sh\nprintf '%%s\\n' \"$*\" > '%s/argv'\n"
        "case \"$*\" in "
        "*' payload-stage '*) printf '%%s\\n' \"$*\" > '%s/stage-argv'; echo '{\"ok\":true,\"path\":\"/A22xImages/ota.boot.img\"}';; "
        "*' members '*) printf '%%s\\n' \"$*\" > '%s/members-argv'; echo '{\"ok\":true,\"members\":[]}';; "
        "*'/A22xImages/ota.boot.img'*) printf '%%s\\n' \"$*\" > '%s/staged-argv'; echo '%s';; "
        "*' targets'*) echo '%s';; *' check '*) sleep 0.2; echo '%s';; *) exit 9;; esac\n",
        argv[1],argv[1],argv[1],argv[1],check_reply,targets_reply,check_reply);fclose(f);chmod(script,0700);
    App*a=calloc(1,sizeof(*a));if(!a)return 2;initialize(a);a->device=true;copy(a->python,sizeof(a->python),script);copy(a->flash_helper,sizeof(a->flash_helper),"/opt/a22x-recovery/flash.py");
    /* The result page of the kept stock BOOT, then its button. */
    a->successful=true;a->result_return=ANDROID_MENU;copy(a->stock_boot_path,sizeof(a->stock_boot_path),"/a22x-recovery/saved-boot/stock-A226BXXSBDZC3-5df570768942.img");
    copy(a->stock_boot_token,sizeof(a->stock_boot_token),"cache-token");screen(a,RESULT);
    if(!samsung_action(a,A_STOCK_BOOT_FLASH))return 3;
    uint64_t deadline=milliseconds()+10000;
    while((a->job.pid||a->screen!=FLASH_REVIEW)&&milliseconds()<deadline){a->now=milliseconds();poll_job(a);struct timespec p={0,1000000};nanosleep(&p,NULL);if(a->screen==RESULT&&!a->job.pid)break;}
    bool good=a->screen==FLASH_REVIEW&&a->flash_review_valid&&!strcmp(flash_target_label(a),"boot")&&!strcmp(a->flash_volume,"cache")&&!strncmp(a->flash_sha,"5df57076",8);
    /* After Recents has changed (or removed) the current Files volume, the
       actual helper argv still names A and its selected-entry token. */
    a->flash_from_file=true;a->volume_index=-1;copy(a->flash_origin_volume,sizeof(a->flash_origin_volume),"userdata");
    copy(a->flash_origin_token,sizeof(a->flash_origin_token),"volume-A");copy(a->flash_origin_entry.path,sizeof(a->flash_origin_entry.path),"/media/0/A.img");
    memset(a->flash_origin_entry.token,'a',64);a->flash_origin_entry.token[64]=0;flash_chosen(a);
    deadline=milliseconds()+10000;while(a->job.pid&&milliseconds()<deadline){a->now=milliseconds();poll_job(a);struct timespec p={0,1000000};nanosleep(&p,NULL);}
    char argfile[PATH_LEN],argtext[4096]={0};snprintf(argfile,sizeof(argfile),"%s/argv",argv[1]);f=fopen(argfile,"r");if(!f)good=false;
    else{size_t got=fread(argtext,1,sizeof(argtext)-1,f);fclose(f);good=good&&got>0&&strstr(argtext,"--volume userdata --volume-token volume-A --path /media/0/A.img")&&strstr(argtext,"--expected-entry-token aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");}
    /* An Odin archive or payload ZIP is pinned on listing and staging; the
       newly extracted image is a different entry and must not inherit that token. */
    copy(a->flash_origin_entry.path,sizeof(a->flash_origin_entry.path),"/media/0/AP_fixture.zip");
    copy(a->flash_path,sizeof(a->flash_path),a->flash_origin_entry.path);(void)start_flash_job(a,J_FLASH_MEMBERS);
    deadline=milliseconds()+10000;while(a->job.pid&&milliseconds()<deadline){a->now=milliseconds();poll_job(a);struct timespec p={0,1000000};nanosleep(&p,NULL);}
    copy(a->flash_member,sizeof(a->flash_member),"payload.bin/boot");(void)start_flash_job(a,J_FLASH_STAGE);
    deadline=milliseconds()+10000;while(a->job.pid&&milliseconds()<deadline){a->now=milliseconds();poll_job(a);struct timespec p={0,1000000};nanosleep(&p,NULL);}
    good=good&&argv_file(argv[1],"members-argv","--expected-entry-token",true)&&argv_file(argv[1],"stage-argv","--expected-entry-token",true)&&
         argv_file(argv[1],"staged-argv","--path /A22xImages/ota.boot.img",true)&&argv_file(argv[1],"staged-argv","--expected-entry-token",false);
    /* A new Install-origin flash must never inherit the previous Files token. */
    a->flash_from_file=false;copy(a->flash_path,sizeof(a->flash_path),a->flash_origin_entry.path);(void)start_flash_job(a,J_FLASH_CHECK);
    deadline=milliseconds()+10000;while(a->job.pid&&milliseconds()<deadline){a->now=milliseconds();poll_job(a);struct timespec p={0,1000000};nanosleep(&p,NULL);}
    good=good&&argv_file(argv[1],"argv","--expected-entry-token",false);
    printf("{\"ok\":%s,\"screen\":%d,\"review\":%d,\"target\":\"%s\",\"status\":\"%s\"}\n",good?"true":"false",(int)a->screen,a->flash_review_valid,flash_target_label(a),a->status);
    free(a->pixels);free(a);return good?0:1;
}
