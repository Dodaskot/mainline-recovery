/* SPDX-License-Identifier: MIT — late input-node discovery with local fixtures only. */
#define main recovery_ui_program_main
#include "recovery_ui.c"
#undef main

int main(void){
    char dir[]="/tmp/a22x-input-XXXXXX",path[256];
    if(!mkdtemp(dir))return 1;
    Input inputs[MAX_INPUTS];int count=0,ok=1;
    scan_inputs(NULL,inputs,&count,dir,"");if(count!=0)ok=0;
    snprintf(path,sizeof(path),"%s/event2",dir);int fd=open(path,O_CREAT|O_RDWR|O_CLOEXEC,0600);
    if(fd<0)ok=0;else close(fd);
    scan_inputs(NULL,inputs,&count,dir,"");if(count!=1||strcmp(inputs[0].path,path))ok=0;
    scan_inputs(NULL,inputs,&count,dir,"");if(count!=1)ok=0;
    unlink(path);scan_inputs(NULL,inputs,&count,dir,"");if(count!=0)ok=0;
    snprintf(path,sizeof(path),"%s/event9",dir);fd=open(path,O_CREAT|O_RDWR|O_CLOEXEC,0600);
    if(fd<0)ok=0;else close(fd);
    scan_inputs(NULL,inputs,&count,dir,"");if(count!=1)ok=0;
    scan_inputs(NULL,inputs,&count,dir,path);if(count!=1)ok=0;
    for(int n=0;n<count;n++)close(inputs[n].fd);
    unlink(path);rmdir(dir);
    if(!ok){fprintf(stderr,"late input scan failed\n");return 1;}
    puts("{\"ok\":true,\"late_input_discovery\":true,\"no_duplicate_fds\":true,\"node_removal\":true}");return 0;
}
