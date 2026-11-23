/* SPDX-License-Identifier: MIT — the interface's side of the media service and the player (2026-11-22,
 * the owner). media_service.py runs Bluetooth and the player (a22x-media) in the browser's engine with its
 * own layer; the interface asks it for Bluetooth on one socket and drives the player on another. A file
 * to play is opened here, on the volume the interface already holds, and its descriptor is handed over:
 * nothing of a card is mounted where the player runs. */
#ifndef A22X_MEDIA_CLIENT_H
#define A22X_MEDIA_CLIENT_H
#include <sys/mman.h>

#define MEDIA_SERVICE_SOCKET "/run/a22x-recovery/media.sock"
#define MEDIA_PLAYER_SOCKET "/run/a22x-recovery/media/run/a22x-media.sock"
#define MEDIA_SHM_BYTES (1080u*2408u*4u+64u)
#define MEDIA_SPAWN_WAIT_MS 120000u

/* Both may live in App (a file's page and the queue): copied without snprintf, which may not be handed
   two parts of one object. */
static void media_copy(char*out,size_t size,const char*in){size_t n=strnlen(in,size-1);memmove(out,in,n);out[n]=0;}
static void media_tell(App*a,const char*message){copy(a->mu.error,sizeof(a->mu.error),message);a->mu.error_until=a->now+5000;a->dirty=true;}
static bool media_wanted(const App*a){return a->device&&!a->preview;}

/* The service: started once when Bluetooth or the player is first wanted, then kept. */
static void media_spawn(App*a){
    char helper[PATH_LEN];
    if(!media_wanted(a)||a->mu.spawned||!sibling_helper(a,"media_service.py",helper,sizeof(helper)))return;
    a->mu.spawned=true;a->mu.spawned_at=a->now;copy(a->mu.progress,sizeof(a->mu.progress),tr("Starting Bluetooth and the player..."));
    pid_t pid=fork();if(pid<0){a->mu.spawned=false;return;}
    if(!pid){
        if(fork()==0){
            (void)setsid();(void)close_range(3,~0u,0);unsetenv("A22X_RECOVERY_LOCK_FD");
            int in=open("/dev/null",O_RDONLY|O_CLOEXEC),out=open("/run/a22x-recovery/media-service.log",O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW|O_CLOEXEC,0600);
            if(in>=0)dup2(in,0);
            if(out>=0){dup2(out,1);dup2(out,2);}
            char*args[]={a->python,"-B",helper,"serve",NULL};execv(a->python,args);
        }
        _exit(0);
    }
    int status=0;while(waitpid(pid,&status,0)<0&&errno==EINTR){}
}
static int media_connect_socket(const char*path){
    int fd=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);if(fd<0)return -1;
    struct sockaddr_un addr={.sun_family=AF_UNIX};copy(addr.sun_path,sizeof(addr.sun_path),path);
    if(connect(fd,(struct sockaddr*)&addr,sizeof(addr))<0){close(fd);return -1;}
    return fd;
}
static void media_service_send(App*a,const char*json){
    if(a->mu.svc_fd<0)return;
    size_t n=strlen(json);
    if(send(a->mu.svc_fd,json,n,MSG_NOSIGNAL)<0||send(a->mu.svc_fd,"\n",1,MSG_NOSIGNAL)<0){close(a->mu.svc_fd);a->mu.svc_fd=-1;}
}
static void media_output(App*a,const char*device,const char*name);
static void media_player_send(App*a,const char*line){
    if(a->mu.player_fd<0)return;
    if(send(a->mu.player_fd,line,strlen(line),MSG_NOSIGNAL)<0){close(a->mu.player_fd);a->mu.player_fd=-1;}
}
/* Connects what is there, once a second; starts the service when something needs it. */
static void media_link(App*a,bool needed){
    if(!media_wanted(a)||a->now<a->mu.retry_at)return;
    if(a->mu.svc_fd>=0&&(a->mu.player_fd>=0||!a->mu.available))return;
    a->mu.retry_at=a->now+1000;
    /* A service that is there answers; one that is not (never started, or stopped: its socket file can
       stay behind) is started, again at most every 15 s and three times in all. */
    if(a->mu.svc_fd<0&&(a->mu.spawned||needed)){
        a->mu.svc_fd=media_connect_socket(MEDIA_SERVICE_SOCKET);
        if(a->mu.svc_fd>=0){a->mu.svc_len=0;media_service_send(a,"{\"op\":\"status\"}");}
        else if(needed&&a->mu.spawns<3&&(!a->mu.spawns||a->now-a->mu.spawned_at>15000)){a->mu.spawned=false;media_spawn(a);if(a->mu.spawned)a->mu.spawns++;}
    }
    if(a->mu.player_fd<0&&a->mu.svc_fd>=0&&access(MEDIA_PLAYER_SOCKET,F_OK)==0){
        a->mu.player_fd=media_connect_socket(MEDIA_PLAYER_SOCKET);a->mu.pl_len=0;
        if(a->mu.player_fd>=0){char v[32];snprintf(v,sizeof(v),"volume %d\n",a->mu.volume?a->mu.volume:80);media_player_send(a,v);}
    }
    if(a->mu.spawned&&!a->mu.known&&a->now-a->mu.spawned_at>MEDIA_SPAWN_WAIT_MS){a->mu.known=a->bt.known=true;a->mu.available=a->bt.available=false;copy(a->mu.reason,sizeof(a->mu.reason),tr("The media service did not start"));copy(a->bt.reason,sizeof(a->bt.reason),a->mu.reason);a->mu.progress[0]=0;a->dirty=true;}
}

/* --- the service's events -------------------------------------------------------------------------------- */
static void media_service_event(App*a,char*line){
    static JsonToken tokens[1024];Json j;
    if(json_parse(&j,line,tokens,1024)<=0)return;
    char event[24];jstring(&j,0,"event",event,sizeof(event));
    if(!strcmp(event,"progress")){jstring(&j,0,"message",a->mu.progress,sizeof(a->mu.progress));a->dirty=true;return;}
    if(!strcmp(event,"error")){char m[200];jstring(&j,0,"message",m,sizeof(m));media_tell(a,m);return;}
    if(!strcmp(event,"pairing")){
        char kind[16];jstring(&j,0,"kind",kind,sizeof(kind));
        a->bt.pairing_kind=!strcmp(kind,"confirm")?1:!strcmp(kind,"type")?2:0;
        jstring(&j,0,"name",a->bt.pairing_name,sizeof(a->bt.pairing_name));jstring(&j,0,"passkey",a->bt.pairing_passkey,sizeof(a->bt.pairing_passkey));
        jstring(&j,0,"address",a->bt.pairing_address,sizeof(a->bt.pairing_address));
        if(a->bt.pairing_kind)haptic(a,2);
        a->dirty=true;return;
    }
    if(strcmp(event,"state"))return;
    a->mu.known=a->bt.known=true;a->mu.progress[0]=0;
    a->mu.available=a->bt.available=json_bool(&j,json_get(&j,0,"available"),0)==1;
    jstring(&j,0,"reason",a->mu.reason,sizeof(a->mu.reason));copy(a->bt.reason,sizeof(a->bt.reason),a->mu.reason);
    int bt=json_get(&j,0,"bt");
    if(bt>=0){
        /* Who was connected before this report: an audio device that is new takes the sound below. */
        char before[BT_DEVICES_MAX][sizeof(a->bt.devices[0].address)];unsigned int before_count=0;
        for(unsigned int n=0;n<a->bt.count&&before_count<BT_DEVICES_MAX;n++)if(a->bt.devices[n].connected)copy(before[before_count++],sizeof(before[0]),a->bt.devices[n].address);
        bool reported=json_bool(&j,json_get(&j,bt,"powered"),0)==1;
        if(a->bt.power_wanted&&(reported==(a->bt.power_wanted==2)||milliseconds()>=a->bt.power_until))a->bt.power_wanted=0;
        a->bt.powered=a->bt.power_wanted?a->bt.power_wanted==2:reported;a->bt.scanning=json_bool(&j,json_get(&j,bt,"scanning"),0)==1;
        int list=json_get(&j,bt,"devices");a->bt.count=0;
        if(list>=0)for(int i=list+1;i<json_next(&j,list)&&a->bt.count<BT_DEVICES_MAX;i=json_next(&j,i)){
            BtDevice*d=&a->bt.devices[a->bt.count];memset(d,0,sizeof(*d));
            jstring(&j,i,"address",d->address,sizeof(d->address));jstring(&j,i,"name",d->name,sizeof(d->name));jstring(&j,i,"kind",d->kind,sizeof(d->kind));
            d->paired=json_bool(&j,json_get(&j,i,"paired"),0)==1;d->connected=json_bool(&j,json_get(&j,i,"connected"),0)==1;
            int battery=json_get(&j,i,"battery");uint64_t level=battery>=0&&j.text[j.tokens[battery].start]!='-'?json_uint(&j,battery,UINT64_MAX):UINT64_MAX;
            d->battery=level<=100?(int)level:-1;
            if(d->address[0])a->bt.count++;
            /* The device whose number is shown is paired now: the number is done with (2026-11-22, the owner). */
            if(a->bt.pairing_kind&&d->paired&&d->address[0]&&!strcmp(d->address,a->bt.pairing_address)){a->bt.pairing_kind=0;a->dirty=true;}
        }
        /* Android's way (2026-11-22, the owner: YouTube in the browser stayed on the speaker with the
           headphones connected): headphones that connect take the sound, the player's and the browser's. */
        for(unsigned int n=0;n<a->bt.count;n++){
            const BtDevice*d=&a->bt.devices[n];if(!d->connected||strcmp(d->kind,"audio"))continue;
            bool was=false;for(unsigned int k=0;k<before_count;k++)if(!strcmp(before[k],d->address))was=true;
            if(was||strstr(a->mu.output,d->address))continue;
            char device[96];snprintf(device,sizeof(device),"bluealsa:DEV=%s,PROFILE=a2dp",d->address);media_output(a,device,d->name);break;
        }
    }
    /* A Bluetooth audio device that went away takes the sound back to the phone, and what played pauses
       there rather than going on aloud (Android's "becoming noisy"). */
    if(!strncmp(a->mu.output,"bluealsa",8)){
        bool there=false;for(unsigned int n=0;n<a->bt.count;n++)if(a->bt.devices[n].connected&&strstr(a->mu.output,a->bt.devices[n].address))there=true;
        if(!there){
            media_output(a,"default","");
            if(a->mu.local.playing)media_player_send(a,"pause\n");
            if(a->mu.web.playing){web_send(a,"Jpause");a->mu.web.playing=false;}
        }
    }
    a->dirty=true;
}
static void media_service_read(App*a){
    while(a->mu.svc_fd>=0){
        if(a->mu.svc_len>=sizeof(a->mu.svc_in)-1)a->mu.svc_len=0;
        ssize_t n=recv(a->mu.svc_fd,a->mu.svc_in+a->mu.svc_len,sizeof(a->mu.svc_in)-1-a->mu.svc_len,MSG_DONTWAIT);
        /* The service stopped: what it told is not known any more; it is started again when needed. */
        if(n==0||(n<0&&errno!=EAGAIN&&errno!=EINTR)){close(a->mu.svc_fd);a->mu.svc_fd=-1;a->mu.known=a->mu.available=a->bt.known=a->bt.available=false;a->bt.pairing_kind=0;a->dirty=true;break;}
        if(n<0)break;
        a->mu.svc_len+=(size_t)n;a->mu.svc_in[a->mu.svc_len]=0;
        char*start=a->mu.svc_in,*end;
        while((end=strchr(start,'\n'))){*end=0;media_service_event(a,start);start=end+1;}
        a->mu.svc_len-=(size_t)(start-a->mu.svc_in);memmove(a->mu.svc_in,start,a->mu.svc_len);
    }
}

/* --- the player ---------------------------------------------------------------------------------------------- */
static void media_play_at(App*a,int index,bool paused);
static void media_player_line(App*a,char*line){
    MediaCard*l=&a->mu.local;
    if(!strncmp(line,"state ",6)){
        int playing=0,video=0,w=0,h=0;unsigned long position=0,duration=0;
        char*p;
        if((p=strstr(line,"playing=")))playing=atoi(p+8);
        if((p=strstr(line,"position=")))position=strtoul(p+9,NULL,10);
        if((p=strstr(line,"duration=")))duration=strtoul(p+9,NULL,10);
        if((p=strstr(line,"video=")))video=atoi(p+6);
        if((p=strstr(line,"width=")))w=atoi(p+6);
        if((p=strstr(line,"height=")))h=atoi(p+7);
        /* A player that plays what this interface does not know (it started again while the player went on):
           stopped, not left playing out of reach. */
        if(!l->source){if(playing)media_player_send(a,"stop\n");return;}
        l->playing=playing;l->position_ms=(uint32_t)position;l->position_at=a->now;if(duration)l->duration_ms=(uint32_t)duration;
        bool was=a->mu.video;a->mu.video=video;l->video=video;a->mu.src_w=w;a->mu.src_h=h;
        if(video&&!was&&a->screen!=PLAYER)a->mu.pip=true;
        if(!video)a->mu.pip=a->mu.full=false;
        /* One sound at a time is kept by the owner's actions (a start here pauses the page, a page that
           starts pauses the player), never by these reports: a late playing=1 paused a page that had just
           taken the sound, and both stood still (2026-11-22, on the phone). */
        media_choose(a);a->dirty=true;
    }else if(!strncmp(line,"title ",6)){if(line[6]){copy(l->title,sizeof(l->title),line+6);media_choose(a);}}
    else if(!strncmp(line,"artist ",7)){if(line[7]){copy(l->subtitle,sizeof(l->subtitle),line+7);media_choose(a);}}
    /* Under the shade a picture changes nothing drawn: its still, blurred picture stays (2026-11-22). */
    else if(!strncmp(line,"frame ",6)){unsigned int seq=0;int w=0,h=0;if(sscanf(line+6,"%u %d %d",&seq,&w,&h)==3){a->mu.frame_seq=seq;a->mu.frame_w=w;a->mu.frame_h=h;if(!a->qs.visible)a->dirty=true;}}
    else if(!strcmp(line,"ended")){
        l->playing=false;
        int next=a->mu.repeat?a->mu.at:a->mu.at+1;
        if(a->mu.shuffle&&a->mu.count>1)next=(int)((unsigned int)rand()%(unsigned int)a->mu.count);
        if(next<a->mu.count)media_play_at(a,next,false);else{a->mu.video=a->mu.pip=a->mu.full=false;l->position_ms=l->duration_ms;a->mu.ended=true;}
        media_choose(a);a->dirty=true;
    }else if(!strncmp(line,"error ",6)){media_tell(a,line+6);}
}
static void media_player_read(App*a){
    while(a->mu.player_fd>=0){
        if(a->mu.pl_len>=sizeof(a->mu.pl_in)-1)a->mu.pl_len=0;
        char cmsg[CMSG_SPACE(sizeof(int))];struct iovec io={a->mu.pl_in+a->mu.pl_len,sizeof(a->mu.pl_in)-1-a->mu.pl_len};
        struct msghdr msg={.msg_iov=&io,.msg_iovlen=1,.msg_control=cmsg,.msg_controllen=sizeof(cmsg)};
        ssize_t n=recvmsg(a->mu.player_fd,&msg,MSG_DONTWAIT|MSG_CMSG_CLOEXEC);
        if(n==0||(n<0&&errno!=EAGAIN&&errno!=EINTR)){close(a->mu.player_fd);a->mu.player_fd=-1;a->mu.local.playing=false;a->mu.video=a->mu.pip=a->mu.full=false;media_choose(a);break;}
        if(n<0)break;
        struct cmsghdr*c=CMSG_FIRSTHDR(&msg);
        if(c&&c->cmsg_level==SOL_SOCKET&&c->cmsg_type==SCM_RIGHTS){
            int fd;memcpy(&fd,CMSG_DATA(c),sizeof(int));
            if(a->mu.shm){munmap(a->mu.shm,MEDIA_SHM_BYTES);a->mu.shm=NULL;}
            void*map=mmap(NULL,MEDIA_SHM_BYTES,PROT_READ,MAP_SHARED,fd,0);if(map!=MAP_FAILED)a->mu.shm=map;
            close(fd);a->mu.asked_w=a->mu.asked_h=-1;
            if(a->mu.pending_play){a->mu.pending_play=false;media_play_at(a,a->mu.at,false);}
        }
        a->mu.pl_len+=(size_t)n;a->mu.pl_in[a->mu.pl_len]=0;
        char*start=a->mu.pl_in,*end;
        while((end=strchr(start,'\n'))){*end=0;if(strcmp(start,"shm"))media_player_line(a,start);start=end+1;}
        a->mu.pl_len-=(size_t)(start-a->mu.pl_in);memmove(a->mu.pl_in,start,a->mu.pl_len);
    }
}
/* The size the player scales pictures to: the window over the interface, the whole panel, the player's
   own card, or none (sound only) while no picture shows. */
static void media_frame_size(App*a,int w,int h){
    if(w||h)a->mu.frame_wanted=true;
    if(a->mu.player_fd<0||(w==a->mu.asked_w&&h==a->mu.asked_h))return;
    char line[48];snprintf(line,sizeof(line),"video %d %d\n",w,h);media_player_send(a,line);a->mu.asked_w=w;a->mu.asked_h=h;
}
static const FileVolume*media_volume(const App*a,const char*id){
    for(int n=0;n<a->volume_count;n++)if(!strcmp(a->volumes[n].id,id)&&a->volumes[n].mounted)return &a->volumes[n];
    return NULL;
}
static void media_play_at(App*a,int index,bool paused){
    if(index<0||index>=a->mu.count)return;
    a->mu.at=index;const MediaItem*m=&a->mu.queue[index];MediaCard*l=&a->mu.local;
    l->source=MEDIA_LOCAL;media_copy(l->title,sizeof(l->title),m->name);
    const FileVolume*v=media_volume(a,m->volume);
    copy(l->subtitle,sizeof(l->subtitle),tr("Local file"));
    l->position_ms=0;l->duration_ms=0;l->position_at=a->now;l->video=m->video;l->playing=false;a->mu.ended=false;media_choose(a);
    if(!v){media_tell(a,tr("The card of this file is not mounted"));return;}
    if(a->mu.player_fd<0||!a->mu.shm){a->mu.pending_play=true;media_link(a,true);a->dirty=true;return;}
    char full[PATH_LEN*2];snprintf(full,sizeof(full),"%s%s",v->mountpoint,m->path);
    /* Beside an operation a file is read only where storage is shared: one that holds it alone keeps it
       (2026-11-22, the owner), and the player says why instead of waiting. */
    if(a->job.pid&&!ui_free(a)&&!storage_readable(a)){media_tell(a,tr("The operation holds storage alone: play this file when it ends."));return;}
    int fd=open(full,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0){media_tell(a,tr("This file cannot be opened"));return;}
    const char*line=paused?"openfd-paused\n":"openfd\n";
    char cmsg[CMSG_SPACE(sizeof(int))];memset(cmsg,0,sizeof(cmsg));struct iovec io={(void*)line,strlen(line)};
    struct msghdr msg={.msg_iov=&io,.msg_iovlen=1,.msg_control=cmsg,.msg_controllen=sizeof(cmsg)};
    struct cmsghdr*c=CMSG_FIRSTHDR(&msg);c->cmsg_level=SOL_SOCKET;c->cmsg_type=SCM_RIGHTS;c->cmsg_len=CMSG_LEN(sizeof(int));memcpy(CMSG_DATA(c),&fd,sizeof(int));
    if(sendmsg(a->mu.player_fd,&msg,MSG_NOSIGNAL)<0){close(a->mu.player_fd);a->mu.player_fd=-1;}
    close(fd);l->playing=!paused;a->mu.asked_w=a->mu.asked_h=-1;
    if(!paused){a->mu.local_started_at=a->now?a->now:1;if(a->mu.web.playing){web_send(a,"Jpause");a->mu.web.playing=false;}}
    media_choose(a);a->dirty=true;
}
static bool media_name(const char*name,bool*video){
    static const char*const audio[]={".mp3",".m4a",".aac",".flac",".ogg",".oga",".opus",".wav",".alac",".wma"};
    static const char*const pictures[]={".mp4",".m4v",".mkv",".webm",".mov",".avi",".ts",".3gp"};
    for(size_t k=0;k<sizeof(audio)/sizeof(*audio);k++)if(file_name_ends(name,audio[k])){*video=false;return true;}
    for(size_t k=0;k<sizeof(pictures)/sizeof(*pictures);k++)if(file_name_ends(name,pictures[k])){*video=true;return true;}
    return false;
}
/* A file of Files into the queue; PLAY: it plays now. */
static void media_enqueue(App*a,const char*volume,const char*path,const char*name,bool play){
    bool video=false;if(!media_name(name,&video))return;
    if(a->mu.count>=MEDIA_QUEUE_MAX){memmove(&a->mu.queue[0],&a->mu.queue[1],sizeof(MediaItem)*(MEDIA_QUEUE_MAX-1));a->mu.count--;if(a->mu.at>0)a->mu.at--;}
    MediaItem*m=&a->mu.queue[a->mu.count++];memset(m,0,sizeof(*m));
    media_copy(m->name,sizeof(m->name),name);media_copy(m->volume,sizeof(m->volume),volume);media_copy(m->path,sizeof(m->path),path);m->video=video;
    if(play)media_play_at(a,a->mu.count-1,false);
    else{char note[96];snprintf(note,sizeof(note),"%s",tr("Added to the queue"));toast(a,note);}
}
/* A control of the shade's card, for the one it shows: the player's file or the browser's page. */
static void player_command(App*a,const char*command,uint32_t value){
    if(a->media.source==MEDIA_BROWSER){
        a->mu.web=a->media;
        char line[48];/* J: the session's media op (D and M are a finger's down and move) */
        if(!strcmp(command,"seek"))snprintf(line,sizeof(line),"Jseek %u",value);else snprintf(line,sizeof(line),"J%s",command);
        web_send(a,line);
        if(!strcmp(command,"play")&&a->mu.local.playing){media_player_send(a,"pause\n");a->mu.local.playing=false;}
        media_choose(a);return;
    }
    if(a->media.source==MEDIA_LOCAL)a->mu.local=a->media;
    MediaCard*l=&a->mu.local;
    if(!strcmp(command,"previous")){
        if(media_position_of(a,l)>3000||a->mu.at==0){media_player_send(a,"seek 0\n");l->position_ms=0;l->position_at=a->now;}
        else media_play_at(a,a->mu.at-1,false);
    }else if(!strcmp(command,"next")){if(a->mu.at+1<a->mu.count)media_play_at(a,a->mu.at+1,false);}
    else if(!strcmp(command,"seek")){char line[32];snprintf(line,sizeof(line),"seek %u\n",value);media_player_send(a,line);}
    else if(!strcmp(command,"play")||!strcmp(command,"pause")){
        /* The player closed a file that played to its end: Play starts it again. */
        if(!strcmp(command,"play")&&(a->mu.player_fd<0||a->mu.ended)&&a->mu.count){media_play_at(a,a->mu.at,false);return;}
        char line[16];snprintf(line,sizeof(line),"%s\n",command);media_player_send(a,line);
        if(!strcmp(command,"play")){a->mu.local_started_at=a->now?a->now:1;if(a->mu.web.playing){web_send(a,"Jpause");a->mu.web.playing=false;}}
    }
    media_choose(a);
}
/* A control of the player's own page or window: always the player's file, whatever the shade shows. */
static void player_local_control(App*a,int action){
    if(!a->mu.local.source){if(action==A_QS_MEDIA_PLAY&&a->mu.count)media_play_at(a,a->mu.at,false);return;}
    a->media=a->mu.local;media_card_control(a,action);
}
static void media_output(App*a,const char*device,const char*name){
    copy(a->mu.output,sizeof(a->mu.output),device);copy(a->mu.output_name,sizeof(a->mu.output_name),name);
    char line[160];snprintf(line,sizeof(line),"output %s\n",device);media_player_send(a,line);a->dirty=true;
    /* The browser's sound follows (sound.py's switch, 2026-11-22): the device's address, or the phone. */
    char address[24]="";const char*dev=strstr(device,"DEV=");
    if(dev){dev+=4;size_t k=0;while(dev[k]&&dev[k]!=','&&k+1<sizeof(address)){address[k]=dev[k];k++;}address[k]=0;}
    char json[96];snprintf(json,sizeof(json),"{\"op\":\"sound-output\",\"bluetooth\":\"%s\"}",address);media_service_send(a,json);
}
/* After each picture of the interface: no view showed the video, so the player stops scaling it
   (its sound goes on). */
static void media_frame_done(App*a){if(!a->mu.frame_wanted&&a->mu.video)media_frame_size(a,0,0);}
/* Once a turn: links and events. A dark panel wants no pictures. */
static void media_pump(App*a){
    if(a->mu.web_changed){
        a->mu.web_changed=false;
        /* A page that starts to play takes the sound, unless the owner started the player just now:
           then the page is the one that stops. */
        if(a->mu.web.playing&&a->mu.local.playing){
            if(a->mu.local_started_at&&a->now-a->mu.local_started_at<2000){web_send(a,"Jpause");a->mu.web.playing=false;}
            else{media_player_send(a,"pause\n");a->mu.local.playing=false;}
        }
        media_choose(a);
    }
    bool needed=a->screen==PLAYER||a->screen==BT_PAGE||a->mu.count>0;
    media_link(a,needed);
    media_service_read(a);media_player_read(a);
    if(a->display_blank_known&&a->display_blanked&&a->mu.video&&a->mu.asked_w)media_frame_size(a,0,0);
}
#endif
