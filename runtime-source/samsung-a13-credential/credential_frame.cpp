// SPDX-License-Identifier: MIT
#include "credential_codec.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <time.h>
#include <unistd.h>
namespace sp {
namespace {
int64_t millis(){
    timespec t{};
    if(clock_gettime(CLOCK_MONOTONIC,&t))return -1;
    return int64_t(t.tv_sec)*1000+t.tv_nsec/1000000;
}
bool wait_read(int fd,int64_t end) {
    for(;;){
        int64_t now=millis();if(now<0||now>=end)return false;
        pollfd p{fd,POLLIN,0};
        int n=poll(&p,1,int(end-now));
        if(n<0&&errno==EINTR)continue;
        return n==1&&(p.revents&(POLLIN|POLLHUP))&&!(p.revents&(POLLERR|POLLNVAL));
    }
}
bool take(int fd,uint8_t* out,size_t size,int64_t end){
    size_t at=0;
    while(at<size){
        if(!wait_read(fd,end))return false;
        ssize_t n=read(fd,out+at,size-at);
        if(n<0&&errno==EINTR)continue;
        if(n<=0)return false;
        at+=size_t(n);
    }
    return true;
}
uint32_t le32(const uint8_t* p){
    return uint32_t(p[0])|uint32_t(p[1])<<8|uint32_t(p[2])<<16|uint32_t(p[3])<<24;
}
}
bool read_samsung_credential_frame(int fd,unsigned actual_type,g3::Secret* output){
    if(!output)return false;
    output->clear();
    if(actual_type!=1&&actual_type!=4)return false;
    struct stat st{};struct statfs fs{};int flags=fcntl(fd,F_GETFL);
    if(flags<0||(flags&O_ACCMODE)!=O_RDONLY||fstat(fd,&st)||fstatfs(fd,&fs)||
       !S_ISFIFO(st.st_mode)||uint64_t(fs.f_type)!=0x50495045)return false;
    int64_t start=millis();if(start<0)return false;int64_t end=start+5000;
    uint8_t header[12]={};
    if(!take(fd,header,4,end))return false;
    uint32_t type=4,length=le32(header);
    if(length==0x43323241U){ // "A22C": typed v2. v1 is password-only.
        if(!take(fd,header+4,8,end)){g3::wipe(header,sizeof(header));return false;}
        type=le32(header+4);length=le32(header+8);
    }
    g3::wipe(header,sizeof(header));
    if(type!=actual_type||!length||length>256)return false;
    g3::Secret input;input.bytes.resize(length);
    if(!take(fd,input.bytes.data(),length,end))return false;
    uint8_t extra=0;
    if(!wait_read(fd,end))return false;
    ssize_t eof=read(fd,&extra,1);g3::wipe(&extra,1);
    if(eof!=0)return false;
    return encode_samsung_credential(type,input,output);
}
}
