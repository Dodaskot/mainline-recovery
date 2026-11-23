// Synthetic pipe/EOF/type-binding fixtures; never actual credentials.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "credential_codec.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>
static unsigned checks=0;
static void check(bool v){checks++;if(!v){std::fprintf(stderr,"frame check %u failed\n",checks);std::abort();}}
static void u32(std::vector<uint8_t>& b,uint32_t n){for(unsigned i=0;i<4;i++)b.push_back(uint8_t(n>>(8*i)));}
static std::vector<uint8_t> frame(unsigned type,const std::vector<uint8_t>& body,bool typed=true){
 std::vector<uint8_t>b;
 if(typed){b.insert(b.end(),{'A','2','2','C'});u32(b,type);}
 u32(b,body.size());b.insert(b.end(),body.begin(),body.end());return b;
}
static void run(unsigned actual,std::vector<uint8_t> bytes,bool accept,std::vector<uint8_t> expected={}){
 int fd[2];check(pipe2(fd,O_CLOEXEC)==0);check(write(fd[1],bytes.data(),bytes.size())==ssize_t(bytes.size()));close(fd[1]);
 g3::Secret out;out.bytes.assign({0xaa});check(sp::read_samsung_credential_frame(fd[0],actual,&out)==accept);
 check(out.bytes==expected);close(fd[0]);
}
int main(){
 run(4,frame(4,{'p','a','s','s'},false),true,{'p','a','s','s'});
 run(4,frame(4,{'p','a','s','s'}),true,{'p','a','s','s'});
 run(1,frame(1,{'1','2','3','6','9'}),true,{'1','2','3','6','9'});
 run(4,frame(4,{0xc4,0x80}),true,{1,0});
 run(1,frame(4,{'1','2','3','6','9'},false),false);
 run(4,frame(1,{'1','2','3','6','9'}),false);
 run(1,frame(4,{'1','2','3','6','9'}),false);
 run(3,frame(3,{'1','2','3','4'}),false);
 run(1,frame(1,{0,1,2,5,8}),false);
 run(1,frame(1,{'1','3','9','6'}),false);
 run(4,frame(4,{0xed,0xa0,0x80}),false);
 run(4,frame(4,{}),false);
 run(4,frame(4,std::vector<uint8_t>(257,'x')),false);
 auto good=frame(1,{'1','2','3','6','9'});
 for(size_t i=0;i<good.size();i++)run(1,std::vector<uint8_t>(good.begin(),good.begin()+i),false);
 auto extra=good;extra.push_back('x');run(1,extra,false);
 auto twice=good;twice.insert(twice.end(),good.begin(),good.end());run(1,twice,false);
 good[0]='B';run(1,good,false);
 int fds[2];check(pipe2(fds,O_CLOEXEC)==0);g3::Secret out;
 check(!sp::read_samsung_credential_frame(fds[1],4,&out));close(fds[0]);close(fds[1]);
 int file=memfd_create("synthetic-frame",MFD_CLOEXEC);check(file>=0);
 auto body=frame(4,{'p','a','s','s'});check(write(file,body.data(),body.size())==ssize_t(body.size()));check(lseek(file,0,SEEK_SET)==0);
 check(!sp::read_samsung_credential_frame(file,4,&out));close(file);
 check(!sp::read_samsung_credential_frame(-1,4,&out));check(!sp::read_samsung_credential_frame(-1,4,nullptr));
 std::printf("Samsung credential frame PASS checks=%u\n",checks);
}
