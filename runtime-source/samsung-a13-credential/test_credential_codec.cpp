// Synthetic public fixtures only; no phone, Gatekeeper, or user input.
#include "credential_codec.h"
#include <cstdio>
#include <cstdlib>
#include <initializer_list>
#include <cstring>
static unsigned checks=0;
static void check(bool v){checks++;if(!v){std::fprintf(stderr,"codec check %u failed\n",checks);std::abort();}}
static void vector(unsigned type,std::initializer_list<uint8_t> in,std::initializer_list<uint8_t> expected){
 g3::Secret source,out;source.bytes.assign(in);out.bytes.assign({0xaa});
 check(sp::encode_samsung_credential(type,source,&out));check(out.bytes.size()==expected.size());
 check(!std::memcmp(out.bytes.data(),expected.begin(),expected.size()));
}
static void reject(unsigned type,std::initializer_list<uint8_t> in){
 g3::Secret source,out;source.bytes.assign(in);out.bytes.assign({0xaa});
 check(!sp::encode_samsung_credential(type,source,&out));check(out.bytes.empty());
}
static bool pattern(const char* p){
 g3::Secret in,out;in.bytes.assign(p,p+std::strlen(p));
 bool ok=sp::encode_samsung_credential(1,in,&out);
 check(ok?in.bytes==out.bytes:out.bytes.empty());return ok;
}
static uint64_t counts[10]={};
static void enumerate(g3::Secret& in,unsigned used){
 if(in.bytes.size()>=4){g3::Secret out;if(sp::encode_samsung_credential(1,in,&out))counts[in.bytes.size()]++;}
 if(in.bytes.size()==9)return;
 for(unsigned p=0;p<9;p++)if(!(used&(1U<<p))){
  in.bytes.push_back(uint8_t('1'+p));enumerate(in,used|(1U<<p));in.bytes.pop_back();
 }
}
int main(){
 vector(4,{'p','a','s','s','W','0','r','d','!'}, {'p','a','s','s','W','0','r','d','!'});
 vector(4,{0xc3,0xa9},{0xe9});
 vector(4,{0xc4,0x80},{0x01,0x00});
 vector(4,{0xd0,0x90,0xd0,0x87,0xd1,0x8f},{0x04,0x10,0x04,0x07,0x04,0x4f});
 vector(4,{0xe2,0x82,0xac},{0x20,0xac});
 vector(4,{0xf0,0x9f,0x98,0x80},{0xd8,0x3d,0xde,0x00});
 vector(4,{0x41,0x00,0x42},{0x41,0x00,0x42});
 vector(4,{0xf4,0x8f,0xbf,0xbf},{0xdb,0xff,0xdf,0xff});
 reject(4,{});reject(4,{0xc0,0x80});reject(4,{0xc1,0xbf});
 reject(4,{0xed,0xa0,0x80});reject(4,{0xe2,0x82});reject(4,{0x80});
 reject(4,{0xf4,0x90,0x80,0x80});reject(4,{0xf5,0x80,0x80,0x80});
 reject(4,{0xe0,0x9f,0x80});reject(4,{0xf0,0x8f,0xbf,0xbf});reject(4,{0xc2,0x20});
 reject(3,{'1','2','3','4'});reject(0,{'1','2','3','4'});
 check(pattern("12369"));check(pattern("1862"));check(pattern("5196"));check(pattern("123456789"));
 check(!pattern("1396"));check(!pattern("1937"));check(!pattern("1512"));check(!pattern("123"));
 check(!pattern("1230"));check(!pattern("123:"));reject(1,{0,1,2,5,8});
 g3::Secret a,b;a.bytes.assign(256,'x');check(sp::encode_samsung_credential(4,a,&b));check(a.bytes==b.bytes);
 a.bytes.push_back('x');check(!sp::encode_samsung_credential(4,a,&b));check(b.bytes.empty());
 a.bytes.assign(4,'x');check(!sp::encode_samsung_credential(4,a,&a));check(a.bytes.size()==4);
 check(!sp::encode_samsung_credential(4,a,nullptr));
 g3::Secret sequence;enumerate(sequence,0);
 const uint64_t expected[10]={0,0,0,0,1624,7152,26016,72912,140704,140704};
 uint64_t total=0;for(unsigned n=4;n<=9;n++){check(counts[n]==expected[n]);total+=counts[n];}
 check(total==389112);
 std::printf("Samsung credential codec PASS checks=%u canonical_patterns=%llu\n",checks,(unsigned long long)total);
}
