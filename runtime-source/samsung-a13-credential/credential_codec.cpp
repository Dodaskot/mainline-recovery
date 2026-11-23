// SPDX-License-Identifier: MIT
#include "credential_codec.h"
namespace sp {
namespace {
constexpr size_t kMaximum=256;
struct Scratch {
    uint32_t cp=0, minimum=0, seen=0;
    unsigned continuation=0;
    int previous=-1, cell=0, row=0, column=0, dr=0, dc=0, mid=0;
    ~Scratch(){g3::wipe(this,sizeof(*this));}
};
bool append_unit(uint32_t unit,g3::Secret* out) {
    uint8_t bytes[2]={uint8_t(unit>>8),uint8_t(unit)};
    bool ok=out->append(bytes+(unit<=255?1:0),unit<=255?1:2,kMaximum);
    g3::wipe(bytes,sizeof(bytes));return ok;
}
bool canonical_pattern(const g3::Secret& in) {
    if(in.bytes.size()<4||in.bytes.size()>9)return false;
    Scratch s;
    for(uint8_t point:in.bytes) {
        if(point<'1'||point>'9')return false;
        s.cell=int(point-'1');
        if(s.seen&(1U<<s.cell))return false;
        if(s.previous>=0) {
            s.row=s.previous/3;s.column=s.previous%3;
            s.dr=s.cell/3-s.row;s.dc=s.cell%3-s.column;
            // Exact Samsung LockPatternView gap rule. A missing point is
            // rejected here; the UI is responsible for expanding gestures.
            if((s.dr==2||s.dr==-2)&&s.dc!=1&&s.dc!=-1)s.row+=s.dr>0?1:-1;
            if((s.dc==2||s.dc==-2)&&s.dr!=1&&s.dr!=-1)s.column+=s.dc>0?1:-1;
            s.mid=s.row*3+s.column;
            if(!(s.seen&(1U<<s.mid)))return false;
        }
        s.seen|=1U<<s.cell;s.previous=s.cell;
    }
    return true;
}
bool password(const g3::Secret& in,g3::Secret* out) {
    Scratch s;
    for(size_t i=0;i<in.bytes.size();) {
        uint8_t lead=in.bytes[i++];
        if(lead<0x80){s.cp=lead;s.continuation=0;s.minimum=0;}
        else if(lead>=0xc2&&lead<=0xdf){s.cp=lead&0x1f;s.continuation=1;s.minimum=0x80;}
        else if(lead>=0xe0&&lead<=0xef){s.cp=lead&0x0f;s.continuation=2;s.minimum=0x800;}
        else if(lead>=0xf0&&lead<=0xf4){s.cp=lead&7;s.continuation=3;s.minimum=0x10000;}
        else return false;
        if(s.continuation>in.bytes.size()-i)return false;
        while(s.continuation>0) {
            --s.continuation;
            uint8_t b=in.bytes[i++];
            if((b&0xc0)!=0x80)return false;
            s.cp=(s.cp<<6)|(b&0x3f);
        }
        if(s.cp<s.minimum||s.cp>0x10ffff||(s.cp>=0xd800&&s.cp<=0xdfff))return false;
        // Java CharSequence.charAt returns UTF-16 units. Samsung writes a
        // high byte only when that unit exceeds255, then always its low byte.
        if(s.cp<=0xffff) {
            if(!append_unit(s.cp,out))return false;
        } else {
            s.cp-=0x10000;
            if(!append_unit(0xd800+(s.cp>>10),out)||
               !append_unit(0xdc00+(s.cp&0x3ff),out))return false;
        }
    }
    return true;
}
}
bool encode_samsung_credential(unsigned type,const g3::Secret& input,g3::Secret* output) {
    if(!output||output==&input)return false;
    output->clear();
    if(input.bytes.empty()||input.bytes.size()>kMaximum)return false;
    // Conversion never expands valid UTF-8. Reserve once so decoded secret
    // prefixes cannot remain in a freed intermediate vector allocation.
    output->bytes.reserve(input.bytes.size());
    bool ok=false;
    if(type==1)ok=canonical_pattern(input)&&output->append(input.bytes.data(),input.bytes.size(),kMaximum);
    else if(type==4)ok=password(input,output);
    if(!ok)output->clear();
    return ok;
}
}
