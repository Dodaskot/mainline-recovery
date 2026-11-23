/* SPDX-License-Identifier: MIT — Bluetooth's page (2026-11-22, the owner; the pictures of the request are
 * the reference: "Aurora · devices", "Daylight · devices", "Aurora · connecting"). media_service.py does
 * the work through BlueZ; this page shows what it reports and asks it. */
#ifndef A22X_BLUETOOTH_UI_H
#define A22X_BLUETOOTH_UI_H

static int bt_glyph(const BtDevice*d){
    if(!strcmp(d->kind,"keyboard"))return ICON_KEYBOARD_BT;
    if(!strcmp(d->kind,"mouse"))return ICON_MOUSE;
    if(!strcmp(d->kind,"phone"))return ICON_PHONE_BT;
    if(!strcmp(d->kind,"audio"))return strcasestr(d->name,"buds")?ICON_EARBUDS:(strcasestr(d->name,"flip")||strcasestr(d->name,"speaker")||strcasestr(d->name,"jbl"))?ICON_SPEAKER_BOX:ICON_HEADPHONES;
    return ICON_BLUETOOTH;
}
static const char*bt_kind_label(const BtDevice*d){
    return !strcmp(d->kind,"audio")?"Audio":!strcmp(d->kind,"keyboard")?"Keyboard":!strcmp(d->kind,"mouse")?"Mouse":!strcmp(d->kind,"phone")?"Phone":"Device";
}
static void bt_send(App*a,const char*op,const char*address){
    char line[160];
    if(address)snprintf(line,sizeof(line),"{\"op\":\"%s\",\"address\":\"%s\"}",op,address);else snprintf(line,sizeof(line),"{\"op\":\"%s\"}",op);
    media_service_send(a,line);a->dirty=true;
}
static void bt_power(App*a,bool on){
    if(a->mu.svc_fd<0){media_link(a,true);toast(a,"Starting Bluetooth...");return;}
    media_service_send(a,on?"{\"op\":\"bt-power\",\"on\":true}":"{\"op\":\"bt-power\",\"on\":false}");a->bt.powered=on;a->dirty=true;
    /* The switch stays as set while the adapter changes (2026-11-22, the owner's video: on, off, on). */
    a->bt.power_wanted=on?2:1;a->bt.power_until=milliseconds()+6000;
}
static void bt_switch(App*a,int x,int y,bool on,int action,bool enabled){
    Rect r={x,y,104,58};rounded(a,r,29,on?ORANGE:PANEL2);vector_circle(a,on?x+75:x+29,y+29,22,22,on?ui_theme->on_accent:MUTED);
    register_button(a,(Rect){x-20,y-20,144,98},action,enabled,0);
}
static int bt_row(App*a,int y,const BtDevice*d,int index,const char*status){
    Rect r={28,y,664,112};surface(a,r,26,PANEL,A_BT_DEVICE+index);
    gradient(a,(Rect){48,y+24,64,64},32,PANEL2,PANEL2);icon(a,bt_glyph(d),60,y+36,40,TEXT);
    raw_text(true);ellipsis(a,132,y+(status?18:34),480,1,TEXT,d->name);raw_text(false);
    if(status){raw_text(true);ellipsis(a,132,y+64,480,0,MUTED,status);raw_text(false);}
    icon(a,ICON_CHEVRON,636,y+40,32,MUTED);register_button(a,r,A_BT_DEVICE+index,true,0);
    return 124;
}
static void render_bt_pairing(App*a);
static void render_bt_sheet(App*a);
static void render_bluetooth(App*a){
    heading(a,"Bluetooth","Headphones, keyboards and other devices",true);
    int y=236-(int)a->page_scroll;a->clip_active=true;a->clip=page_viewport(a);
    bool ready=a->bt.known&&a->bt.available;
    {Rect r={28,y,664,112};rounded(a,r,30,PANEL);icon(a,ICON_BLUETOOTH,52,y+32,48,TEXT);text(a,124,y+36,1,TEXT,"Bluetooth");
     bt_switch(a,568,y+27,ready&&a->bt.powered,A_BT_TOGGLE,ready);}
    y+=128;
    if(!ready){
        const char*why=a->mu.progress[0]?a->mu.progress:(a->bt.reason[0]?a->bt.reason:tr("Starting Bluetooth..."));
        y+=text_tile(a,y,0,a->bt.reason[0]&&!a->mu.progress[0]?ORANGE:MUTED,why,4)+16;
    }else if(a->bt.powered){
        for(unsigned int n=0;n<a->bt.count;n++){
            const BtDevice*d=&a->bt.devices[n];if(!d->connected)continue;
            Rect r={28,y,664,168};rounded(a,r,30,ORANGE_DARK);
            gradient(a,(Rect){48,y+50,72,72},36,PANEL,PANEL);icon(a,bt_glyph(d),64,y+66,40,ORANGE);
            text(a,140,y+20,0,ORANGE,"CONNECTED");raw_text(true);ellipsis(a,140,y+56,340,1,TEXT,d->name);raw_text(false);
            char line[64];if(d->battery>=0)snprintf(line,sizeof(line),"%s  ·  %d%%",tr(bt_kind_label(d)),d->battery);else copy(line,sizeof(line),tr(bt_kind_label(d)));
            raw_text(true);text(a,140,y+108,0,MUTED,line);raw_text(false);
            button(a,(Rect){488,y+90,188,64},"Disconnect",A_BT_DISCONNECT+(int)n,true,false,0);
            y+=184;
        }
        int saved=0;for(unsigned int n=0;n<a->bt.count;n++)saved+=a->bt.devices[n].paired&&!a->bt.devices[n].connected;
        if(saved){text(a,40,y+8,0,ORANGE,"SAVED");y+=52;
            for(unsigned int n=0;n<a->bt.count;n++){const BtDevice*d=&a->bt.devices[n];if(d->paired&&!d->connected)y+=bt_row(a,y,d,(int)n,tr("Not connected"));}}
        text(a,40,y+30,0,ORANGE,"AVAILABLE DEVICES");
        button(a,(Rect){476,y+8,216,72},a->bt.scanning?"Searching...":"Search",A_BT_SCAN,true,false,0);
        y+=100;int found=0;
        for(unsigned int n=0;n<a->bt.count;n++){const BtDevice*d=&a->bt.devices[n];if(!d->paired&&!d->connected){y+=bt_row(a,y,d,(int)n,NULL);found++;}}
        if(!found){wrapped(a,52,y+8,616,0,MUTED,a->bt.scanning?"Looking for devices. Put a device into pairing mode.":"Tap Search, and put a device into pairing mode.",3);y+=110;}
    }else{wrapped(a,52,y+8,616,0,MUTED,"Turn Bluetooth on to use headphones, keyboards and mice.",3);y+=110;}
    text(a,44,y+30,0,MUTED,"This device: Mainline Recovery");y+=90;
    a->page_content=y+(int)a->page_scroll-236;a->clip_active=false;
    if(a->page_scroll>page_max_scroll(a)){a->page_scroll=page_max_scroll(a);a->dirty=true;}
    if(a->mu.error[0]&&a->now<a->mu.error_until){text_tile(a,1370,0,ORANGE,a->mu.error,2);}
    if(a->mu.device_sheet)render_bt_sheet(a);
}
/* What can be done with one device. */
static void render_bt_sheet(App*a){
    if(a->mu.device_index<0||(unsigned int)a->mu.device_index>=a->bt.count){a->mu.device_sheet=false;return;}
    const BtDevice*d=&a->bt.devices[a->mu.device_index];
    for(int n=0;n<a->button_count;n++)a->buttons[n].enabled=false;
    veil(a,(Rect){0,0,CW,CH},0,0,110);
    int h=d->paired?440:330;Rect sheet={0,CH-h,CW,h};rounded(a,(Rect){0,sheet.y,CW,h+40},36,BG);rounded(a,(Rect){0,sheet.y,CW,h+40},36,PANEL);
    register_button(a,(Rect){0,0,CW,sheet.y},A_BT_SHEET_CLOSE,true,0);  /* a touch above it closes it */
    icon(a,bt_glyph(d),40,sheet.y+36,48,ORANGE);raw_text(true);ellipsis(a,108,sheet.y+40,580,1,TEXT,d->name);raw_text(false);
    int y=sheet.y+120;
    if(d->paired){
        button(a,(Rect){28,y,664,88},d->connected?"Disconnect":"Connect",d->connected?A_BT_DISCONNECT+a->mu.device_index:A_BT_CONNECT,true,true,0);y+=104;
        button(a,(Rect){28,y,664,88},"Forget this device",A_BT_FORGET,true,false,0);y+=104;
    }else{button(a,(Rect){28,y,664,88},"Pair",A_BT_CONNECT,true,true,0);y+=104;}
    button(a,(Rect){28,y,664,88},"Cancel",A_BT_SHEET_CLOSE,true,false,0);
}
/* A device asks: a number to compare, or to type on a keyboard (the reference's "Connect a keyboard?"). */
static void render_bt_pairing(App*a){
    if(!a->bt.pairing_kind)return;
    for(int n=0;n<a->button_count;n++)a->buttons[n].enabled=false;
    if(!a->qs.backdrop)a->qs.backdrop=malloc((size_t)NW*NH*sizeof(uint32_t));
    if(a->qs.backdrop){canvas_blur(a->qs.backdrop,a->pixels);memcpy(a->pixels,a->qs.backdrop,(size_t)NW*NH*sizeof(uint32_t));}
    veil(a,(Rect){0,0,CW,CH},0,BG,120);
    bool keyboard=a->bt.pairing_kind==2;Rect card={44,420,632,640};
    canvas_shadow(a->pixels,canvas_bounds(a),nx(card.x),nx(card.y),nx(card.x+card.w),nx(card.y+card.h),40.f,0,120);
    rounded(a,card,36,BG);rounded(a,card,36,PANEL);
    gradient(a,(Rect){card.x+32,card.y+40,96,96},48,ORANGE_DARK,ORANGE_DARK);icon(a,keyboard?ICON_KEYBOARD_BT:ICON_BLUETOOTH,card.x+56,card.y+64,48,ORANGE);
    wrapped(a,card.x+152,card.y+40,card.w-180,2,TEXT,keyboard?"Connect the keyboard?":"Pair this device?",2);
    raw_text(true);ellipsis(a,card.x+152,card.y+150,card.w-180,1,MUTED,a->bt.pairing_name);raw_text(false);
    wrapped(a,card.x+32,card.y+214,card.w-64,0,TEXT,keyboard?"Type this code on the keyboard and press Enter":"Check that the device shows the same code",2);
    Rect code={card.x+32,card.y+300,card.w-64,132};rounded(a,code,28,PANEL2);
    char shown[16];size_t len=strlen(a->bt.pairing_passkey);if(len==6)snprintf(shown,sizeof(shown),"%.3s %.3s",a->bt.pairing_passkey,a->bt.pairing_passkey+3);else copy(shown,sizeof(shown),a->bt.pairing_passkey);
    raw_text(true);centered(a,code,3,TEXT,shown);raw_text(false);
    int y=card.y+card.h-120;
    button(a,(Rect){card.x+32,y,(card.w-80)/2,88},"Cancel",A_BT_PAIR_NO,true,false,0);
    if(keyboard)button(a,(Rect){card.x+48+(card.w-80)/2,y,(card.w-80)/2,88},"Waiting...",A_BT_PAIR_NO,false,true,0);
    else button(a,(Rect){card.x+48+(card.w-80)/2,y,(card.w-80)/2,88},"Pair",A_BT_PAIR_YES,true,true,0);
}
static bool bluetooth_action(App*a,int id){
    if(id==A_BLUETOOTH){a->page_scroll=0;a->mu.output_sheet=false;media_link(a,true);screen(a,BT_PAGE);if(a->bt.powered&&a->mu.svc_fd>=0)media_service_send(a,"{\"op\":\"bt-scan\",\"on\":true}");return true;}
    if(id==A_BACK&&a->screen==BT_PAGE){
        if(a->mu.device_sheet){a->mu.device_sheet=false;a->dirty=true;return true;}
        if(a->bt.scanning)media_service_send(a,"{\"op\":\"bt-scan\",\"on\":false}");
        screen(a,came_from(a,HOME));return true;
    }
    if(id==A_BT_TOGGLE){bt_power(a,!a->bt.powered);return true;}
    if(id==A_BT_SCAN){media_service_send(a,a->bt.scanning?"{\"op\":\"bt-scan\",\"on\":false}":"{\"op\":\"bt-scan\",\"on\":true}");return true;}
    if(id>=A_BT_DEVICE&&id<A_BT_DEVICE+BT_DEVICES_MAX){
        unsigned int n=(unsigned int)(id-A_BT_DEVICE);if(n>=a->bt.count)return true;
        /* An unknown device pairs at once; a saved one offers connect and forget. */
        if(!a->bt.devices[n].paired){bt_send(a,"bt-pair",a->bt.devices[n].address);toast(a,"Pairing...");}
        else{a->mu.device_sheet=true;a->mu.device_index=(int)n;a->dirty=true;}
        return true;
    }
    if(id>=A_BT_DISCONNECT&&id<A_BT_DISCONNECT+BT_DEVICES_MAX){unsigned int n=(unsigned int)(id-A_BT_DISCONNECT);if(n<a->bt.count)bt_send(a,"bt-disconnect",a->bt.devices[n].address);a->mu.device_sheet=false;return true;}
    if(id==A_BT_CONNECT&&a->mu.device_index>=0&&(unsigned int)a->mu.device_index<a->bt.count){
        const BtDevice*d=&a->bt.devices[a->mu.device_index];bt_send(a,d->paired?"bt-connect":"bt-pair",d->address);a->mu.device_sheet=false;toast(a,d->paired?"Connecting...":"Pairing...");return true;}
    if(id==A_BT_FORGET&&a->mu.device_index>=0&&(unsigned int)a->mu.device_index<a->bt.count){bt_send(a,"bt-remove",a->bt.devices[a->mu.device_index].address);a->mu.device_sheet=false;return true;}
    if(id==A_BT_SHEET_CLOSE){a->mu.device_sheet=false;a->dirty=true;return true;}
    if(id==A_BT_PAIR_YES||id==A_BT_PAIR_NO){
        bool yes=id==A_BT_PAIR_YES;
        media_service_send(a,yes?"{\"op\":\"bt-answer\",\"accept\":true}":"{\"op\":\"bt-answer\",\"accept\":false}");
        a->bt.pairing_kind=0;a->dirty=true;return true;
    }
    return false;
}
#endif
