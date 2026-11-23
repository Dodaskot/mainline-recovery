/* Native theme editor. The draft keeps the full PC palette and original RGB backdrop. */
#define EDITOR_ROLES 55
#define EDITOR_PAGES ((EDITOR_ROLES+7)/8)
static const char*te_label(const char*en,const char*uk,const char*de){return ui_language==1?uk:ui_language==2?de:en;}
static const char*const editor_labels[25][3]={
    {"Background","Тло","Hintergrund"},{"Panel","Картка","Fläche"},{"Raised panel","Піднята картка","Erhöhte Fläche"},
    {"Divider","Розділювач","Trennlinie"},{"Border","Рамка","Rand"},{"Text","Текст","Text"},{"Secondary text","Підпис","Untertitel"},
    {"Accent","Акцент","Akzent"},{"Selection","Виділення","Auswahl"},{"Selection border","Рамка виділення","Auswahlrand"},
    {"Accent text","Текст на акценті","Akzenttext"},{"Icon background","Тло значка","Symbolfläche"},{"Knob","Повзунок","Regler"},
    {"Success","Успіх","Erfolg"},{"Error","Помилка","Fehler"},{"File","Файл","Datei"},{"Link","Посилання","Link"},
    {"Danger background","Тло попередження","Warnfläche"},{"Message","Сповіщення","Meldung"},{"Message text","Текст сповіщення","Meldungstext"},
    {"Shadow","Тінь","Schatten"},{"Banner top","Верх банера","Banner oben"},{"Banner bottom","Низ банера","Banner unten"},
    {"Banner text","Текст банера","Bannertext"},{"Banner subtitle","Підпис банера","Banneruntertitel"}
};
static void editor_name(int role,char*out,size_t size){
    if(role<25){const char*const*l=editor_labels[role];snprintf(out,size,"%s",te_label(l[0],l[1],l[2]));}
    else if(role<37)snprintf(out,size,"%s %d",role<31?te_label("Tile","Плитка","Kachel"):te_label("Tile icon","Значок плитки","Kachelsymbol"),(role-25)%6+1);
    else if(role<39)snprintf(out,size,"%s",role==37?te_label("Terminal background","Тло термінала","Terminalfläche"):te_label("Terminal text","Текст термінала","Terminaltext"));
    else snprintf(out,size,"ANSI %d",role-39);
}
static uint32_t*editor_color(ThemeFileHeader*d,int role){
    if(role<25)return &d->colors[role];
    if(role<31)return &d->tile_fill[role-25];
    if(role<37)return &d->tile_ink[role-31];
    if(role==37)return &d->terminal_bg;
    if(role==38)return &d->terminal_fg;
    return &d->palette[role-39];
}
static float editor_unit(float x){return fmaxf(0,fminf(1,x));}
static uint32_t editor_rgb(float h,float s,float v){
    float hue=h-floorf(h),p=hue*6.f;int i=(int)p;
    float f=p-i,low=v*(1-s),down=v*(1-s*f),up=v*(1-s*(1-f));
    const float rgb[6][3]={{v,up,low},{down,v,low},{low,v,up},{low,down,v},{up,low,v},{v,low,down}};
    return ((uint32_t)lroundf(rgb[i][0]*255)<<16)|((uint32_t)lroundf(rgb[i][1]*255)<<8)|(uint32_t)lroundf(rgb[i][2]*255);
}
static void editor_select(App*a,int role){
    uint32_t c=*editor_color(&a->editor,role);
    float r=(float)(c>>16)/255,g=(float)((c>>8)&255)/255,b=(float)(c&255)/255;
    float v=fmaxf(r,fmaxf(g,b)),d=v-fminf(r,fminf(g,b));
    if(d>0){float h=v==r?(g-b)/d:v==g?(b-r)/d+2:(r-g)/d+4;a->editor_hue=h/6-floorf(h/6);}
    a->editor_value=v;a->editor_sat=v?d/v:0;a->editor_role=role;a->editor_page=role/8;a->dirty=true;
}
static bool editor_name_valid(const char*name){
    return strlen(name)<sizeof(((ThemeFileHeader*)0)->name)&&name[strspn(name," 	")]!=0;
}
static void editor_changed(App*a){
    a->editor_warning[0]=0;a->editor_confirm_contrast=false;a->dirty=true;
}
static bool editor_begin(App*a){
    free(a->editor_pixels);a->editor_pixels=NULL;
    const Theme*t=ui_theme;ThemeFileHeader*d=&a->editor;memset(d,0,sizeof(*d));
    memcpy(d->magic,"A22XTHM1",8);
    d->flags=THEME_FLAG_UI|(t->bento?THEME_FLAG_BENTO:0)|(t->blur<<8)|t->tile_style;
    copy(d->name,sizeof(d->name),te_label("My theme","Моя тема","Mein Thema"));
    for(unsigned int i=0;i<theme_file_count;i++){
        const ThemeFile*file=&theme_files[i];
        if(t!=&file->theme)continue;
        d->flags|=file->header.flags&(THEME_FLAG_LIGHT|THEME_FLAG_TERMINAL);
        size_t prefix=strlen(theme_folders[1]);
        if(!strncmp(file->path,theme_folders[1],prefix)&&file->path[prefix]=='/'){
            copy(d->code,sizeof(d->code),file->header.code);copy(d->name,sizeof(d->name),file->header.name);
            copy(d->note,sizeof(d->note),file->header.note);
        }
        break;
    }
    if(t==&themes[1])d->flags|=THEME_FLAG_LIGHT;
    uint32_t colors[]={t->bg,t->panel,t->panel2,t->line,t->edge,t->text,t->muted,t->accent,t->container,t->container_edge,t->on_accent,t->icon_fill,t->knob,t->green,t->red,t->blue,t->purple,t->danger,t->toast_fill,t->toast_text,t->shadow,t->hero_top,t->hero_bottom,t->hero_text,t->hero_sub};
    memcpy(d->colors,colors,sizeof(colors));memcpy(d->tile_fill,t->tile_fill,sizeof(d->tile_fill));memcpy(d->tile_ink,t->tile_ink,sizeof(d->tile_ink));
    static const uint32_t ansi[16]=TM_ANSI_PALETTE;
    memcpy(d->palette,t->terminal_palette?t->terminal_palette:ansi,sizeof(d->palette));
    d->terminal_bg=t->terminal_bg;d->terminal_fg=t->terminal_fg;
    d->surface_alpha=t->surface_alpha;d->edge_alpha=t->edge_alpha;d->shadow_strength=t->shadow_strength;
    if(t->backdrop){d->image_w=t->backdrop_w?t->backdrop_w:BACKDROP_W;d->image_h=t->backdrop_h?t->backdrop_h:BACKDROP_H;}
    if(d->image_w){
        size_t bytes=(size_t)d->image_w*d->image_h*3;
        a->editor_pixels=malloc(bytes);if(!a->editor_pixels)return false;
        memcpy(a->editor_pixels,t->backdrop,bytes);
    }
    a->editor_hue=0;a->editor_drag=0;a->editor_shape=false;editor_changed(a);editor_select(a,7);return true;
}
/* Two sliding box passes. Radius scales with source width so the preview and wallpaper agree. */
static void editor_blur_line(const uint8_t*src,uint8_t*dst,int n,int step,int radius){
    unsigned sum[3]={0};int count=0;
    for(int i=0;i<=radius&&i<n;i++,count++)for(int k=0;k<3;k++)sum[k]+=src[i*step+k];
    for(int i=0;i<n;i++){
        for(int k=0;k<3;k++)dst[i*step+k]=(uint8_t)(sum[k]/count);
        if(i>=radius){for(int k=0;k<3;k++)sum[k]-=src[(i-radius)*step+k];count--;}
        if(i+radius+1<n){for(int k=0;k<3;k++)sum[k]+=src[(i+radius+1)*step+k];count++;}
    }
}
static uint8_t*editor_blur(const uint8_t*src,int w,int h,unsigned amount){
    if(!amount||!w||!h)return NULL;
    size_t bytes=(size_t)w*h*3;uint8_t*tmp=malloc(bytes),*out=malloc(bytes);
    if(!tmp||!out){free(tmp);free(out);return NULL;}
    int radius=1+(int)(amount*(unsigned)w/1400);
    for(int y=0;y<h;y++)editor_blur_line(src+y*w*3,tmp+y*w*3,w,3,radius);
    for(int x=0;x<w;x++)editor_blur_line(tmp+x*3,out+x*3,h,3*w,radius);
    free(tmp);return out;
}
static bool editor_write(App*a){
    if(snprintf(a->editor_file,sizeof(a->editor_file),"%s/theme-draft-XXXXXX",a->workdir)>=(int)sizeof(a->editor_file)){a->editor_file[0]=0;return false;}
    int fd=mkstemp(a->editor_file);
    if(fd<0){a->editor_file[0]=0;return false;}
    FILE*f=fdopen(fd,"wb");if(!f){close(fd);return false;}
    size_t bytes=(size_t)a->editor.image_w*a->editor.image_h*3;
    bool ok=fwrite(&a->editor,1,sizeof(a->editor),f)==sizeof(a->editor)&&
        (!bytes||(a->editor_pixels&&fwrite(a->editor_pixels,1,bytes,f)==bytes));
    return fclose(f)==0&&ok;
}
static void editor_preview(App*a){
    ThemeFileHeader*d=&a->editor;Rect panel={28,208,664,164};
    gradient(a,panel,18,d->colors[0],d->colors[0]);
    if(d->image_w&&a->editor_pixels){
        enum {W=166,H=41};uint8_t thumb[W*H*3];
        for(int y=0;y<H;y++)for(int x=0;x<W;x++)memcpy(thumb+(y*W+x)*3,a->editor_pixels+
            ((size_t)(y*d->image_h/H)*d->image_w+x*d->image_w/W)*3,3);
        uint8_t*soft=editor_blur(thumb,W,H,(d->flags&THEME_BLUR_MASK)>>8);const uint8_t*src=soft?soft:thumb;
        for(int y=0;y<H;y++)for(int x=0;x<W;x++){const uint8_t*p=src+(y*W+x)*3;
            rectangle(a,(Rect){28+4*x,208+4*y,4,4},((uint32_t)p[0]<<16)|((uint32_t)p[1]<<8)|p[2]);}
        free(soft);
    }
    canvas_shadow(a->pixels,canvas_bounds(a),nx(60),nx(230),nx(654),nx(348),30,d->colors[20],d->shadow_strength);
    glass_panel(a,(Rect){60,230,594,118},20,d->colors[1],d->colors[4],d->surface_alpha,d->edge_alpha);
    text(a,86,268,1,d->colors[5],te_label("Preview","Зразок","Vorschau"));
    gradient(a,(Rect){420,254,208,68},22,d->colors[7],d->colors[7]);
    text(a,442,272,0,d->colors[10],te_label("Select","Вибрати","Auswählen"));
}
static const Rect editor_sv={40,696,640,180},editor_hues={40,896,640,46};
static const unsigned int editor_shifts[]={16,23,29};
static const unsigned int editor_masks[]={127,63,7};
static const int editor_style_max[]={90,42,6};
static const int editor_style_default[]={36,30,0};
static Rect editor_bar(int i){
    return i<4?(Rect){306,966+84*i,374,62}:(Rect){306,744+126*(i-4),374,78};
}
static int editor_style(const ThemeFileHeader*d,int i){
    return theme_style_value(d->flags,editor_shifts[i],editor_masks[i],editor_style_default[i]);
}
static int editor_level(const ThemeFileHeader*d,int i){
    if(i==0)return (255-(int)d->surface_alpha)*100/159;
    if(i==1)return (255-(int)d->edge_alpha)*100/255;
    if(i==2)return (int)d->shadow_strength*100/255;
    return (int)((d->flags&THEME_BLUR_MASK)>>8);
}
static const char*editor_layout_label(const ThemeFileHeader*d){
    return d->flags&THEME_FLAG_BENTO?te_label("Layout: tiles","Макет: плитки","Layout: Kacheln"):te_label("Layout: list","Макет: список","Layout: Liste");
}
static void editor_slider(App*a,Rect r,const char*label,int value,int maximum){
    ellipsis(a,40,r.y+20,263,0,TEXT,label);gradient(a,(Rect){r.x,r.y+26,r.w,10},5,EDGE,EDGE);
    int x=r.x+(r.w-1)*value/maximum;vector_circle(a,x,r.y+31,14,14,ORANGE);
}
static void editor_tile_preview(App*a,const ThemeFileHeader*d,Rect r,int tone,int glyph,const char*label){
    int corner=editor_style(d,0),badge=editor_style(d,1),rim=editor_style(d,2);
    gradient(a,r,corner,d->tile_fill[tone],d->tile_fill[tone]);
    tile_outline(a,r,corner,nx(rim),d->colors[4],255);
    veil(a,(Rect){r.x+24,r.y+30,76,76},badge,d->colors[1],d->surface_alpha);
    icon(a,glyph,r.x+41,r.y+47,42,d->tile_ink[tone]);
    ellipsis(a,r.x+25,r.y+136,r.w-50,1,d->colors[5],label);
}
static void editor_shapes(App*a){
    ThemeFileHeader*d=&a->editor;
    editor_tile_preview(a,d,(Rect){40,442,308,218},0,A_BACKUP,te_label("Backup","Резервна копія","Sicherung"));
    editor_tile_preview(a,d,(Rect){372,442,308,218},1,A_FILES,te_label("Files","Файли","Dateien"));
    static const char*const labels[][3]={
        {"Tile corners","Кути плиток","Kachelecken"},{"Icon corners","Кути значків","Symbolecken"},
        {"Border width","Товщина рамки","Randbreite"}
    };
    for(int i=0;i<3;i++){
        char label[96];int value=editor_style(d,i);
        snprintf(label,sizeof(label),"%s  %d",te_label(labels[i][0],labels[i][1],labels[i][2]),value);
        editor_slider(a,editor_bar(4+i),label,value,editor_style_max[i]);
    }
    button(a,(Rect){40,1136,640,86},editor_layout_label(d),A_TE_LAYOUT,ui_free(a),false,0);
}
static void editor_colors(App*a){
    ThemeFileHeader*d=&a->editor;
    char label[100],name[80];editor_name(a->editor_role,name,sizeof(name));
    snprintf(label,sizeof(label),"%s   #%06X",name,*editor_color(d,a->editor_role));text(a,40,388,1,TEXT,label);
    for(int i=0;i<8;i++){
        int role=a->editor_page*8+i;if(role>=EDITOR_ROLES)break;
        Rect r={40+(i%4)*162,442+(i/4)*72,152,64};uint32_t c=*editor_color(d,role);
        gradient(a,r,14,role==a->editor_role?TEXT:EDGE,role==a->editor_role?TEXT:EDGE);
        gradient(a,(Rect){r.x+5,r.y+5,r.w-10,r.h-10},10,c,c);
        register_button(a,r,A_TE_COLOR+role,ui_free(a),0);
    }
    snprintf(label,sizeof(label),"%s   %d / %d",te_label("Color group","Група кольорів","Farbgruppe"),a->editor_page+1,EDITOR_PAGES);
    button(a,(Rect){40,595,640,72},label,A_TE_PAGE,ui_free(a),false,0);
    for(int i=0;i<80;i++){uint32_t top=editor_rgb(a->editor_hue,i/79.f,1);
        gradient(a,(Rect){40+8*i,696,8,180},0,top,0);
        rectangle(a,(Rect){40+8*i,896,8,46},editor_rgb(i/79.f,1,1));}
    int cx=40+(int)(a->editor_sat*639),cy=696+(int)((1-a->editor_value)*179);
    vector_circle(a,cx,cy,11,5,0);vector_circle(a,cx,cy,9,3,0xffffff);
    int hue=40+(int)(639*a->editor_hue);vector_circle(a,hue,919,12,6,0);vector_circle(a,hue,919,10,3,0xffffff);
    static const char*const titles[4][3]={{"Transparency","Прозорість","Transparenz"},{"Border transparency","Прозорість рамки","Randtransparenz"},{"Shadow","Сила тіні","Schatten"},{"Backdrop blur","Розмиття тла","Hintergrundunschärfe"}};
    for(int i=0;i<4;i++){
        Rect r=editor_bar(i);int level=editor_level(d,i);snprintf(label,sizeof(label),"%s %d%%",te_label(titles[i][0],titles[i][1],titles[i][2]),i==0?(int)lroundf(100.f*(255-d->surface_alpha)/255):level);
        editor_slider(a,r,label,level,100);
    }
}
static void render_theme_editor(App*a){
    heading(a,te_label("Theme editor","Редактор теми","Themeneditor"),NULL,true);
    button(a,(Rect){40,153,308,48},te_label("Colors","Кольори","Farben"),A_TE_COLORS_TAB,ui_free(a)&&a->editor_shape,!a->editor_shape,0);
    button(a,(Rect){372,153,308,48},te_label("Tiles","Плитки","Kacheln"),A_TE_TILES_TAB,ui_free(a)&&!a->editor_shape,a->editor_shape,0);
    editor_preview(a);
    if(a->editor_shape)editor_shapes(a);else editor_colors(a);
    char name[82];
    snprintf(name,sizeof(name),"%s · %s",te_label("Name","Назва","Name"),a->editor.name);
    button(a,(Rect){28,1332,310,88},name,A_TE_NAME,ui_free(a),false,0);
    const char*save=a->editor_confirm_contrast?te_label("Save anyway","Зберегти все одно","Trotzdem speichern"):te_label("Save","Зберегти","Speichern");
    button(a,(Rect){354,1332,338,88},save,A_TE_SAVE,ui_free(a),true,0);
    if(a->editor_warning[0])wrapped(a,40,1430,640,0,ORANGE,a->editor_warning,2);
}
static bool editor_touch(App*a,bool down,int x,int y){
    if(!a->editor_drag){
        if(!down||a->pointer_down||!ui_free(a))return false;
        if(!a->editor_shape&&inside(editor_sv,x,y))a->editor_drag=1;
        else if(!a->editor_shape&&inside(editor_hues,x,y))a->editor_drag=2;
        else for(int i=a->editor_shape?4:0;i<(a->editor_shape?7:4);i++)if(inside(editor_bar(i),x,y))a->editor_drag=3+i;
        if(!a->editor_drag)return false;
        a->pointer_down=true;a->pressed_action=0;
    }
    if(a->editor_drag<=2){
        float u=editor_unit((x-editor_sv.x)/(float)(editor_sv.w-1));
        if(a->editor_drag==1){a->editor_sat=u;a->editor_value=1-editor_unit((y-editor_sv.y)/(float)(editor_sv.h-1));}
        else a->editor_hue=u;
        *editor_color(&a->editor,a->editor_role)=editor_rgb(a->editor_hue,a->editor_sat,a->editor_value);
        if(a->editor_role>=39)a->editor.flags|=THEME_FLAG_TERMINAL;
    }else{
        int i=a->editor_drag-3;Rect r=editor_bar(i);float u=editor_unit((x-r.x)/(float)(r.w-1));
        if(i==0)a->editor.surface_alpha=255-lroundf(159*u);
        if(i==1)a->editor.edge_alpha=255-lroundf(255*u);
        if(i==2)a->editor.shadow_strength=lroundf(255*u);
        if(i==3)a->editor.flags=(a->editor.flags&~THEME_BLUR_MASK)|((unsigned int)lroundf(100*u)<<8);
        if(i>=4){
            int style=i-4;unsigned shift=editor_shifts[style];
            unsigned level=1+(unsigned)lroundf(editor_style_max[style]*u);
            a->editor.flags=(a->editor.flags&~(editor_masks[style]<<shift))|(level<<shift);
        }
    }
    if(!down){a->editor_drag=0;a->pointer_down=false;}
    editor_changed(a);return true;
}
