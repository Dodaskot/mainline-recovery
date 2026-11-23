/* Exercise touch editing, validation and reloading the installed copy in a fixture. */
#define main recovery_main
#include "recovery_ui.c"
#undef main

static void wait_save(App*a){
    uint64_t deadline=milliseconds()+20000;
    while(a->job.pid&&milliseconds()<deadline){a->now=milliseconds();poll_job(a);usleep(1000);}
    assert(!a->job.pid);
}
static void drag_test(App*a,int x1,int y,int x2){
    uint64_t t=milliseconds();pointer(a,true,x1,y,t);pointer(a,true,x2,y,t+20);pointer(a,false,x2,y,t+40);
}
int main(int argc,char**argv){
    assert(argc==2&&getenv("A22X_THEMES_RAM")&&getenv("A22X_RECOVERY_THEMES_HELPER"));
    App*a=calloc(1,sizeof(*a));assert(a);initialize(a);
    copy(a->fixture,sizeof(a->fixture),argv[1]);snprintf(a->workdir,sizeof(a->workdir),"%s/session",argv[1]);
    Rect sample={100,200,200,100};
    rectangle(a,sample,0x202020);
    glass_panel(a,sample,20,0xffffff,0xff0000,100,255);
    uint32_t center=a->pixels[(size_t)nx(250)*NW+nx(200)];
    assert(center!=0xffffff&&center!=0xff0000&&center!=0x202020);
    rectangle(a,sample,0x202020);
    glass_panel(a,sample,20,0xffffff,0xff0000,100,0);
    assert(a->pixels[(size_t)nx(250)*NW+nx(200)]==center);
    /* 2026-11-22: the theme is a setting of the Tools tab (shell_ui.h), no longer a tile of Home. */
    ui_language=1;theme_apply(a,2);screen(a,TOOLS);
    assert(test_press(a,A_THEME,50)&&test_press(a,A_THEME_EDIT,50)&&a->screen==THEME_EDITOR);
    assert(test_press(a,A_TE_COLOR+5,50));drag_test(a,50,875,40);
    assert(a->editor.colors[5]==0&&ui_theme->text==themes[2].text);
    assert(test_press(a,A_TE_SAVE,50)&&a->job.kind==J_THEME_EDIT);wait_save(a);
    assert(a->screen==THEME_EDITOR&&a->editor_confirm_contrast&&a->editor_warning[0]);
    assert(!strcmp(ui_theme->code,"aurora"));
    drag_test(a,60,696,40);assert(a->editor.colors[5]==0xffffff);
    drag_test(a,308,990,616);drag_test(a,306,1070,480);drag_test(a,306,1160,580);drag_test(a,306,1240,679);
    assert(((a->editor.flags&THEME_BLUR_MASK)>>8)==100);
    assert(test_press(a,A_TE_PAGE,50)&&test_press(a,A_TE_COLOR+11,50));
    drag_test(a,50,919,403);drag_test(a,100,717,564);
    uint32_t picked=a->editor.colors[11];assert(picked!=themes[2].icon_fill);
    unsigned opacity=a->editor.surface_alpha,edge=a->editor.edge_alpha,shadow=a->editor.shadow_strength;
    assert(test_press(a,A_TE_NAME,50)&&a->screen==FILE_PROMPT);
    copy(a->fs_prompt,sizeof(a->fs_prompt),"Моя аврора");
    assert(test_press(a,A_FS_PROMPT_NEXT,50)&&a->screen==THEME_EDITOR);
    assert(test_press(a,A_TE_TILES_TAB,50)&&a->editor_shape);
    drag_test(a,440,777,306);
    drag_test(a,400,903,530);
    drag_test(a,400,1030,679);
    assert(editor_style(&a->editor,0)==0&&editor_style(&a->editor,2)==6);
    assert(test_press(a,A_TE_LAYOUT,50)&&test_press(a,A_TE_SAVE,50));wait_save(a);
    assert(a->screen==THEME&&!strcmp(ui_theme->code,"custom-1"));
    assert(!strcmp(ui_theme->name,"Моя аврора")&&theme_file_count==1);
    theme_reload(a);
    assert(ui_theme->blur==100&&ui_theme->surface_alpha==opacity&&ui_theme->edge_alpha==edge&&ui_theme->shadow_strength==shadow);
    assert(ui_theme->text==0xffffff&&ui_theme->icon_fill==picked&&!ui_theme->bento);
    assert(ui_theme->backdrop&&!memcmp(ui_theme->backdrop,backdrop_aurora,sizeof(backdrop_aurora)));
    uint32_t*plain=malloc((size_t)NW*NH*4);assert(plain);canvas_backdrop(plain,backdrop_aurora,BACKDROP_W,BACKDROP_H);
    assert(memcmp(plain,a->backdrop,(size_t)NW*NH*4));free(plain);
    assert(theme_style_value(ui_theme->tile_style,16,127,36)==0&&theme_style_value(ui_theme->tile_style,29,7,0)==6);
    assert(test_press(a,A_THEME_EDIT,50)&&!strcmp(a->editor.name,"Моя аврора"));
    assert(test_press(a,A_TE_NAME,50));
    copy(a->fs_prompt,sizeof(a->fs_prompt),"Нова назва");
    assert(test_press(a,A_FS_PROMPT_NEXT,50)&&test_press(a,A_TE_SAVE,50));wait_save(a);
    assert(a->screen==THEME&&theme_file_count==1&&!strcmp(ui_theme->code,"custom-1")&&!strcmp(ui_theme->name,"Нова назва"));
    assert(test_press(a,A_THEME_EDIT,50));
    assert(test_press(a,A_TE_COLOR+5,50));drag_test(a,40,875,66);
    assert(test_press(a,A_TE_SAVE,50));wait_save(a);
    assert(a->screen==THEME_EDITOR&&a->editor_confirm_contrast);
    assert(test_press(a,A_TE_SAVE,50));wait_save(a);
    assert(a->screen==THEME&&theme_file_count==1&&!strcmp(ui_theme->code,"graphite"));
    assert(theme_select(a,"custom-1")&&ui_theme->text==0&&ui_theme->blur==100);
    assert(test_press(a,A_THEME_EDIT,50));drag_test(a,300,919,600);
    assert(test_press(a,A_BACK,50)&&!strcmp(ui_theme->code,"custom-1"));
    puts("PASS named save, stable update, inline contrast warning and confirmation, tile geometry, blur, cancel");
    return 0;
}
