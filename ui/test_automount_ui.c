/* Mounting at start end to end (2026-11-20): the interface's start, the real automount.py and
 * filesystem.py on fixture volumes (folders, no block device), then the volume list as Files reads it. */
#define main recovery_ui_original_main
#include "recovery_ui.c"
#undef main
#include <ftw.h>
#define CHECK(x) do{checks++;if(!(x)){fprintf(stderr,"automount-ui check %u line %d failed: %s; screen=%d toast=%s\n",checks,__LINE__,#x,a?(int)a->screen:-1,a?a->toast:"");return 1;}}while(0)
static unsigned int checks;
static const char*test_root;
static int remove_entry(const char*path,const struct stat*st,int kind,struct FTW*walk){
    (void)st;(void)kind;(void)walk;
    size_t n=strlen(test_root);
    if(strncmp(path,test_root,n)||(path[n]&&path[n]!='/'))return -1;
    return remove(path);
}
static const FileVolume*volume_named(const App*a,const char*id){
    for(int n=0;n<a->volume_count;n++)if(!strcmp(a->volumes[n].id,id))return &a->volumes[n];
    return NULL;
}
static bool write_text(const char*path,const char*text){
    FILE*f=fopen(path,"w");if(!f)return false;bool ok=fputs(text,f)>=0;return fclose(f)==0&&ok;
}
int main(int argc,char**argv){
    App*a=NULL;
    if(argc<3){fprintf(stderr,"usage: %s SOURCE_TREE PYTHON\n",argv[0]);return 2;}
    char root[PATH_MAX];snprintf(root,sizeof(root),"%s/a22x-automount-ui-XXXXXX",getenv("TMPDIR")?getenv("TMPDIR"):"/tmp");
    CHECK(mkdtemp(root)!=NULL);
    const char*folders[]={"sd","usb","data","cache","efs"};
    for(size_t n=0;n<sizeof(folders)/sizeof(folders[0]);n++){char path[PATH_MAX];snprintf(path,sizeof(path),"%s/%s",root,folders[n]);CHECK(mkdir(path,0700)==0);}
    char fixture[PATH_MAX];snprintf(fixture,sizeof(fixture),"%s/filesystem-fixture.json",root);
    CHECK(write_text(fixture,"{\"schema\":\"a22x.filesystem.fixture.v1\",\"volumes\":["
        "{\"id\":\"sdcard-p1\",\"path\":\"sd\",\"fs_type\":\"exfat\",\"mounted\":false},"
        "{\"id\":\"usb-p1\",\"path\":\"usb\",\"fs_type\":\"exfat\",\"mounted\":true,\"read_only\":true},"
        "{\"id\":\"userdata\",\"path\":\"data\",\"fs_type\":\"f2fs\",\"mounted\":false},"
        "{\"id\":\"cache\",\"path\":\"cache\",\"fs_type\":\"ext4\",\"mounted\":false},"
        "{\"id\":\"efs\",\"path\":\"efs\",\"fs_type\":\"vfat\",\"mounted\":false}]}"));
    a=calloc(1,sizeof(*a));CHECK(a!=NULL);a->pixels=calloc((size_t)NW*NH,sizeof(uint32_t));CHECK(a->pixels!=NULL);
    a->volume_index=-1;a->focus=-1;a->mount_cards=a->mount_data=2;a->automount_fixture=true;
    copy(a->fixture,sizeof(a->fixture),root);copy(a->python,sizeof(a->python),argv[2]);
    snprintf(a->filesystem_helper,sizeof(a->filesystem_helper),"%s/filesystem.py",argv[1]);
    snprintf(a->distro_helper,sizeof(a->distro_helper),"%s/distro.py",argv[1]);
    /* Nothing before the home page; on it, once, the helper with the saved choices. */
    a->screen=SPLASH;automount_tick(a);CHECK(!a->job.pid&&!a->automount_started);
    a->screen=HOME;automount_tick(a);CHECK(a->job.pid&&a->job.kind==J_AUTOMOUNT&&a->automount_started);
    CHECK(await_job(a));
    CHECK(!strcmp(a->toast,T("Mounted at start: 3")));
    a->fs_inventory_destination=FILE_VOLUMES;CHECK(start_files_job(a,J_FS_INVENTORY)&&await_job(a));
    const FileVolume*sd=volume_named(a,"sdcard-p1"),*usb=volume_named(a,"usb-p1"),*data=volume_named(a,"userdata"),*cache=volume_named(a,"cache"),*efs=volume_named(a,"efs");
    CHECK(sd&&usb&&data&&cache&&efs);
    CHECK(sd->mounted&&!sd->read_only);        /* the card for writing */
    CHECK(usb->mounted&&!usb->read_only);      /* a stick usb-sync had opened read-only: now for writing */
    CHECK(data->mounted&&!data->read_only);    /* unencrypted Android data for writing */
    CHECK(!cache->mounted&&!efs->mounted);     /* other partitions: not by default */
    /* Not again: the start is once, and a later tick starts nothing. */
    screen(a,FILE_VOLUMES);screen(a,HOME);automount_tick(a);CHECK(!a->job.pid);
    /* A USB drive that arrives (usb-sync mounts it read-only first) is mounted for writing; nothing else is touched. */
    CHECK(write_text(fixture,"{\"schema\":\"a22x.filesystem.fixture.v1\",\"volumes\":["
        "{\"id\":\"sdcard-p1\",\"path\":\"sd\",\"fs_type\":\"exfat\",\"mounted\":false},"
        "{\"id\":\"usb-p1\",\"path\":\"usb\",\"fs_type\":\"exfat\",\"mounted\":false},"
        "{\"id\":\"userdata\",\"path\":\"data\",\"fs_type\":\"f2fs\",\"mounted\":false},"
        "{\"id\":\"cache\",\"path\":\"cache\",\"fs_type\":\"ext4\",\"mounted\":false},"
        "{\"id\":\"efs\",\"path\":\"efs\",\"fs_type\":\"vfat\",\"mounted\":false}]}"));
    char state[PATH_MAX];snprintf(state,sizeof(state),"%s/.filesystem-state.json",root);CHECK(write_text(state,"{\"usb-p1\":{\"mounted\":true,\"read_only\":true}}"));
    a->automount_rerun=true;automount_tick(a);CHECK(a->job.pid&&a->automount_cards_only);CHECK(await_job(a));
    CHECK(!strcmp(a->toast,T("USB drive mounted for writing")));
    CHECK(start_files_job(a,J_FS_INVENTORY)&&await_job(a));
    sd=volume_named(a,"sdcard-p1");usb=volume_named(a,"usb-p1");data=volume_named(a,"userdata");
    CHECK(usb&&usb->mounted&&!usb->read_only);
    CHECK(sd&&sd->mounted&&!sd->read_only);  /* the card is a removable volume too: mounted for writing again */
    CHECK(data&&!data->mounted);             /* a drive arriving never mounts Android data */
    /* Cards set to Don't mount: a drive that arrives starts nothing. */
    a->mount_cards=0;a->automount_rerun=true;automount_tick(a);CHECK(!a->job.pid&&!a->automount_rerun);
    /* The test's own fixture, made by mkdtemp above: removed without a shell, nothing outside it. */
    test_root=root;CHECK(nftw(root,remove_entry,16,FTW_DEPTH|FTW_PHYS)==0);
    free(a->pixels);free(a);
    printf("{\"ok\":true,\"automount_ui_checks\":%u,\"real_helpers\":true,\"device_io\":false}\n",checks);
    return 0;
}
