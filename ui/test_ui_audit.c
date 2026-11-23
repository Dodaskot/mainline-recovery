/* SPDX-License-Identifier: MIT — synthetic preview and format wording checks. */
#define main recovery_ui_program_main
#include "recovery_ui.c"
#undef main
int main(void){
    App*a=calloc(1,sizeof(*a));assert(a);initialize(a);
    assert(preview(a,"file-volume-userdata"));FileVolume*v=current_volume(a);
    assert(v&&!strcmp(v->id,"userdata")&&!strcmp(v->label,"Android data (synthetic)"));
    assert(!strcmp(v->fs_type,"f2fs")&&!strcmp(v->decrypt_state,"locked"));
    assert(v->decrypt_supported&&v->preparation_required&&v->credential_required&&!v->mounted&&!v->mountable);
    assert(!v->write_supported&&v->access_modes_known&&v->access_ro&&v->access_rw);
    assert(!strcmp(v->credential_type,"unknown")&&!strcmp(v->access_mode_qualification,"pending"));
    render(a);assert(test_button(a,A_FS_MOUNT_RO)->enabled&&test_button(a,A_FS_MOUNT_RW)->enabled);
    assert(preview(a,"files"));v=&a->volumes[0];
    assert(!strcmp(v->label,"Linux / userdata")&&!strcmp(v->fs_type,"ext4")&&v->mounted&&v->write_supported);
    for(unsigned int n=0;n<LANGUAGE_COUNT;n++)if(!strcmp(language_codes[n],"de"))ui_language=n;
    assert(!strcmp(tr("WILL BE ERASED"),"WIRD GELÖSCHT"));
    assert(!strcmp(tr("Not identified"),"Nicht erkannt"));
    const char*cancel="Cancelled. The recovery session remains available.";
    const char*german="Abgebrochen. Die Recovery-Sitzung bleibt verfügbar.";
    assert(!strcmp(tr(cancel),german));
    assert(preview(a,"file-volume-userdata-cancel"));v=current_volume(a);
    assert(v&&!v->fs_type[0]&&!strcmp(a->fs_status,cancel)&&v->session_retained);
    render(a);assert(!v->fs_type[0]);
    assert(test_button(a,A_FS_MOUNT_RO)->enabled&&test_button(a,A_FS_MOUNT_RW)->enabled);
    assert(test_button(a,A_FS_FORMAT_EXT4)->hold_ms==0&&test_button(a,A_FS_FORMAT_F2FS)->hold_ms==0);
    const size_t bytes=(size_t)NW*NH*sizeof(uint32_t);uint32_t*expected=malloc(bytes);assert(expected);
    memset(a->pixels,0,bytes);raw_text(false);files_note(a,100);memcpy(expected,a->pixels,bytes);
    copy(a->fs_status,sizeof(a->fs_status),german);memset(a->pixels,0,bytes);files_note(a,100);
    assert(!memcmp(expected,a->pixels,bytes));
    copy(a->fs_status,sizeof(a->fs_status),cancel);memset(a->pixels,0,bytes);raw_text(true);files_note(a,100);
    assert(memcmp(expected,a->pixels,bytes));raw_text(false);free(expected);
    copy(v->fs_type,sizeof(v->fs_type),"f2fs");render(a);assert(!strcmp(v->fs_type,"f2fs"));
    copy(v->fs_type,sizeof(v->fs_type),"ext4");render(a);assert(!strcmp(v->fs_type,"ext4"));
    puts("{\"ok\":true,\"android_fixture\":true,\"linux_fixture\":true,\"german_cancel_render\":true,\"filesystem_unchanged\":true}");
    free(a->pixels);free(a);return 0;
}
