/* Android user0 logical files on userdata; explicit independent backup flow. */
#ifndef A22X_ANDROID_DATA_BACKUP_UI_H
#define A22X_ANDROID_DATA_BACKUP_UI_H
static const char*ad_l(const char*en,const char*uk,const char*de){return ui_language==1?uk:ui_language==2?de:en;}
static const char*model_title(void){return ad_l("Full Data for this model","Усі дані для цієї моделі","Alle Daten für dieses Modell");}
static bool ad_path_ok(const char*p){
    const char*prefix="/media/0/A22xDataBackups/";size_t n=strlen(prefix),len=strlen(p);
    if(strncmp(p,prefix,n)||len<=n+8||strcmp(p+len-8,".tar.zst"))return false;
    const char*name=p+n;if(strchr(name,'/')||strstr(name,".."))return false;
    for(;*name;name++)if(!isalnum((unsigned char)*name)&&*name!='-'&&*name!='_'&&*name!='.')return false;
    return true;
}
static bool ad_ready(const App*a){return a->ad_known&&a->ad_can&&a->ad_mounted&&a->ad_ce&&!a->ad_ro&&a->ad_write&&valid_sha256(a->ad_token);}
static const char*migrate_title(void){
    return ad_l("Transfer to another Android","Перенести на інший Android","Auf ein anderes Android übertragen");
}
static void render_ad_choice(App*a){
    heading(a,ad_l("Android backup","Копія Android","Android-Sicherung"),ad_l("Choose what to save and where.","Оберіть вміст і місце копії.","Inhalt und Speicherort wählen."),true);
    button(a,(Rect){28,260,664,106},ad_l("Partitions to SD / USB","Розділи на SD / USB","Partitionen auf SD / USB"),A_AD_PARTITIONS,ui_free(a),true,0);
    wrapped(a,44,385,632,0,MUTED,ad_l("Partition copy on external storage.","Копія розділів на зовнішньому носії.","Partitionskopie auf externem Speicher."),3);
    button(a,(Rect){28,520,664,106},ad_l("Files on userdata","Файли на userdata","Dateien auf userdata"),A_AD_FILES,ui_free(a),false,0);
    wrapped(a,44,645,632,0,MUTED,ad_l("Logical user files in Android storage.","Логічна копія файлів у сховищі Android.","Logische Kopie der Dateien im Android-Speicher."),3);
    button(a,(Rect){28,780,664,106},ad_l("Portable file backup","Переносима копія файлів","Portable Dateisicherung"),A_AD_MEDIA,ui_free(a),false,0);
    wrapped(a,44,905,632,0,MUTED,ad_l("Photos, documents and other shared files.","Фото, документи та інші спільні файли.","Fotos, Dokumente und weitere gemeinsame Dateien."),3);
    button(a,(Rect){28,1040,664,106},model_title(),A_AD_MODEL,ui_free(a),false,0);
    wrapped(a,44,1165,632,0,MUTED,ad_l("Apps, settings, Wi-Fi, contacts and home screen.","Застосунки, налаштування, Wi-Fi, контакти й робочий стіл.","Apps, Einstellungen, WLAN, Kontakte und Startbildschirm."),3);
    button(a,(Rect){28,1300,664,100},migrate_title(),A_AD_MIGRATE,ui_free(a),false,0);
}
static void render_ad_backup(App*a){
    heading(a,ad_l("Files on userdata","Файли на userdata","Dateien auf userdata"),ad_l("User 0 logical file copy","Логічна копія файлів користувача 0","Logische Dateikopie von Benutzer 0"),true);
    const char*state=!a->ad_known?ad_l("Checking state...","Перевірка стану...","Status wird geprüft..."):ad_ready(a)?ad_l("Ready: Android unlocked, writable","Готово: Android відкрито для запису","Bereit: Android entsperrt, beschreibbar"):!a->ad_mounted||!a->ad_ce?ad_l("Android is locked or not mounted","Android заблоковано або не змонтовано","Android gesperrt oder nicht eingehängt"):a->ad_ro?ad_l("Android is read-only","Android лише для читання","Android ist schreibgeschützt"):a->ad_write&&!a->ad_can?ad_l("Refresh state before a new copy","Оновіть стан перед новою копією","Vor neuer Kopie Status aktualisieren"):ad_l("Writing is unavailable","Запис недоступний","Schreiben nicht verfügbar");
    text_tile(a,235,0,ad_ready(a)?TEXT:ORANGE,state,3);
    if(a->ad_reason[0]){raw_text(true);wrapped(a,40,348,640,0,MUTED,a->ad_reason,2);raw_text(false);}
    wrapped(a,40,430,640,0,ORANGE,ad_l("The copy is on userdata. Formatting or losing userdata also destroys it.","Копія на userdata. Форматування чи втрата userdata знищить і її.","Die Kopie liegt auf userdata. Formatierung oder Verlust von userdata zerstört auch sie."),4);
    wrapped(a,40,570,640,0,MUTED,ad_l("This is not a full partition image or portable Android migration. No separate backup password is applied; the archive is inside encrypted user storage.","Це не повний образ розділів і не перенос Android. Окремий пароль копії не застосовується; архів у шифрованому сховищі користувача.","Kein vollständiges Partitionsabbild und keine portable Android-Migration. Kein separates Sicherungspasswort; das Archiv liegt im verschlüsselten Benutzerspeicher."),6);
    if(a->ad_verified){char size[48];human_bytes(a->ad_bytes,size,sizeof(size));text(a,40,815,0,TEXT,ad_l("Verified copy","Перевірена копія","Geprüfte Kopie"));raw_text(true);wrapped(a,40,855,640,0,TEXT,a->ad_path,3);text(a,40,970,0,MUTED,size);raw_text(false);}
    button(a,(Rect){28,1060,320,80},ad_l("Files / Mount","Файли / монтування","Dateien / Einhängen"),A_FILES,ui_free(a),false,0);
    button(a,(Rect){372,1060,320,80},ad_l("Refresh","Оновити","Aktualisieren"),A_AD_REFRESH,ui_free(a),false,0);
    button(a,(Rect){28,1170,664,80},ad_l("Verify last copy","Перевірити останню копію","Letzte Kopie prüfen"),A_AD_VERIFY,ui_free(a)&&a->ad_verified&&a->ad_known&&a->ad_mounted&&a->ad_ce&&valid_sha256(a->ad_token),false,0);
    button(a,(Rect){28,1300,664,100},ad_l("Create backup","Створити копію","Sicherung erstellen"),A_AD_CREATE,ui_free(a)&&ad_ready(a),true,0);
}
static bool start_ad_job(App*a,int kind){
    if(a->job.pid||a->preview)return false;
    if(kind!=J_AD_INSPECT&&kind!=J_AD_BACKUP&&kind!=J_AD_VERIFY)return false;
    if(kind==J_AD_BACKUP&&!ad_ready(a))return false;
    if(kind==J_AD_VERIFY&&(!a->ad_known||!a->ad_mounted||!a->ad_ce||!valid_sha256(a->ad_token)||!a->ad_verified||!valid_sha256(a->ad_sha)||!ad_path_ok(a->ad_path)))return false;
    if(!sibling_helper(a,"android_data.py",a->ad_helper,sizeof(a->ad_helper)))return false;
    char*args[16];int n=0;args[n++]=a->python;args[n++]=a->ad_helper;
    if(a->device)args[n++]="--device";else{args[n++]="--fixture";args[n++]=a->fixture;}
    args[n++]=(char*)job_name(kind);
    if(kind!=J_AD_INSPECT){args[n++]="--expected-volume-token";args[n++]=a->ad_token;}
    if(kind==J_AD_BACKUP)args[n++]="--confirm";
    if(kind==J_AD_VERIFY){args[n++]="--path";args[n++]=a->ad_path;args[n++]="--expected-sha256";args[n++]=a->ad_sha;}
    args[n]=NULL;if(!launch_job(a,kind,args))return false;a->result_return=ANDROID_DATA_BACKUP;return true;
}
static void complete_ad_job(App*a,const Json*j,int kind,bool ok){
    if(kind==J_AD_INSPECT){
        a->ad_known=true;a->ad_can=a->ad_mounted=a->ad_ce=a->ad_write=false;a->ad_ro=true;a->ad_token[0]=a->ad_reason[0]=0;
        if(ok&&j&&jequals(j,0,"operation","inspect")){
            a->ad_can=json_bool(j,json_get(j,0,"can_backup"),0)==1;a->ad_mounted=json_bool(j,json_get(j,0,"mounted"),0)==1;a->ad_ce=json_bool(j,json_get(j,0,"ce_authenticated"),0)==1;a->ad_ro=json_bool(j,json_get(j,0,"read_only"),1)!=0;a->ad_write=json_bool(j,json_get(j,0,"write_supported"),0)==1;
            jstring(j,0,"volume_token",a->ad_token,sizeof(a->ad_token));jstring(j,0,"reason",a->ad_reason,sizeof(a->ad_reason));
            if(!jequals(j,0,"destination","/media/0/A22xDataBackups"))a->ad_can=false;
        }else copy(a->ad_reason,sizeof(a->ad_reason),"INSPECT_FAILED");a->dirty=true;return;
    }
    char path[512]={0},sha[80]={0};int ar=j?json_get(j,0,"archive"):-1;
    if(j&&ar>=0){jstring(j,ar,"path",path,sizeof(path));jstring(j,ar,"sha256",sha,sizeof(sha));}
    bool good=ok&&j&&jequals(j,0,"operation",kind==J_AD_BACKUP?"backup":"verify")&&json_bool(j,json_get(j,0,"verified"),-1)==1&&ar>=0&&jequals(j,ar,"volume","userdata")&&ad_path_ok(path)&&valid_sha256(sha)&&json_uint(j,json_get(j,ar,"bytes"),0)>0;
    if(kind==J_AD_VERIFY)good=good&&!strcmp(path,a->ad_path)&&!strcmp(sha,a->ad_sha);
    if(!good){a->ad_can=false;a->ad_verified=false;files_problem(a,"BACKUP_NOT_VERIFIED",ad_l("The operation failed or its result was not verified. Refresh state before another attempt.","Операція не вдалася або результат не підтверджено. Перед новою спробою оновіть стан.","Der Vorgang schlug fehl oder das Ergebnis ist nicht bestätigt. Vor erneutem Versuch Status aktualisieren."),ANDROID_DATA_BACKUP);return;}
    copy(a->ad_path,sizeof(a->ad_path),path);copy(a->ad_sha,sizeof(a->ad_sha),sha);a->ad_bytes=json_uint(j,json_get(j,ar,"bytes"),0);a->ad_verified=true;a->ad_can=false;
    screen(a,ANDROID_DATA_BACKUP);a->dirty=true;
}
static bool ad_media_volume(const FileVolume*v){
    return v&&v->mounted&&v->mountable&&valid_sha256(v->token)&&
        (!strcmp(v->id,"userdata")||!strncmp(v->id,"sdcard-",7)||!strncmp(v->id,"usb-",4));
}
static bool ad_media_writable(const FileVolume*v){return ad_media_volume(v)&&!v->read_only&&v->write_supported;}
static const FileVolume*ad_media_lookup(const App*a,const char*id){
    for(int i=0;i<a->volume_count;i++)if(!strcmp(a->volumes[i].id,id))return &a->volumes[i];
    return NULL;
}
/* Android data that encrypts nothing (LineageOS 20), mounted as it is: there is no unlock to ask for
   (2026-11-21, on the phone: the portable copy asked LineageOS for one). */
static bool ad_plain_open(const FileVolume*v){return v&&v->android_plain&&v->mounted&&!strcmp(v->mount_owner,"filesystem");}
static const FileVolume*ad_media_userdata(const App*a){
    const FileVolume*v=ad_media_lookup(a,"userdata");
    if(ad_media_volume(v)&&ad_plain_open(v))return v;
    return ad_media_volume(v)&&v->ce_authenticated&&v->fscrypt_policy_verified&&
        !strcmp(v->mount_owner,"android-decrypt")&&!strcmp(v->decrypt_state,"mounted")?v:NULL;
}
static bool ad_encrypted_media(const char*path){
    size_t n=strlen(path);return n>11&&!strcasecmp(path+n-11,".tar.gz.enc");
}
static bool ad_media_file(const App*a){
    const FileVolume*v=ad_media_lookup(a,a->volume_id);const FileEntry*e=&a->fs_selected;
    size_t n=strlen(e->name);
    return ad_media_volume(v)&&file_is_regular(e)&&((n>7&&!strcasecmp(e->name+n-7,".tar.gz"))||ad_encrypted_media(e->name))&&
        (strcmp(v->id,"userdata")||(!strncmp(e->path,"/media/0/",9)&&(v->ce_authenticated||ad_plain_open(v))));
}
static bool ad_twrp_file(const App*a){
    const FileEntry*entry=&a->fs_selected;
    const FileVolume*volume=ad_media_lookup(a,a->volume_id);
    if(!file_is_regular(entry)||!volume||!volume->mounted||!valid_sha256(volume->token))return false;
    if(strcmp(volume->id,"cache")&&!ad_media_volume(volume))return false;
    if(!strcmp(volume->id,"userdata")&&((!volume->ce_authenticated&&!ad_plain_open(volume))||strncmp(entry->path,"/media/0/",9)))return false;
    const char*name=entry->name;
    size_t size=strlen(name);
    if((size!=13&&size!=16)||strncmp(name,"data.",5)||strncmp(name+9,".win",4))return false;
    if(strncmp(name+5,"f2fs",4)&&(strncmp(name+5,"ext",3)||name[8]<'2'||name[8]>'4'))return false;
    return size==13||(name[13]>='0'&&name[13]<='8'&&isdigit((unsigned char)name[14])&&isdigit((unsigned char)name[15]));
}
static void render_ad_twrp_review(App*a){
    heading(a,ad_l("Data backup check","Перевірка копії Data","Data-Sicherung prüfen"),"TWRP / OrangeFox",true);
    raw_text(true);wrapped(a,40,240,640,0,TEXT,a->fs_selected.path,4);raw_text(false);
    char parts[48],size[48],files[48],apps[64];
    snprintf(parts,sizeof(parts),"%llu / %llu",(unsigned long long)a->ad_twrp_checked,(unsigned long long)a->ad_twrp_parts);
    snprintf(files,sizeof(files),"%llu",(unsigned long long)a->ad_twrp_files);
    snprintf(apps,sizeof(apps),"%llu CE / %llu DE",(unsigned long long)a->ad_twrp_ce_apps,(unsigned long long)a->ad_twrp_de_apps);
    human_bytes(a->ad_twrp_bytes,size,sizeof(size));
    stat_tile(a,(Rect){28,410,664,112},ad_l("Segments with verified checksums","Частини зі звіреними сумами","Teile mit geprüften Prüfsummen"),
              parts,a->ad_twrp_checked==a->ad_twrp_parts?GREEN:ORANGE);
    stat_tile(a,(Rect){28,540,324,112},ad_l("Files","Файли","Dateien"),files,TEXT);
    stat_tile(a,(Rect){368,540,324,112},ad_l("Unpacked size","Розмір даних","Entpackte Größe"),size,TEXT);
    stat_tile(a,(Rect){28,670,664,112},ad_l("User 0 app data","Дані програм користувача 0","App-Daten von Benutzer 0"),apps,TEXT);
    if(a->ad_twrp_fbe)wrapped(a,40,822,640,0,MUTED,ad_l("The archive contains Android encryption metadata.",
        "Архів містить метадані шифрування Android.","Das Archiv enthält Android-Verschlüsselungsmetadaten."),3);
    wrapped(a,40,990,640,0,ORANGE,ad_l("The source model and exact ROM need to be verified before restoring Data.",
        "Для відновлення Data потрібно підтвердити модель і точну збірку вихідної прошивки.",
        "Vor der Wiederherstellung von Data müssen Quellmodell und genaue ROM-Version geprüft werden."),5);
}
static bool start_ad_twrp_job(App*a){
    if(a->job.pid||a->preview||!ad_twrp_file(a)||!sibling_helper(a,"android_twrp.py",a->ad_helper,sizeof(a->ad_helper)))return false;
    FileVolume*v=current_volume(a);if(!v)return false;
    char*args[12];int n=0;args[n++]=a->python;args[n++]=a->ad_helper;
    if(a->device)args[n++]="--device";else{args[n++]="--fixture";args[n++]=a->fixture;}
    args[n++]="--volume";args[n++]=v->id;args[n++]="--expected-volume-token";args[n++]=v->token;
    args[n++]="--path";args[n++]=a->fs_selected.path;args[n++]="--summary";args[n]=NULL;
    return launch_job(a,J_AD_TWRP_REVIEW,args);
}
static void complete_ad_twrp_job(App*a,const Json*j,bool ok){
    int archive=j?json_get(j,0,"archive"):-1,counts=j?json_get(j,0,"counts"):-1;
    uint64_t parts=counts>=0?json_uint(j,json_get(j,counts,"parts"),0):0;
    uint64_t checked=counts>=0?json_uint(j,json_get(j,counts,"checked_parts"),UINT64_MAX):UINT64_MAX;
    char sha[80]={0};if(archive>=0)jstring(j,archive,"sha256",sha,sizeof(sha));
    if(!ok||!j||!jequals(j,0,"schema","a22x.twrp-data-review.v1")||!json_bool(j,json_get(j,0,"verified_structure"),0)||
       archive<0||parts<1||parts>900||checked>parts||!valid_sha256(sha)||
       !jequals(j,archive,"volume",a->volume_id)||!jequals(j,archive,"path",a->fs_selected.path)){
        char code[96]="TWRP_REVIEW_FAILED",message[384];
        copy(message,sizeof(message),ad_l("The Data backup could not be checked.","Не вдалося перевірити копію Data.","Die Data-Sicherung konnte nicht geprüft werden."));
        if(j){int error=json_get(j,0,"error");if(error>=0){jstring(j,error,"code",code,sizeof(code));jstring(j,error,"message",message,sizeof(message));}}
        files_problem(a,code,message,FILE_INFO);return;
    }
    a->ad_twrp_parts=parts;a->ad_twrp_checked=checked;
    a->ad_twrp_files=json_uint(j,json_get(j,counts,"files"),0);a->ad_twrp_bytes=json_uint(j,json_get(j,counts,"file_bytes"),0);
    a->ad_twrp_ce_apps=json_uint(j,json_get(j,counts,"ce_packages"),0);a->ad_twrp_de_apps=json_uint(j,json_get(j,counts,"de_packages"),0);
    a->ad_twrp_fbe=jarray_has(j,0,"twrp_metadata","TWRP.security.fscrypt");
    screen(a,ANDROID_TWRP_REVIEW);
}
static void ad_media_refresh(App*a){
    a->fs_inventory_destination=ANDROID_MEDIA_BACKUP;
    if(!start_files_job(a,J_FS_INVENTORY))a->dirty=true;
}
static void ad_media_initial_destination(App*a){
    if(a->ad_media_dest[0])return;
    const FileVolume*dest=ad_media_lookup(a,"userdata");
    if(!ad_media_writable(dest)){
        dest=NULL;
        for(int i=0;i<a->volume_count;i++){
            if(ad_media_writable(&a->volumes[i])){dest=&a->volumes[i];break;}
        }
    }
    if(dest)copy(a->ad_media_dest,sizeof(a->ad_media_dest),dest->id);
}
static bool ad_backup_list_current(const App*a,const FileVolume*data){
    return data&&valid_sha256(a->ad_backup_registry_sha)&&!strcmp(data->token,a->ad_backup_source_token);
}
/* Kinds of shared files (file_types.py), in its order; all of them is no choice. */
#define AD_KINDS 7
#define AD_KINDS_ALL ((1u<<AD_KINDS)-1)
static const char*const ad_kind_ids[AD_KINDS]={"photos","videos","audio","documents","archives","apks","other"};
static const char*ad_kind_title(int i){
    static const char*const t[AD_KINDS][3]={{"Photos","Фото","Fotos"},{"Videos","Відео","Videos"},{"Audio","Аудіо","Audio"},
        {"Documents","Документи","Dokumente"},{"Archives","Архіви","Archive"},{"APK files","APK-файли","APK-Dateien"},{"Other files","Інші файли","Andere Dateien"}};
    return ad_l(t[i][0],t[i][1],t[i][2]);
}
static int ad_kind_count(unsigned kinds){int n=0;for(int i=0;i<AD_KINDS;i++)n+=(kinds>>i)&1;return n;}
static const char*ad_migrate_kinds_text(App*a){
    unsigned kinds=a->ad_migrate_kinds&AD_KINDS_ALL;a->ad_migrate_kinds_arg[0]=0;
    if(kinds==AD_KINDS_ALL)return NULL;
    for(int i=0;i<AD_KINDS;i++)if((kinds>>i)&1){
        if(a->ad_migrate_kinds_arg[0])strncat(a->ad_migrate_kinds_arg,",",sizeof(a->ad_migrate_kinds_arg)-strlen(a->ad_migrate_kinds_arg)-1);
        strncat(a->ad_migrate_kinds_arg,ad_kind_ids[i],sizeof(a->ad_migrate_kinds_arg)-strlen(a->ad_migrate_kinds_arg)-1);
    }
    return a->ad_migrate_kinds_arg;
}
static void render_ad_migrate_options(App*a){
    heading(a,ad_l("What to transfer","Що переносити","Was übertragen"),ad_l("Settings, contacts and Wi-Fi always go along.",
        "Налаштування, контакти й Wi-Fi переносяться завжди.","Einstellungen, Kontakte und WLAN kommen immer mit."),true);
    button(a,(Rect){28,270,664,96},a->ad_migrate_root?ad_l("Root and adb · On","Root і adb · Так","Root und adb · Ja"):
        ad_l("Root and adb · Off","Root і adb · Ні","Root und adb · Nein"),A_AD_MIG_ROOT,!a->job.pid,a->ad_migrate_root,0);
    wrapped(a,40,384,640,0,MUTED,ad_l("adb on, its allowed computers and Magisk's adb rule: root over adb in the next system.",
        "Увімкнений adb, дозволені комп'ютери й правило Magisk для adb: root з adb у наступній системі.",
        "adb an, erlaubte Computer und Magisks adb-Regel: Root über adb im nächsten System."),3);
    text(a,40,520,0,MUTED,ad_l("Shared files","Спільні файли","Gemeinsame Dateien"));
    for(int i=0;i<AD_KINDS;i++){
        bool on=(a->ad_migrate_kinds>>i)&1;
        button(a,(Rect){28+(i%2)*344,570+(i/2)*112,320,92},ad_kind_title(i),A_AD_MIG_KIND+i,!a->job.pid,on,0);
    }
    char count[96];snprintf(count,sizeof(count),ad_l("Chosen: %d of %d kinds","Вибрано: %d із %d типів","Gewählt: %d von %d Arten"),
        ad_kind_count(a->ad_migrate_kinds&AD_KINDS_ALL),AD_KINDS);
    text(a,40,1040,0,MUTED,count);
    button(a,(Rect){28,1318,664,94},ad_l("Done","Готово","Fertig"),A_AD_MIG_DONE,true,true,0);
}
static void render_ad_media(App*a){
    const FileVolume*data=ad_media_userdata(a),*dest=ad_media_lookup(a,a->ad_media_dest);
    bool selection_current=ad_backup_list_current(a,data);
    bool ready=!a->job.pid&&data&&ad_media_writable(dest)&&(!a->ad_migrate||!a->ad_backup_apps_selected||selection_current);
    heading(a,a->ad_migrate?migrate_title():a->ad_model?model_title():ad_l("Portable file backup","Переносима копія файлів","Portable Dateisicherung"),a->ad_migrate?"tar.gz.enc":a->ad_model?"tar.zst.enc":"tar.gz",true);
    wrapped(a,40,252,640,0,MUTED,a->ad_migrate?ad_l("Shared files, settings, contacts, Wi-Fi and supported home layouts.","Спільні файли, налаштування, контакти, Wi-Fi й розкладка екрана.","Gemeinsame Dateien, Einstellungen, Kontakte, WLAN und Startbildschirm."):a->ad_model?ad_l("Copies Android user 0 files and settings from Data.","Копіює файли та налаштування основного користувача з Data.","Kopiert Daten und Einstellungen von Android-Benutzer 0."):ad_l("Copies photos, documents and app exports from shared storage. Private app data is excluded.",
        "Копіює фото, документи й експорти зі спільного сховища. Приватні дані застосунків виключено.",
        "Kopiert Fotos, Dokumente und App-Exporte aus dem gemeinsamen Speicher. Private App-Daten bleiben außen vor."),5);
    if(!data)wrapped(a,40,442,640,0,ORANGE,ad_l("Unlock and mount Android Data in Files.",
        "Розблокуйте та змонтуйте Data у «Файлах».","Android-Daten in Dateien entsperren und einhängen."),3);
    else if(a->ad_migrate){
        char label[128];
        if(a->ad_backup_apps_selected&&!selection_current)copy(label,sizeof(label),ad_l("Review app selection", "Перевірити вибір застосунків", "App-Auswahl prüfen"));
        else snprintf(label,sizeof(label),ad_l("App data (%d)","Дані застосунків (%d)","App-Daten (%d)"),a->ad_backup_apps_selected);
        button(a,(Rect){28,450,320,82},label,A_AD_APP_PICK,!a->job.pid,false,0);
        char what[128];int kinds=ad_kind_count(a->ad_migrate_kinds&AD_KINDS_ALL);
        if(kinds==AD_KINDS)snprintf(what,sizeof(what),"%s%s",ad_l("Contents · all","Вміст · усе","Inhalt · alles"),a->ad_migrate_root?" · root":"");
        else snprintf(what,sizeof(what),ad_l("Contents · %d kinds%s","Вміст · %d типи%s","Inhalt · %d Arten%s"),kinds,a->ad_migrate_root?" · root":"");
        button(a,(Rect){372,450,320,82},what,A_AD_MIG_OPTIONS,!a->job.pid,false,0);
    }
    text(a,40,580,0,MUTED,ad_l("Destination","Місце збереження","Ziel"));
    if(ad_media_writable(dest)){raw_text(true);ellipsis(a,40,623,640,1,TEXT,dest->label[0]?dest->label:dest->id);raw_text(false);}
    else wrapped(a,40,623,640,1,ORANGE,ad_l("No writable destination selected","Виберіть доступний носій","Kein beschreibbares Ziel gewählt"),2);
    button(a,(Rect){28,708,664,82},ad_l("Change destination","Змінити носій","Ziel wechseln"),A_AD_MEDIA_NEXT,!a->job.pid,false,0);
    wrapped(a,40,820,640,0,ORANGE,(a->ad_model||a->ad_migrate)?ad_l("Keep the backup password. Formatting Data erases copies stored there.","Збережіть пароль копії. Форматування Data видаляє копії на цьому томі.","Passwort aufbewahren. Formatieren von Data löscht dort gespeicherte Kopien."):ad_l("Copies on SD and USB are readable without a password.",
        "Копії на SD і USB можна прочитати без пароля.","Kopien auf SD und USB sind ohne Passwort lesbar."),3);
    if(a->ad_media_saved){
        text(a,40,928,0,GREEN,ad_l("Verified copy","Перевірена копія","Geprüfte Kopie"));
        raw_text(true);wrapped(a,40,963,640,0,TEXT,a->ad_media_path,3);raw_text(false);
    }else if(!a->ad_model&&!a->ad_migrate)wrapped(a,40,928,640,0,MUTED,ad_l("To restore, open the archive's file actions and choose Restore to Android.",
        "Для відновлення відкрийте меню файлу архіву й виберіть «На Android».",
        "Zum Wiederherstellen im Dateimenü des Archivs Auf Android wählen."),4);
    button(a,(Rect){28,1110,320,82},ad_l("Files / Mount","Файли / монтування","Dateien / Einhängen"),A_FILES,!a->job.pid,false,0);
    button(a,(Rect){372,1110,320,82},ad_l("Refresh","Оновити","Aktualisieren"),A_AD_MEDIA_REFRESH,!a->job.pid,false,0);
    button(a,(Rect){28,1300,664,100},ad_l("Hold to create backup","Утримуйте для копіювання","Halten zum Sichern"),A_AD_MEDIA_BACKUP,ready,true,1100);
}
static void render_ad_backup_apps(App*a){
    heading(a,ad_l("Choose app data","Вибрати дані застосунків","App-Daten auswählen"),NULL,true);
    char count[96];
    snprintf(count,sizeof(count),ad_l("Selected %d of %d","Вибрано %d із %d","%d von %d ausgewählt"),
        a->ad_backup_apps_selected,a->ad_backup_apps_count);
    text(a,40,235,0,MUTED,count);
    if(!a->ad_backup_apps_count)wrapped(a,40,324,640,0,MUTED,ad_l("No supported app data found.",
        "Даних сумісних застосунків не знайдено.","Keine unterstützten App-Daten gefunden."),3);
    for(int row=0;row<AD_APP_ROWS;row++){
        int index=a->ad_backup_apps_page*AD_APP_ROWS+row;
        if(index>=a->ad_backup_apps_count)break;
        const AdSourceApp*app=&a->ad_backup_apps[index];
        raw_text(true);
        button(a,(Rect){28,298+row*102,664,84},app->package,A_AD_APP_ITEM+row,
            !a->job.pid&&(app->selected||a->ad_backup_apps_selected<AD_APP_MAX),app->selected,0);
        raw_text(false);
    }
    int last=a->ad_backup_apps_count?(a->ad_backup_apps_count-1)/AD_APP_ROWS:0;
    if(last){
        char page[32];snprintf(page,sizeof(page),"%d / %d",a->ad_backup_apps_page+1,last+1);
        button(a,(Rect){28,928,106,74},"←",A_AD_APP_PREV,a->ad_backup_apps_page>0,false,0);
        button(a,(Rect){586,928,106,74},"→",A_AD_APP_NEXT,a->ad_backup_apps_page<last,false,0);
        centered(a,(Rect){140,928,440,74},0,MUTED,page);
    }
    bool all=a->ad_backup_apps_selected==a->ad_backup_apps_count;
    bool over=a->ad_backup_apps_count>AD_APP_MAX;
    if(over)wrapped(a,40,1014,640,0,MUTED,ad_l("Choose up to 256 apps per backup.",
        "В одну копію можна додати до 256 застосунків.","Pro Sicherung sind bis zu 256 Apps möglich."),3);
    if(a->ad_backup_apps_count)button(a,(Rect){28,1082,664,70},a->ad_backup_include_apks?
        ad_l("Include APKs · On","Додавати APK · Так","APKs mitsichern · Ja"):
        ad_l("Include APKs · Off","Додавати APK · Ні","APKs mitsichern · Nein"),A_AD_APP_PICK_APKS,true,a->ad_backup_include_apks,0);
    if(a->ad_backup_apps_count)button(a,(Rect){28,1170,664,82},all||over?ad_l("Clear selection","Зняти вибір","Auswahl aufheben"):
        ad_l("Select all","Вибрати всі","Alle auswählen"),A_AD_APP_PICK_ALL,!over||a->ad_backup_apps_selected>0,false,0);
    button(a,(Rect){28,1318,664,94},ad_l("Done","Готово","Fertig"),A_AD_APP_PICK_DONE,true,true,0);
}
static AdApp*ad_selected_app(App*a){
    int index=a->ad_apps_selected;
    return index>=0&&index<a->ad_apps_count?&a->ad_apps[index]:NULL;
}
static bool ad_apps_target_ready(const App*a,const FileVolume*data){
    return data&&valid_sha256(a->ad_apps_target)&&!strcmp(a->ad_apps_target,data->token);
}
static const char*ad_app_status_label(enum AdAppStatus status){
    switch(status){
    case AD_APP_COMPATIBLE:return ad_l("App identity matches","Пакет збігається","App-Identität stimmt überein");
    case AD_APP_MISSING:return ad_l("Install the app first","Спочатку встановіть застосунок","Zuerst die App installieren");
    case AD_APP_SIGNER:return ad_l("Different app signature","Інший підпис застосунку","Andere App-Signatur");
    case AD_APP_OS:return ad_l("Requires a newer Android","Потрібен новіший Android","Neueres Android erforderlich");
    case AD_APP_VERSION:return ad_l("Different app version","Інша версія застосунку","Andere App-Version");
    case AD_APP_EMPTY:return ad_l("No private data saved","Приватні дані в копії відсутні","Keine privaten Daten gesichert");
    case AD_APP_RESTORED:return ad_l("Data verified after restore","Дані перевірено після відновлення","Daten nach Wiederherstellung geprüft");
    }
    return "";
}
static void render_ad_app_restore(App*a){
    heading(a,ad_l("Restore app data","Відновити дані застосунків","App-Daten wiederherstellen"),NULL,true);
    if(!a->ad_apps_count){
        wrapped(a,40,300,640,0,MUTED,ad_l("This backup contains no app data.","У цій копії немає даних застосунків.",
            "Diese Sicherung enthält keine App-Daten."),4);
        return;
    }
    for(int row=0;row<AD_APP_ROWS;row++){
        int index=a->ad_apps_page*AD_APP_ROWS+row;
        if(index>=a->ad_apps_count)break;
        const AdApp*app=&a->ad_apps[index];
        bool selected=index==a->ad_apps_selected,compatible=app->status==AD_APP_COMPATIBLE;
        Rect area={28,250+row*112,664,100};
        surface(a,area,22,selected?ORANGE:PANEL,A_AD_APP_ITEM+row);
        raw_text(true);ellipsis(a,52,area.y+18,616,0,selected?ON_ORANGE:TEXT,app->package);raw_text(false);
        const char*notice=app->apk_saved&&app->status==AD_APP_MISSING?
            ad_l("Install the APKs saved in this backup","Встановіть APK із цієї копії","Gesicherte APKs zuerst installieren"):
            ad_app_status_label(app->status);
        text(a,52,area.y+57,0,selected?ON_ORANGE:app->status==AD_APP_RESTORED?GREEN:MUTED,notice);
        register_button(a,area,A_AD_APP_ITEM+row,!a->job.pid&&compatible,0);
    }
    int last=(a->ad_apps_count-1)/AD_APP_ROWS;
    if(last>0){
        char page[32];snprintf(page,sizeof(page),"%d / %d",a->ad_apps_page+1,last+1);
        button(a,(Rect){28,932,106,74},"←",A_AD_APP_PREV,!a->job.pid&&a->ad_apps_page>0,false,0);
        button(a,(Rect){586,932,106,74},"→",A_AD_APP_NEXT,!a->job.pid&&a->ad_apps_page<last,false,0);
        centered(a,(Rect){140,932,440,74},0,MUTED,page);
    }
    const FileVolume*data=ad_media_userdata(a);
    bool writable=ad_apps_target_ready(a,data)&&ad_media_writable(data);
    const AdApp*app=ad_selected_app(a);
    if(app){raw_text(true);wrapped(a,40,1028,640,0,TEXT,app->package,7);raw_text(false);}
    if(!writable)wrapped(a,40,1260,640,0,ORANGE,ad_l("Mount Data for writing, then reopen this archive.",
        "Змонтуйте Data для запису й відкрийте цей архів знову.","Data beschreibbar einhängen und das Archiv erneut öffnen."),3);
    else button(a,(Rect){28,1350,664,90},ad_l("Hold to restore","Утримуйте для відновлення","Halten zum Wiederherstellen"),
        A_AD_APP_RESTORE,!a->job.pid&&app&&app->status==AD_APP_COMPATIBLE&&valid_sha256(a->ad_media_sha),true,1400);
}
static void render_ad_media_restore(App*a){
    if(a->ad_media_apps){render_ad_app_restore(a);return;}
    bool restored=a->ad_media_folder[0]!=0;
    heading(a,ad_l("Restore shared files","Відновити спільні файли","Gemeinsame Dateien wiederherstellen"),NULL,true);
    char bytes[48],count[96];human_bytes(a->ad_media_bytes,bytes,sizeof(bytes));
    snprintf(count,sizeof(count),"%llu  /  %s",(unsigned long long)a->ad_media_files,bytes);
    text(a,40,254,0,MUTED,ad_l("Files / size","Файли / розмір","Dateien / Größe"));text(a,40,295,1,TEXT,count);
    raw_text(true);wrapped(a,40,380,640,0,TEXT,a->ad_media_path,4);raw_text(false);
    if(restored){
        text(a,40,600,0,GREEN,ad_l("Restored to","Відновлено в","Wiederhergestellt nach"));
        raw_text(true);wrapped(a,40,650,640,0,TEXT,a->ad_media_folder,4);raw_text(false);
    }else{
        wrapped(a,40,600,640,0,MUTED,ad_l("Creates a new folder in Android shared storage. Existing files stay in place.",
            "Створює нову папку у спільному сховищі Android. Наявні файли залишаються на місці.",
            "Erstellt einen neuen Ordner im gemeinsamen Android-Speicher. Vorhandene Dateien bleiben erhalten."),5);
        if(!ad_media_writable(ad_media_userdata(a)))wrapped(a,40,820,640,0,ORANGE,ad_l("Unlock and mount Android Data for writing in Files.",
            "Розблокуйте й змонтуйте Android Data для запису у «Файлах».","Android-Daten in Dateien entsperren und beschreibbar einhängen."),4);
        button(a,(Rect){28,1300,664,100},ad_l("Hold to restore","Утримуйте для відновлення","Halten zum Wiederherstellen"),
            A_AD_MEDIA_RESTORE,!a->job.pid&&ad_media_writable(ad_media_userdata(a))&&valid_sha256(a->ad_media_sha),true,1400);
    }
}
static bool start_model_backup(App*a){
    const FileVolume*data=ad_media_userdata(a),*dest=ad_media_lookup(a,a->ad_media_dest);
    bool with_apps=a->ad_migrate&&a->ad_backup_apps_selected>0;
    if(a->job.pid||a->preview||!data||!ad_media_writable(dest)||!backup_password_sent(a)||
       (with_apps&&!ad_backup_list_current(a,data))||
       !sibling_helper(a,"android_migration.py",a->ad_helper,sizeof(a->ad_helper)))return false;
    copy(a->ad_media_volume,sizeof(a->ad_media_volume),dest->id);
    char*args[29+2*AD_APP_MAX];int n=0;
    args[n++]=a->python;args[n++]=a->ad_helper;
    if(a->device)args[n++]="--device";else{args[n++]="--fixture";args[n++]=a->fixture;}
    args[n++]="--password-file";args[n++]=a->backup_password_file;args[n++]="create";args[n++]="--summary";
    if(a->ad_migrate){args[n++]="--include-personal";args[n++]="--include-settings";args[n++]="--include-shared";
        if(a->ad_migrate_root)args[n++]="--include-root-adb";
        const char*kinds=ad_migrate_kinds_text(a);if(kinds){args[n++]="--shared-types";args[n++]=(char*)kinds;}}
    else {args[n++]="--profile";args[n++]="same-model";}
    if(with_apps){
        if(a->ad_backup_include_apks)args[n++]="--include-apks";
        args[n++]="--expected-registry-sha256";args[n++]=a->ad_backup_registry_sha;
        int selected=0;
        for(int i=0;i<a->ad_backup_apps_count;i++)if(a->ad_backup_apps[i].selected){
            if(selected++>=AD_APP_MAX)return false;
            args[n++]="--package";args[n++]=a->ad_backup_apps[i].package;
        }
        if(selected!=a->ad_backup_apps_selected)return false;
    }
    args[n++]="--expected-volume-token";args[n++]=(char*)data->token;
    args[n++]="--destination-volume";args[n++]=a->ad_media_volume;
    args[n++]="--expected-destination-token";args[n++]=(char*)dest->token;args[n++]="--confirm";args[n]=NULL;
    return launch_job(a,J_AD_MODEL_BACKUP,args);
}
static void complete_model_backup(App*a,const Json*j,bool ok){
    char path[PATH_LEN]={0},sha[80]={0},code[96]="MODEL_BACKUP_FAILED",msg[384]="Full Data backup failed";
    if(j){jstring(j,0,"path",path,sizeof(path));jstring(j,0,"archive_sha256",sha,sizeof(sha));}
    const char*prefix=!strcmp(a->ad_media_volume,"userdata")?"/media/0/A22xMigrationBackups/":"/A22xMigrationBackups/";
    const char*suffix=a->ad_migrate?".tar.gz.enc":".tar.zst.enc";
    size_t n=strlen(path),k=strlen(prefix),ext=strlen(suffix);
    const char*schema="a22x.android-model-data.v1";
    /* Root and adb (on by default) is left out when this Android has neither adb settings, adb keys
       nor Magisk (2026-11-20): the copy then has the schema it has without it, and says so. */
    bool root_absent=false;
    if(a->ad_migrate){
        schema=a->ad_backup_apps_selected&&a->ad_backup_include_apks?"a22x.android-migration.v4":"a22x.android-migration.v3";
        if(a->ad_migrate_root){if(j&&jequals(j,0,"schema","a22x.android-migration.v5"))schema="a22x.android-migration.v5";else root_absent=true;}
    }
    if(!ok||!j||!jequals(j,0,"schema",schema)||!jequals(j,0,"volume",a->ad_media_volume)||
       json_uint(j,json_get(j,0,"application_count"),UINT64_MAX)!=(uint64_t)(a->ad_migrate?a->ad_backup_apps_selected:0)||
       json_bool(j,json_get(j,0,"verified"),0)!=1||!valid_sha256(sha)||n<=k+ext||strncmp(path,prefix,k)||
       strchr(path+k,'/')||strcmp(path+n-ext,suffix)||json_uint(j,json_get(j,0,"archive_bytes"),0)==0){
        if(j){int err=json_get(j,0,"error");if(err>=0){jstring(j,err,"code",code,sizeof(code));jstring(j,err,"message",msg,sizeof(msg));}}
        if(!strcmp(code,"PACKAGE_REGISTRY_CHANGED")||!strcmp(code,"PACKAGE_NOT_INSTALLED"))a->ad_backup_registry_sha[0]=0;
        files_problem(a,code,msg,ANDROID_MEDIA_BACKUP);return;
    }
    copy(a->ad_media_path,sizeof(a->ad_media_path),path);copy(a->ad_media_sha,sizeof(a->ad_media_sha),sha);
    a->ad_media_saved=true;screen(a,ANDROID_MEDIA_BACKUP);
    if(root_absent)toast(a,T("No root or adb settings were found; everything else was copied."));
}
static const char*ad_media_operation(int kind,bool encrypted){
    if(!encrypted)return job_name(kind);
    return kind==J_AD_MEDIA_INSPECT?"inspect-shared":"restore-shared";
}
static bool start_ad_apps_job(App*a,int kind){
    const FileVolume*data=ad_media_userdata(a),*source=ad_media_lookup(a,a->ad_media_volume);
    AdApp*app=ad_selected_app(a);
    bool restore=kind==J_AD_APP_RESTORE;
    if(a->job.pid||a->preview||!a->ad_media_apps||!ad_apps_target_ready(a,data)||!ad_media_volume(source)||
       strcmp(source->token,a->ad_media_token)||!ad_encrypted_media(a->ad_media_path)||!backup_password_sent(a)||
       !sibling_helper(a,"android_migration.py",a->ad_helper,sizeof(a->ad_helper)))return false;
    if(restore&&(!ad_media_writable(data)||!valid_sha256(a->ad_media_sha)||!app||app->status!=AD_APP_COMPATIBLE))return false;
    char*args[24];int n=0;args[n++]=a->python;args[n++]=a->ad_helper;
    if(a->device)args[n++]="--device";else{args[n++]="--fixture";args[n++]=a->fixture;}
    backup_password_args(a,args,&n,false);
    args[n++]=(char*)job_name(kind);
    args[n++]="--volume";args[n++]=a->ad_media_volume;
    args[n++]="--expected-volume-token";args[n++]=a->ad_media_token;
    args[n++]="--path";args[n++]=a->ad_media_path;
    args[n++]="--expected-target-token";args[n++]=a->ad_apps_target;
    if(restore){
        args[n++]="--expected-sha256";args[n++]=a->ad_media_sha;
        args[n++]="--package";args[n++]=app->package;args[n++]="--confirm";
    }
    args[n]=NULL;return launch_job(a,kind,args);
}
/* 2026-11-20: a new system's first start prepared from a migration archive (restore-root-adb
   --first-boot-kernelsu): its fresh Data, never started, gets root over adb, this recovery's adb keys,
   the settings, the apps and the Wi-Fi networks, put back by the new system itself. The archive is
   verified first (its SHA-256 then binds the preparation). */
static bool start_ad_first_boot(App*a,int kind){
    const FileVolume*data=ad_media_lookup(a,"userdata"),*source=ad_media_lookup(a,a->ad_media_volume);
    if(a->job.pid||a->preview||!data||!data->token[0]||!ad_media_volume(source)||strcmp(source->token,a->ad_media_token)||
       !ad_encrypted_media(a->ad_media_path)||!backup_password_sent(a)||
       !sibling_helper(a,"android_migration.py",a->ad_helper,sizeof(a->ad_helper)))return false;
    if(kind==J_AD_FIRST_BOOT&&!valid_sha256(a->ad_media_sha))return false;
    char*args[32];int n=0;args[n++]=a->python;args[n++]=a->ad_helper;
    if(a->device)args[n++]="--device";else{args[n++]="--fixture";args[n++]=a->fixture;}
    backup_password_args(a,args,&n,false);
    args[n++]=(char*)job_name(kind);
    args[n++]="--volume";args[n++]=a->ad_media_volume;
    args[n++]="--expected-volume-token";args[n++]=a->ad_media_token;
    args[n++]="--path";args[n++]=a->ad_media_path;
    if(kind==J_AD_FIRST_BOOT){
        args[n++]="--expected-target-token";args[n++]=(char*)data->token;
        args[n++]="--expected-sha256";args[n++]=a->ad_media_sha;
        args[n++]="--first-boot-kernelsu";args[n++]="--with-recovery-adb-keys";
        args[n++]="--stage-apps";args[n++]="--stage-wifi";
        /* The recovery's own saved networks too, as the Linux installer carries them (2026-11-21, the owner). */
        args[n++]="--with-recovery-wifi";args[n++]="--confirm";
    }
    args[n]=NULL;return launch_job(a,kind,args);
}
static void complete_ad_first_boot(App*a,const Json*j,int kind,bool ok){
    char code[96]="FIRST_BOOT_FAILED",msg[384]="The new system could not be prepared";
    if(!ok||!j||json_get(j,0,"error")>=0){
        if(j){int err=json_get(j,0,"error");if(err>=0){jstring(j,err,"code",code,sizeof(code));jstring(j,err,"message",msg,sizeof(msg));}}
        if(!strcmp(code,"WRONG_PASSWORD")){backup_password_ask(a,J_AD_FIRST_BOOT_CHECK,true,FILE_INFO);return;}
        files_problem(a,code,msg,FILE_INFO);return;
    }
    if(kind==J_AD_FIRST_BOOT_CHECK){
        char sha[80]={0};jstring(j,0,"archive_sha256",sha,sizeof(sha));
        if(!valid_sha256(sha)||!jequals(j,0,"schema","a22x.android-migration.v5")){
            files_problem(a,"ROOT_ADB_ABSENT",ad_l("This archive carries no root and adb part. Make a new transfer copy.",
                "У цьому архіві немає частини root і adb. Зробіть нову копію перенесення.",
                "Dieses Archiv enthält keinen Root- und adb-Teil. Neue Übertragungskopie erstellen."),FILE_INFO);return;
        }
        copy(a->ad_media_sha,sizeof(a->ad_media_sha),sha);
        if(!start_ad_first_boot(a,J_AD_FIRST_BOOT))files_problem(a,"FIRST_BOOT_FAILED","The new system could not be prepared",FILE_INFO);
        return;
    }
    /* What waits in the new system's data, on a page of its own with its start (2026-11-21: a toast
       alone left the work page turning after the preparation had ended). */
    int apps=0,wifi=0,keys=0,staged=json_get(j,0,"staged");bool contacts=false;char shell_root[32]={0};
    if(staged>=0){int list=json_get(j,staged,"apps");
        if(list>=0&&j->tokens[list].type==J_ARRAY)for(int i=list+1;i<j->count&&j->tokens[i].start<j->tokens[list].end;i=json_next(j,i))apps++;
        wifi=(int)json_uint(j,json_get(j,staged,"wifi_networks"),0)+(int)json_uint(j,json_get(j,staged,"recovery_wifi"),0);
        contacts=json_bool(j,json_get(j,staged,"contacts"),0)==1;}
    keys=(int)json_uint(j,json_get(j,0,"adb_keys"),0);jstring(j,0,"shell_root",shell_root,sizeof(shell_root));
    a->successful=true;copy(a->status,sizeof(a->status),"New system prepared");
    snprintf(a->message,sizeof(a->message),T(contacts?"Waiting in its data: root for adb (%s), %d adb keys, %d apps with their data, %d Wi-Fi networks and the contacts. Android puts them back itself at its first start; that start takes a few minutes longer.":
                                                       "Waiting in its data: root for adb (%s), %d adb keys, %d apps with their data and %d Wi-Fi networks. Android puts them back itself at its first start; that start takes a few minutes longer."),
             shell_root[0]?shell_root:"root",keys,apps,wifi);
    a->first_boot_ready=true;a->result_return=FILE_INFO;screen(a,RESULT);
}
static bool parse_ad_package(const Json*j,int string,char*package,size_t capacity){
    int length=json_string(j,string,package,capacity);
    if(length<=0||strlen(package)!=(size_t)length)return false;
    for(const char*p=package;*p;p++)if(!isalnum((unsigned char)*p)&&*p!='.'&&*p!='_')return false;
    return true;
}
static bool start_ad_backup_apps(App*a,const FileVolume*source){
    if(a->job.pid||a->preview||!a->ad_migrate||!source||
       !sibling_helper(a,"android_migration.py",a->ad_helper,sizeof(a->ad_helper)))return false;
    copy(a->ad_backup_source_token,sizeof(a->ad_backup_source_token),source->token);
    char*args[9];int n=0;args[n++]=a->python;args[n++]=a->ad_helper;
    if(a->device)args[n++]="--device";else{args[n++]="--fixture";args[n++]=a->fixture;}
    args[n++]="list-apps";
    args[n++]="--expected-volume-token";args[n++]=a->ad_backup_source_token;
    args[n]=NULL;return launch_job(a,J_AD_APP_LIST,args);
}
static void complete_ad_backup_apps(App*a,const Json*j,bool ok){
    char sha[80]={0};int packages=j?json_get(j,0,"packages"):-1;
    const FileVolume*data=ad_media_userdata(a);
    if(j)jstring(j,0,"registry_sha256",sha,sizeof(sha));
    bool good=ok&&j&&data&&!strcmp(data->token,a->ad_backup_source_token)&&valid_sha256(sha)&&
        jequals(j,0,"operation","list-apps")&&jequals(j,0,"volume_token",a->ad_backup_source_token)&&
        packages>=0&&j->tokens[packages].type==J_ARRAY;
    int count=0;
    if(good)for(int row=packages+1,end=json_next(j,packages);row<end;row=json_next(j,row)){
        if(count>=AD_SRC_APP_MAX){good=false;break;}
        AdSourceApp*app=&a->ad_backup_apps[count];
        if(!parse_ad_package(j,row,app->package,sizeof(app->package))||
           (count&&strcmp(a->ad_backup_apps[count-1].package,app->package)>=0)){good=false;break;}
        app->selected=false;count++;
    }
    if(!good){
        a->ad_backup_registry_sha[0]=0;
        char code[96]="APP_LIST_FAILED",message[384];
        copy(message,sizeof(message),ad_l("Could not read installed apps.","Не вдалося прочитати список застосунків.",
            "Installierte Apps konnten nicht gelesen werden."));
        int error=j?json_get(j,0,"error"):-1;
        if(error>=0){jstring(j,error,"code",code,sizeof(code));jstring(j,error,"message",message,sizeof(message));}
        files_problem(a,code,message,ANDROID_MEDIA_BACKUP);return;
    }
    a->ad_backup_apps_count=count;a->ad_backup_apps_page=0;a->ad_backup_apps_selected=0;
    copy(a->ad_backup_registry_sha,sizeof(a->ad_backup_registry_sha),sha);
    screen(a,ANDROID_APP_BACKUP_PICK);
}
static bool parse_ad_app(const Json*j,int entry,AdApp*app){
    static const char*const states[]={"identity_matches","package_missing","signing_mismatch","older_android","app_version_mismatch","no_private_data"};
    char status[48];jstring(j,entry,"status",status,sizeof(status));
    if(!parse_ad_package(j,json_get(j,entry,"package"),app->package,sizeof(app->package)))return false;
    app->apk_saved=json_bool(j,json_get(j,entry,"apk_saved"),0)==1;
    for(size_t i=0;i<sizeof(states)/sizeof(states[0]);i++)if(!strcmp(status,states[i])){app->status=(enum AdAppStatus)i;return true;}
    return false;
}
static void complete_ad_apps_job(App*a,const Json*j,int kind,bool ok){
    bool restore=kind==J_AD_APP_RESTORE;
    char sha[80]={0};
    if(j)jstring(j,0,"archive_sha256",sha,sizeof(sha));
    bool good=ok&&j&&jequals(j,0,"operation",job_name(kind))&&valid_sha256(sha)&&json_bool(j,json_get(j,0,"verified"),0)==1;
    if(good&&restore){
        AdApp*app=ad_selected_app(a);char package[201];jstring(j,0,"package",package,sizeof(package));
        good=app&&app->status==AD_APP_COMPATIBLE&&!strcmp(package,app->package)&&!strcmp(sha,a->ad_media_sha);
        if(good){app->status=AD_APP_RESTORED;a->ad_apps_selected=-1;}
    }else if(good){
        int rows=json_get(j,0,"applications");char path[PATH_LEN];jstring(j,0,"path",path,sizeof(path));
        good=rows>=0&&j->tokens[rows].type==J_ARRAY&&!strcmp(path,a->ad_media_path)&&
            jequals(j,0,"volume",a->ad_media_volume)&&jequals(j,0,"target_token",a->ad_apps_target)&&
            ad_apps_target_ready(a,ad_media_userdata(a));
        if(good){
            int count=0;
            for(int row=rows+1;row<json_next(j,rows);row=json_next(j,row)){
                if(count>=AD_APP_MAX||!parse_ad_app(j,row,&a->ad_apps[count])){good=false;break;}
                count++;
            }
            if(good){a->ad_apps_count=count;copy(a->ad_media_sha,sizeof(a->ad_media_sha),sha);}
        }
    }
    if(!good){
        char code[96]="APP_DATA_NOT_VERIFIED",message[384];
        copy(message,sizeof(message),ad_l("The app data operation could not be verified.",
            "Операцію з даними застосунку не підтверджено.","Der Vorgang für App-Daten konnte nicht bestätigt werden."));
        int error=j?json_get(j,0,"error"):-1;
        if(error>=0){jstring(j,error,"code",code,sizeof(code));jstring(j,error,"message",message,sizeof(message));}
        files_problem(a,code,message,restore?ANDROID_MEDIA_RESTORE:FILE_INFO);
        return;
    }
    screen(a,ANDROID_MEDIA_RESTORE);a->dirty=true;
}
static bool start_ad_media_job(App*a,int kind){
    bool encrypted=kind!=J_AD_MEDIA_BACKUP&&ad_encrypted_media(a->ad_media_path);
    if(a->job.pid||a->preview||!sibling_helper(a,encrypted?"android_migration.py":"android_data.py",a->ad_helper,sizeof(a->ad_helper)))return false;
    const FileVolume*data=ad_media_userdata(a),*dest=ad_media_lookup(a,a->ad_media_dest);
    if(kind==J_AD_MEDIA_BACKUP&&(!data||!ad_media_writable(dest)))return false;
    if(kind==J_AD_MEDIA_RESTORE&&(!ad_media_writable(data)||!valid_sha256(a->ad_media_sha)))return false;
    if(kind!=J_AD_MEDIA_BACKUP&&(!valid_sha256(a->ad_media_token)||!a->ad_media_path[0]))return false;
    char*args[23];int n=0;args[n++]=a->python;args[n++]=a->ad_helper;
    if(a->device)args[n++]="--device";else{args[n++]="--fixture";args[n++]=a->fixture;}
    if(encrypted){
        if(!backup_password_sent(a))return false;
        backup_password_args(a,args,&n,false);
    }
    args[n++]=(char*)ad_media_operation(kind,encrypted);
    if(kind==J_AD_MEDIA_BACKUP){
        copy(a->ad_media_volume,sizeof(a->ad_media_volume),dest->id);
        args[n++]="--expected-volume-token";args[n++]=(char*)data->token;
        args[n++]="--destination-volume";args[n++]=a->ad_media_volume;
        args[n++]="--expected-destination-token";args[n++]=(char*)dest->token;args[n++]="--confirm";
    }else{
        args[n++]="--volume";args[n++]=a->ad_media_volume;
        args[n++]="--expected-volume-token";args[n++]=a->ad_media_token;args[n++]="--path";args[n++]=a->ad_media_path;
        if(kind==J_AD_MEDIA_RESTORE){
            args[n++]="--expected-target-token";args[n++]=(char*)data->token;
            args[n++]="--expected-sha256";args[n++]=a->ad_media_sha;args[n++]="--confirm";
        }
    }
    args[n]=NULL;return launch_job(a,kind,args);
}
static void complete_ad_media_job(App*a,const Json*j,int kind,bool ok){
    enum Screen back=kind==J_AD_MEDIA_BACKUP?ANDROID_MEDIA_BACKUP:kind==J_AD_MEDIA_INSPECT?FILE_INFO:ANDROID_MEDIA_RESTORE;
    int ar=j?json_get(j,0,"archive"):-1,counts=j?json_get(j,0,"counts"):-1;
    char path[PATH_LEN]={0},sha[80]={0},folder[PATH_LEN]={0};
    if(ar>=0){jstring(j,ar,"path",path,sizeof(path));jstring(j,ar,"sha256",sha,sizeof(sha));}
    bool encrypted=kind!=J_AD_MEDIA_BACKUP&&ad_encrypted_media(a->ad_media_path);
    bool good=ok&&j&&jequals(j,0,"operation",ad_media_operation(kind,encrypted))&&jequals(j,0,"scope","android-shared-storage-user0")&&
        json_bool(j,json_get(j,0,"verified"),0)&&ar>=0&&counts>=0&&jequals(j,ar,"volume",a->ad_media_volume)&&
        path[0]=='/'&&valid_sha256(sha)&&json_uint(j,json_get(j,ar,"bytes"),0)>0;
    if(kind!=J_AD_MEDIA_BACKUP)good=good&&!strcmp(path,a->ad_media_path);
    else{
        const char*store=!strcmp(a->ad_media_volume,"userdata")?"/media/0/A22xPortableBackups/":"/A22xPortableBackups/";
        size_t prefix=strlen(store),length=strlen(path);
        good=good&&length>prefix+7&&!strncmp(path,store,prefix)&&!strchr(path+prefix,'/')&&!strcmp(path+length-7,".tar.gz");
    }
    if(kind==J_AD_MEDIA_RESTORE){
        char expected[80];snprintf(expected,sizeof(expected),"/media/0/Restored-%s-%.24s",encrypted?"Migration":"Android",a->ad_media_sha);
        if(j)jstring(j,0,"folder",folder,sizeof(folder));
        good=good&&!strcmp(sha,a->ad_media_sha)&&!strcmp(folder,expected);
    }
    if(!good){
        char code[96]="MEDIA_COPY_FAILED",message[384];
        copy(message,sizeof(message),ad_l("The portable archive operation could not be verified.","Операцію з переносимою копією не підтверджено.","Der Vorgang konnte nicht bestätigt werden."));
        if(j){int error=json_get(j,0,"error");if(error>=0){jstring(j,error,"code",code,sizeof(code));jstring(j,error,"message",message,sizeof(message));}}
        files_problem(a,code,message,back);return;
    }
    a->ad_media_files=json_uint(j,json_get(j,counts,"files"),0);a->ad_media_bytes=json_uint(j,json_get(j,counts,"file_bytes"),0);
    copy(a->ad_media_sha,sizeof(a->ad_media_sha),sha);
    if(kind==J_AD_MEDIA_BACKUP){copy(a->ad_media_path,sizeof(a->ad_media_path),path);a->ad_media_saved=true;screen(a,ANDROID_MEDIA_BACKUP);}
    else{copy(a->ad_media_folder,sizeof(a->ad_media_folder),folder);screen(a,ANDROID_MEDIA_RESTORE);}
}
/* Switch Android (2026-11-20): one Android lives on the phone at a time; changing it is these steps,
   each on the page that does it. Root and adb, the settings, apps, contacts and Wi-Fi of the old one
   come back at the new one's first start (New system in the transfer copy's file actions). */
static const char*switch_text(int step,int line){
    static const char*const t[6][2][3]={
        {{"1. Save this system and data","1. Зберегти систему й дані","1. System und Daten sichern"},
         {"Partitions to SD, and Transfer to another Android: apps, settings, root and adb.","Розділи на SD і «Перенести на інший Android»: програми, налаштування, root і adb.","Partitionen auf SD und Übertragung: Apps, Einstellungen, Root und adb."}},
        {{"2. Install the other Android","2. Встановити інший Android","2. Anderes Android installieren"},
         {"Samsung firmware, a ROM ZIP or a GSI; a saved system: Backup, Phone partitions.","Прошивка Samsung, ROM ZIP чи GSI; збережена система: «Резервна копія», «Розділи телефону».","Samsung-Firmware, ROM-ZIP oder GSI; ein gesichertes System: Sicherung, Telefonpartitionen."}},
        {{"3. Format data for Android","3. Форматувати дані для Android","3. Daten für Android formatieren"},
         {"Wipe, Data for Android: the new system starts on fresh data.","Очищення, «Дані для Android»: нова система стартує на свіжих даних.","Löschen, Daten für Android: das neue System startet auf frischen Daten."}},
        {{"4. Root for the new system","4. Root для нової системи","4. Root für das neue System"},
         {"Magisk; not needed when its BOOT has KernelSU (H3ckedUI).","Magisk; не потрібно, якщо в його BOOT є KernelSU (H3ckedUI).","Magisk; unnötig, wenn sein BOOT KernelSU hat (H3ckedUI)."}},
        {{"5. Prepare its first start","5. Підготувати перший запуск","5. Ersten Start vorbereiten"},
         {"Files, SD, A22xMigrationBackups, the copy, New system.","«Файли», SD, A22xMigrationBackups, копія, «Нова система».","Dateien, SD, A22xMigrationBackups, die Kopie, Neues System."}},
        {{"6. Restart into it","6. Перезапустити в неї","6. Darin neu starten"},
         {"Root over adb and the data come back by themselves.","Root з adb і дані повернуться самі.","Root über adb und die Daten kommen von selbst zurück."}}};
    return ad_l(t[step][line][0],t[step][line][1],t[step][line][2]);
}
static void render_switch(App*a){
    heading(a,ad_l("Switch Android","Перемкнути Android","Android wechseln"),ad_l("One Android lives on the phone at a time.",
        "На телефоні одночасно живе один Android.","Auf dem Telefon lebt jeweils ein Android."),true);
    for(int i=0;i<6;i++){
        int y=250+i*176;
        button(a,(Rect){28,y,664,92},switch_text(i,0),A_SWITCH_STEP+i,ui_free(a),i==4,0);
        wrapped(a,44,y+102,632,0,MUTED,switch_text(i,1),2);
    }
}
static bool switch_action(App*a,int id){
    if(id==A_SWITCH){if(ui_free(a)){a->page_scroll=0;screen(a,ANDROID_SWITCH);}return true;}
    if(a->screen!=ANDROID_SWITCH)return false;
    if(id==A_BACK){screen(a,OS_MENU);return true;}
    if(id<A_SWITCH_STEP||id>A_SWITCH_STEP+5||!ui_free(a))return false;
    switch(id-A_SWITCH_STEP){
    case 0:screen(a,ANDROID_BACKUP_CHOICE);break;
    case 1:case 3:a->compat_pick=false;a->page_scroll=0;screen(a,ANDROID_MENU);break;
    case 2:screen(a,WIPE);break;
    case 4:a->volume_scroll=0;a->fs_inventory_destination=FILE_VOLUMES;screen(a,FILE_VOLUMES);start_files_job(a,J_FS_INVENTORY);break;
    default:screen(a,POWER);break;
    }
    return true;
}
static bool ad_action(App*a,int id){
    if(switch_action(a,id))return true;
    if(id==A_BACKUP_ANDROID){screen(a,ANDROID_BACKUP_CHOICE);return true;}
    if(id==A_AD_PARTITIONS&&a->screen==ANDROID_BACKUP_CHOICE){identity_open_kind(a,1);return true;}
    if(id==A_AD_FILES&&a->screen==ANDROID_BACKUP_CHOICE){a->ad_known=false;screen(a,ANDROID_DATA_BACKUP);if(!start_ad_job(a,J_AD_INSPECT)){a->ad_known=true;copy(a->ad_reason,sizeof(a->ad_reason),"INSPECT_FAILED");}return true;}
    if(id==A_AD_TWRP_REVIEW&&a->screen==FILE_INFO&&ad_twrp_file(a)){
        if(!start_ad_twrp_job(a))files_problem(a,"TWRP_REVIEW_FAILED",ad_l("The backup checker could not start.",
            "Не вдалося запустити перевірку копії.","Sicherungsprüfung konnte nicht gestartet werden."),FILE_INFO);
        return true;
    }
    if(id==A_BACK&&a->screen==ANDROID_TWRP_REVIEW){screen(a,FILE_INFO);return true;}
    if((id==A_AD_MEDIA||id==A_AD_MODEL||id==A_AD_MIGRATE)&&a->screen==ANDROID_BACKUP_CHOICE){
        a->ad_model=id==A_AD_MODEL;a->ad_migrate=id==A_AD_MIGRATE;
        a->ad_media_saved=false;a->ad_media_dest[0]=0;
        a->ad_backup_registry_sha[0]=0;a->ad_backup_apps_selected=0;a->ad_backup_include_apks=true;
        a->ad_migrate_root=true;a->ad_migrate_kinds=AD_KINDS_ALL;
        screen(a,ANDROID_MEDIA_BACKUP);ad_media_refresh(a);return true;
    }
    if(id==A_AD_FIRST_BOOT&&a->screen==FILE_INFO&&ad_media_file(a)&&ad_encrypted_media(a->fs_selected.name)){
        const FileVolume*v=ad_media_lookup(a,a->volume_id);
        if(!v)return true;
        copy(a->ad_media_volume,sizeof(a->ad_media_volume),v->id);copy(a->ad_media_token,sizeof(a->ad_media_token),v->token);
        copy(a->ad_media_path,sizeof(a->ad_media_path),a->fs_selected.path);a->ad_media_sha[0]=0;
        backup_password_ask(a,J_AD_FIRST_BOOT_CHECK,false,FILE_INFO);
        return true;
    }
    if((id==A_AD_MEDIA_INSPECT||id==A_AD_APP_INSPECT)&&a->screen==FILE_INFO&&ad_media_file(a)){
        bool apps=id==A_AD_APP_INSPECT;
        const FileVolume*data=ad_media_userdata(a);
        if(apps&&!ad_encrypted_media(a->fs_selected.name))return true;
        if(apps&&!data){
            toast(a,ad_l("Unlock and mount Data in Files first.","Спочатку розблокуйте й змонтуйте Data у «Файлах».",
                "Zuerst Data in Dateien entsperren und einhängen."));
            return true;
        }
        const FileVolume*v=ad_media_lookup(a,a->volume_id);
        copy(a->ad_media_volume,sizeof(a->ad_media_volume),v->id);copy(a->ad_media_token,sizeof(a->ad_media_token),v->token);
        copy(a->ad_media_path,sizeof(a->ad_media_path),a->fs_selected.path);a->ad_media_sha[0]=a->ad_media_folder[0]=0;
        a->ad_media_apps=apps;
        if(apps){
            a->ad_apps_count=a->ad_apps_page=0;a->ad_apps_selected=-1;
            copy(a->ad_apps_target,sizeof(a->ad_apps_target),data->token);
            backup_password_ask(a,J_AD_APP_INSPECT,false,FILE_INFO);
        }else if(ad_encrypted_media(a->ad_media_path))backup_password_ask(a,J_AD_MEDIA_INSPECT,false,FILE_INFO);
        else (void)start_ad_media_job(a,J_AD_MEDIA_INSPECT);
        return true;
    }
    if(a->screen==ANDROID_MEDIA_RESTORE){
        if(id==A_BACK){a->ad_media_sha[0]=0;screen(a,FILE_INFO);return true;}
        if(a->ad_media_apps){
            int last=a->ad_apps_count?(a->ad_apps_count-1)/AD_APP_ROWS:0;
            if(id==A_AD_APP_PREV&&a->ad_apps_page>0){a->ad_apps_page--;a->ad_apps_selected=-1;}
            if(id==A_AD_APP_NEXT&&a->ad_apps_page<last){a->ad_apps_page++;a->ad_apps_selected=-1;}
            if(id>=A_AD_APP_ITEM&&id<A_AD_APP_ITEM+AD_APP_ROWS){
                int index=a->ad_apps_page*AD_APP_ROWS+(id-A_AD_APP_ITEM);
                if(index<a->ad_apps_count&&a->ad_apps[index].status==AD_APP_COMPATIBLE)a->ad_apps_selected=index;
            }
            if(id==A_AD_APP_RESTORE&&!start_ad_apps_job(a,J_AD_APP_RESTORE))
                toast(a,ad_l("Cannot start app restore","Не вдалося почати відновлення","App-Wiederherstellung konnte nicht starten"));
            a->dirty=true;return true;
        }
        if(id==A_AD_MEDIA_RESTORE&&!a->ad_media_folder[0]){(void)start_ad_media_job(a,J_AD_MEDIA_RESTORE);return true;}
    }
    if(a->screen==ANDROID_MIGRATE_OPTIONS){
        if(id==A_BACK||id==A_AD_MIG_DONE){screen(a,ANDROID_MEDIA_BACKUP);return true;}
        if(id==A_AD_MIG_ROOT)a->ad_migrate_root=!a->ad_migrate_root;
        if(id>=A_AD_MIG_KIND&&id<A_AD_MIG_KIND+AD_KINDS){
            unsigned bit=1u<<(id-A_AD_MIG_KIND),next=a->ad_migrate_kinds^bit;
            if(next&AD_KINDS_ALL)a->ad_migrate_kinds=next; /* at least one kind stays chosen */
        }
        a->dirty=true;return true;
    }
    if(a->screen==ANDROID_APP_BACKUP_PICK){
        if(id==A_BACK||id==A_AD_APP_PICK_DONE){screen(a,ANDROID_MEDIA_BACKUP);return true;}
        int count=a->ad_backup_apps_count;
        int last=count?(count-1)/AD_APP_ROWS:0;
        if(id==A_AD_APP_PREV&&a->ad_backup_apps_page>0)a->ad_backup_apps_page--;
        if(id==A_AD_APP_NEXT&&a->ad_backup_apps_page<last)a->ad_backup_apps_page++;
        if(id==A_AD_APP_PICK_APKS&&count)a->ad_backup_include_apks=!a->ad_backup_include_apks;
        if(id==A_AD_APP_PICK_ALL){
            bool select=count<=AD_APP_MAX&&a->ad_backup_apps_selected!=count;
            for(int i=0;i<count;i++)a->ad_backup_apps[i].selected=select;
            a->ad_backup_apps_selected=select?count:0;
        }
        if(id>=A_AD_APP_ITEM&&id<A_AD_APP_ITEM+AD_APP_ROWS){
            int index=a->ad_backup_apps_page*AD_APP_ROWS+(id-A_AD_APP_ITEM);
            if(index<count){
                AdSourceApp*app=&a->ad_backup_apps[index];
                if(app->selected||a->ad_backup_apps_selected<AD_APP_MAX){
                    a->ad_backup_apps_selected+=app->selected?-1:1;
                    app->selected=!app->selected;
                }
            }
        }
        a->dirty=true;return true;
    }
    if(a->screen==ANDROID_MEDIA_BACKUP){
        if(id==A_AD_MEDIA_REFRESH){ad_media_refresh(a);return true;}
        if(id==A_AD_MIG_OPTIONS&&a->ad_migrate){screen(a,ANDROID_MIGRATE_OPTIONS);return true;}
        if(id==A_AD_APP_PICK&&a->ad_migrate){
            const FileVolume*data=ad_media_userdata(a);
            if(ad_backup_list_current(a,data))screen(a,ANDROID_APP_BACKUP_PICK);
            else if(!start_ad_backup_apps(a,data))toast(a,ad_l("Could not open app list","Не вдалося відкрити список застосунків",
                "App-Liste konnte nicht geöffnet werden"));
            return true;
        }
        if(id==A_AD_MEDIA_BACKUP){
            const FileVolume*data=ad_media_userdata(a);
            if(a->ad_migrate&&a->ad_backup_apps_selected&&!ad_backup_list_current(a,data))return true;
            a->ad_media_saved=false;
            if((a->ad_model||a->ad_migrate)&&data&&ad_media_writable(ad_media_lookup(a,a->ad_media_dest)))
                backup_password_ask(a,J_AD_MODEL_BACKUP,false,ANDROID_MEDIA_BACKUP);
            else if(!a->ad_model&&!a->ad_migrate)(void)start_ad_media_job(a,J_AD_MEDIA_BACKUP);
            return true;
        }
        if(id==A_AD_MEDIA_NEXT){
            int selected=-1;
            for(int i=0;i<a->volume_count;i++)if(!strcmp(a->volumes[i].id,a->ad_media_dest)){selected=i;break;}
            for(int n=1;n<=a->volume_count;n++){
                const FileVolume*v=&a->volumes[(selected+n)%a->volume_count];
                if(ad_media_writable(v)){
                    if(strcmp(a->ad_media_dest,v->id))a->ad_media_saved=false;
                    copy(a->ad_media_dest,sizeof(a->ad_media_dest),v->id);break;
                }
            }
            a->dirty=true;return true;
        }
    }
    if(a->screen!=ANDROID_DATA_BACKUP)return false;
    if(id==A_AD_REFRESH){a->ad_known=false;if(!start_ad_job(a,J_AD_INSPECT)){a->ad_known=true;a->ad_can=false;copy(a->ad_reason,sizeof(a->ad_reason),"INSPECT_FAILED");}return true;}
    if(id==A_AD_CREATE){if(ad_ready(a))start_ad_job(a,J_AD_BACKUP);return true;}
    if(id==A_AD_VERIFY){start_ad_job(a,J_AD_VERIFY);return true;}
    return false;
}
#endif
