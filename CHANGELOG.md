# Changelog

What changed in each version of A22x Mainline Recovery, newest first. Every item
was checked on the phone unless it says otherwise. Before 0.6.124: [docs/CHANGELOG.md](docs/CHANGELOG.md);
day-by-day notes with every on-phone check: [docs/PROGRESS.md](docs/PROGRESS.md).

## 1.0.0 (2026-11-13)

The first release for every SM-A226B, after 0.6.206. In short:

- **Every SM-A226B**: the 128 GB phone as well as the 64 GB one (userdata and the eMMC are sized
  from the phone, by the rule of Samsung's PIT; tested on a 64 GB phone only).
- **Linux snapshots** restore and wipe on any SM-A226B, without a capsule made for one phone.
- **Linux data**: homes, accounts, settings and packages into another distribution or onto
  another Linux device, with `restore.sh`.
- **Copies protected with a password**, opened with `openssl` on any computer.
- **Files**: several entries at once, archives in and out, check and repair of F2FS and FAT.
- **Android**: Samsung firmware straight from its ZIP; LineageOS 20, AnyKernel3 and block-based ROMs;
  an offer to reset Android's data after a ZIP changed BOOT.
- **Code reviews** of the access gate and adb, flashing and installation, `distro.py` and
  `filesystem.py`, Linux backups, and of everything new since 0.6.206: every finding fixed.

In detail, newest first:

### Fixes from code reviews

Found by automated code reviews (the changes of 0.6.198–0.6.206, and `distro.py`,
`filesystem.py`, `dm_linear.py`), checked in the code and fixed; tested on the computer, the app's
BOOT copy also on the phone.

- **Flashing**: a write cut short is undone at the next start only when the partition is a mix of
  that very image and its saved copy (page by page); a partition written another way since (Odin,
  a second flash) is left alone. A journal that cannot be read no longer hides the others.
- **Cache**: copies a write still needs count as the newest, so older ones go; with a wrong clock
  nothing is removed; only the newest downloaded recovery stays.
- **Settings**: a change no longer lands on userdata while cache was mounted read-only (it was lost
  at the next start); a read error is no longer taken for damaged settings.
- **Updates**: a public build (`0.6.NN-public`) sees newer releases.
- **UART console**: the settings are read only when someone presses Enter, not at every start.
- **Storage**: two USB drives, an empty card reader and a microSD card pulled out while mounted no
  longer stop every command; Cancel during a copy removes the half-copied files.
- **Linux systems**: a system is removed in one rename first, so a cut removal leaves no broken
  entry; a clean install keeps every file of the image store; a dd copy of userdata can be installed
  and switched to; the new account's home goes to the shared /home; saved Wi-Fi networks (also with
  a 64-character key) reach a system installed beside; the start check replays the ext4 journal;
  network and decompression errors give an answer instead of a traceback; pax rootfs archives of
  any size and Python 3.14's tar bounds.
- **App**: one copy of BOOT at a time; room is checked before the copy.
- **Found on the phone** (0.6.208): with cache and the card mounted read-only by the recovery,
  no copy was kept before a write, so a cut write of BOOT had no way back. The copy now opens them
  for writing, and a write with no room for any copy is refused. Checked on the phone: a write of
  the stock BOOT killed after its first MiB was put back to the Magisk BOOT by resume. The tidy at
  start removes descriptions of saved BOOTs whose image is gone.
- **Samsung firmware ZIP without room beside it** (0.6.218): when the card holding a samfw.com ZIP
  has no room for its tars (5.8 GB ZIP, 7.2 GB unpacked, on a 16 GB card), they are unpacked to
  userdata (A22xFirmware/), which the installation formats for Android at its end anyway. Userdata
  encrypted by Android cannot take them: the page says to format it in Wipe first. Checked on the
  phone: A226BXXSBDZC3 from the ZIP on the card, unpacked in 2 minutes, MD5-checked, 7 partitions
  written and read back in 5 minutes; stock Android started.
- **The 128 GB SM-A226B** (1.0.0): the recovery took the size of the eMMC and of userdata from
  the 64 GB phone and refused a 128 GB one before any installation. Samsung's PIT for this model
  gives every partition before userdata a fixed place and userdata the rest of the device, so
  only these two sizes differ: the eMMC is admitted from 64 to 128 GB and userdata's sizes follow
  it (stock: 8192 sectors short of the end; grown by a Linux image: 33). Tested on the computer;
  the 64 GB phone keeps its sizes. **Not tested on a 128 GB phone.**
- **Copies of Android protected with a password, on the phone** (0.6.236): five partitions saved
  encrypted (opens with openssl on a computer), shown closed after a restart, a wrong password
  refused, verified, and restored: a damaged vbmeta_system was written back and read back.
  An archive of /home/user (402 files) made in Files with the password and extracted again,
  identical; a Linux data backup with the password restored by hand on Ubuntu with `restore.sh`
  (the password, with a space in it, typed at its prompt).
- **Fixes from the review of 0.6.207–0.6.235** (0.6.236), 15 findings, all confirmed and fixed:
  - archives extracted in Files and Linux data no longer follow a hard link out of their folder or
    make device nodes, and a part of Linux data stays in its own folder (checked on the phone: an
    archive that wrote through a hard link is refused, the file outside unchanged);
  - packing keeps one chain of folders open at a time (1100 folders packed on the phone under a
    limit of 256 descriptors; before, about 1000 folders ran out);
  - a ROM's own installer runs first; the recovery writes a block-based ROM's images itself only
    when that installer fails, and names what it did not write (dtbo, vbmeta);
  - super is laid out for a ROM in one write, tried first on a copy of its metadata, so a failure
    leaves it as it was; a ZIP without logical partitions no longer reads super at all;
  - a partition image is read back from the storage, not from the page cache;
  - an encrypted copy on a full card stops at once instead of compressing the rest;
  - Linux data: a card that is only inserted is offered as a destination; more than three backups
    are reached on further pages; a failed restore removes its staging folder (password hashes,
    keys) at once; `restore.sh` keeps spaces in a typed password and upgrades Arch whole
    (`pacman -Syu`), never partially;
  - Delete in Files leaves a folder that is itself a mount point;
  - the Brotli decoder refuses bytes after the end of its stream (checked on the phone);
  - the Backup page says which copies the password protects; EFS and IMEI copies say they are
    saved without it.
- **Linux snapshots on every SM-A226B** (0.6.234): restoring and wiping no longer need a
  qualification capsule made for one phone's eMMC. That rule dates from when the recovery could
  hardly do anything; the build now admits these itself by the model, the partitions (number,
  name, internal eMMC, admitted size) and the hash of every pinned tool, while every archive is
  still read whole before a write, BOOT is admitted by its contents and every write is read back.
  A snapshot from another A226B with the same layout is accepted. Checked on the phone without a
  capsule: userdata erased, an Ubuntu snapshot restored and verified, Ubuntu started with its
  /home (402 files) and network.
- **A card open in Files becomes the backup store** (0.6.235): the Storage page failed with
  SD_ALREADY_MOUNTED_ELSEWHERE; it now lists such a card as not mounted, and Mount lets Files'
  mount go first. Restore reads its list again when you come back from Storage. Checked on the
  phone.
- **Copies protected with a password** (0.6.231, Backup > "Protect copies with a password"): the
  password is typed once and kept in RAM until the recovery restarts. Copies of Android's
  partitions, Linux data and archives made in Files are then encrypted (`NAME.tar.zst.enc`:
  AES-256-CTR, key from PBKDF2-HMAC-SHA-256 with 600 000 rounds, an HMAC-SHA-256 over the whole
  file). A protected copy is listed closed, with a lock; a tap asks for the password and opens it;
  a wrong password is said at once; one changed byte is found before anything is restored. The
  format is the one `openssl enc -aes-256-ctr -pbkdf2` writes, so a copy opens without this recovery:
  `head -c -56 NAME.tar.zst.enc | openssl enc -d -aes-256-ctr -pbkdf2 -iter 600000 -md sha256 | tar --zstd -x`,
  and `restore.sh` of Linux data asks for the password by itself. Not encrypted: copies of the
  identity partitions (EFS) and Linux boot + rootfs snapshots. Checked on the phone: a protected
  Linux data copy made, opened on a computer with openssl, listed closed after a restart, opened
  with the password and restored.
- **A password is typed as dots** (0.6.232): the character just typed is seen for a moment, then
  becomes a dot that springs in. A new password for copies and APatch's SuperKey have "Show".
- **Check and repair for F2FS and FAT** (0.6.231): `fsck.f2fs` and `fsck.fat` from Arch Linux
  ARM's signed packages (`tools/fetch-fsck-tools.sh` fetches and verifies them). Android's
  encrypted data is left to Android. A FAT repair is confirmed by a second pass that changes
  nothing. Checked on the phone on scratch filesystems.
- **Linux data: package lists of Fedora and Alpine** (0.6.231): dnf5's own record of what was
  asked for, and apk's world. openSUSE and dnf4 keep theirs in SQLite, which the recovery cannot
  read. Not yet run against a real Fedora or Alpine system.
- **Linux data** (0.6.226, Backup > Linux data): what is one's own in a Linux system, without the
  system: home folders, accounts (with passwords and admin right), settings (host name, language,
  time zone, Wi-Fi and Bluetooth, SSH host keys) and the list of packages, each chosen by itself,
  into one archive on a card or stick (A22xDataBackups). It restores into whatever Linux is
  installed next: missing accounts are made, homes go to the account of the same name, packages
  are installed under the names the new distribution gives them and the ones it lacks are named.
  The archive carries its own restore.sh, so it restores on any other Linux device as well
  (`sudo sh restore.sh ARCHIVE`). An account that is already there keeps its password; installing
  packages never removes one that is installed; the kernel, firmware, base and network plumbing of
  the source system are not carried over.
  On the phone (0.6.227 to 0.6.230): the Arch Linux ARM of 2026-11-03 restored to userdata; its
  data saved from the menu (2 accounts, 1.4 GiB of homes, 5 Wi-Fi networks, 49 packages: 886 MiB
  in 40 s); userdata formatted; Ubuntu 26.04 with Phosh installed from a file and started; the data
  restored into it in 2 minutes: all 372 files of the homes byte for byte, owners moved to the
  accounts of the same name (the UIDs were the other way round), the missing account made, host
  name, Wi-Fi networks and SSH key in place, 38 packages there and 3 Arch-only ones named; Ubuntu
  started again with it all.
- **Files and folders into an archive, and out again** (0.6.225): in Files, a long press, the
  entries chosen, "Archive" puts them into A22xArchives/FOLDER-DATE.tar.zst on an SD card or a stick
  (tap the destination to change it); owners, permissions, times and links are kept. "Extract here"
  on such an archive (or any .tar, .tar.gz, .tar.xz) unpacks it into a new folder beside it, never
  outside that folder. The archive is portable: it opens on another A22x the same way, or with
  `tar --zstd -xf` on a computer; a short manifest after the zstd stream says what is inside.
  Checked on the phone: two folders archived on the card and extracted, every file identical.
- **Several files at once in Files** (0.6.222): a long press on a file or folder selects it;
  taps add and remove more; "Select all" / "Select none"; "Delete selected" deletes the files and
  the folders with everything in them (removed by descriptor: a symlink is removed, never
  followed; a folder holding another mount stays), after a 3-second hold, and names what could not
  be deleted. Checked on the phone on the SD card.
- **A hold acts as soon as it is full** (0.6.222): every "hold N seconds" button starts its action
  with the finger still down, instead of waiting for the lift. Checked on the phone: the delete ran
  at 4.3 s of a 6-second touch.
- **A ROM's BOOT changed after it was signed** (0.6.221): LineageOS 20 for A226B ships a boot.img
  whose AVB hash no longer fits its contents. The recovery took it for no BOOT of this phone: no
  keep-recovery mark, no format advice, and the restart into the system was refused ("no bootable
  system on userdata"). Such a BOOT is now read as changed after signing; its kernel and ramdisk
  are still checked by decoding them, and the vbmeta partition itself stays strictly checked.
- **A ZIP's own installer shows its progress in percent** (0.6.221), not as "200 B / 1000 B", and
  no speed is made up from it.
- **LineageOS 20 for A226B installed by its own update-binary** (edify, raw images into
  system, vendor, odm, product and boot): the whole ROM in 80 seconds, `script succeeded`.
- **After a ZIP changed Android's BOOT** (0.6.220): on this Samsung Android starts with a changed
  BOOT (a kernel, Magisk or APatch) only after its data is formatted. The result page says so,
  offers "Format data for Android" in place of the restart, and a restart asked for before is not
  started. Checked on the phone with an AnyKernel3 kernel ZIP for SM-A226B (BakaSU + SUSFS
  v1.4.0): the device check passed, only boot changed, its kernel is the release's Image.gz byte
  for byte; after the format stock Android A226BXXSBDZC3 started with `4.14.186 (A226B@a22x)`.
- Under a minute left, the progress page shows seconds ("About 25 s", rounded up to 5 s).
- The native ROM installation shows real sizes and speed per partition, not a fraction as bytes.
- The note after a firmware installation names the kept BOOT "the previous BOOT", Linux or not.
- **Block-based ROMs installed by the recovery itself** (0.6.217): a ZIP with full block OTA images
  (`*.new.dat` or Brotli `*.new.dat.br` with transfer lists) is written by the recovery, image by
  image into its logical partitions laid out for the ROM, each read back, then the ROM's boot.img
  when it is a BOOT of this phone; the ZIP's own updater is not run. A static Brotli decoder
  (tools/brotli_dec.c on google/brotli 1.1.0) comes with the image. Checked on the phone with the
  KKRT One UI 6.1 port: 5.5 GB written and read back; it then stopped at Samsung's Secure OS, which
  refuses its trusted apps on this phone's bootloader (binary 11).
- **What is inside an archive** (0.6.215): Flash a partition opens a ZIP, a Samsung tar or a 7z and
  lists its images with the partition each is for (a ROM's boot.img goes to boot, vendor.img to
  super/vendor), and says when the ZIP installs itself as a whole ROM; the review names the image
  inside and its own size. Checked on the phone with the KKRT ROM.
- **Linux backup on a grown userdata, and Samsung-style block ROMs** (0.6.213): a userdata grown
  to the end of the eMMC by a Linux installation is admitted by the Linux backup (on the owner's
  phone it was refused); restore and wipe need a new qualification capsule. A ROM ZIP whose
  installer writes block OTA images (transfer lists) gets super laid out for it first, when a
  partition is too small (a One UI 6 port made from the A06 has a 263 MB odm, this phone 4.3 MB),
  and the review says how; the installer writes the logical partitions through exact device-mapper
  mappings (the loop devices before ran to the end of super, so a write past a partition's end
  overwrote the next ones).
- **From the review of Linux backups, the display and the clock** (0.6.211): the Linux wipe could
  never format userdata (it held the device exclusively while mke2fs needed it too; reproduced and
  fixed on the phone); Linux snapshots are offered only on the userdata geometry they were qualified
  for (a userdata grown by a Linux installation is not, so they are not offered there); bootimage.py
  is part of what the qualification pins; plans are timed by the boot clock; archives on exFAT are
  not taken for changed; a mount hidden under another is not taken for the card; the display comes
  back when its crash guard died while dark; time servers' answers are bound to the request (checked
  on the phone); only the phone's own misc is read and cleared; a damaged BOOT in a copy gives an
  answer instead of a traceback.
- **From the review of access, adb and Android installs** (0.6.210): an installed image's links
  can no longer lead the adapter, which runs as root, to empty or write the recovery's own files
  (every path is resolved inside the image, as the system itself sees it); adb always asks the
  recovery password; approved computers are never dropped from cache and are loaded before the
  first connection; data from the computer is acknowledged when taken (a 300 MB push kept adbd at
  25 MB on the phone); a computer that vanishes ends its connection within a minute; a cut push
  leaves no open file or part file; USB endpoints are never closed under another thread; OTA
  payloads are read with the right protobuf fields; the app's hold-to-confirm is timed by the clock
  and its root commands really time out.
- **From the review of flashing, installation and copies** (0.6.209): a tar image can no longer
  write outside its folder (absolute names, `..`, a file over a link); another phone's Android data
  is never restored here; an old Android copy in a folder follows the archive's rules (locked
  partitions left, BOOT kept); a failed write inside super puts its copy back; progress output that
  nobody reads no longer stops a write (checked on the phone); old installation journals are pruned;
  an unreadable plan from the app can be forgotten; a non-list "wifi" in the app's handoff no longer
  loses the language and time zone; a tar with a folder beside its disk image imports; diagnostics
  with long logs are trimmed instead of failing.
- **Switching systems**: an account made in one system (a "New user" of a system installed
  beside the others) is added to the system switched to, when its name, UID and group are free
  there, so it no longer locks the others out; the shared /home is checked when an installation
  beside the others is planned, not at its end.
- **More from the review of `distro.py` and `filesystem.py`**: file modes despite the recovery's
  umask (new folders, `resolv.conf`), FAT32's 4 GiB limit checked before a copy or sideload, a
  download stays on the card that holds the images, status reads BOOT once and answers for
  Android's data, a system's platform files are compared as the final check compares them, a failed
  import leaves no unpacked tree, a daemon of the setup no longer holds the installation, and Files
  formats Android's userdata with the stock f2fs features.

## 0.6.198 to 0.6.206

- **Android keeps its data across restarts after a reset** (0.6.206). The reset of Android's data
  left zeros on `metadata`, and Android was trusted to make its filesystem again. A Treble GSI did
  not: it put a RAM disk on `/metadata` instead, so the key of the encrypted data lived in RAM, and
  after the next restart Android found no key and asked for a reset again (seen with Evolution X
  11.11, with and without root). The reset now leaves an empty ext4 there, as the phone's fstab
  describes it. A phone set up by an older build needs one more reset.
- **The installer app is small** (0.6.206): about 0.4 MB instead of 64 MB. It downloads the
  recovery from its release here and the Linux BOOT from the catalog's address, each checked
  against the SHA-256 written into the app, and only when it is about to install them.
- **The app updates itself** from the newest release on GitHub (checked, installed with root), and
  **keeps Android's BOOT on cache** by itself whenever it opens and Android starts: Magisk's copy
  of the original BOOT when there is one, else the BOOT there, marked with its root.
- **The app's home page fits one screen**; its six small tiles are of one size.
- **Evolution X 11.11** (without Google services) started on the phone; the catalog says so.
- **Mount userdata from an Android image's page** (0.6.204): reached through Install > Android,
  the button stayed off because the state of userdata was never read there.
- **Updates in Settings** (0.6.201): one page says which recovery is installed and which is
  published on GitHub, and whether BOOT holds the current Linux release. An update is downloaded,
  its SHA-256 and contents checked, and then written through Flash a partition: reviewed, the old
  content saved first, a hold to write.
- **Cache tidies itself at every start** (0.6.201): older copies of recovery and BOOT, BOOTs kept
  twice, older rooted BOOTs and older published Linux BOOTs go. The settings, the stock BOOT and
  the newest copies of recovery and BOOT stay.
- **ZIP installers are held tighter** (0.6.201, audit): the room is entered by `pivot_root`
  instead of `chroot`, without network, and without the rights to make device nodes, load kernel
  modules, raw I/O, ptrace or restart the phone; the bootloader chain, the modem, the identity
  partitions and the recovery are compared before and after, and a change fails the run.
- **adb over USB comes back by itself** (0.6.201): after a refused connection or a restart of the
  computer's adb server, the phone stayed "offline" until the cable was pulled.
- **Android's partitions inside super in Files** (0.6.199): `system`, `vendor`, `product`
  and `odm` are volumes of their own, opened read-only through a read-only
  device-mapper table, as Android itself maps them. While one is open the kernel holds
  super, so nothing writes super under it; an installation that needs super closes them
  first. On the phone: crDroid's system opened from Files, its `build.prop` read.
- **Cache is checked at every start** (0.6.198), as Android does: it had been mounted
  187 times without a check.
- **Audit fixes** (0.6.200):
  - The password could be passed: when the settings that hold it were not in RAM
    within 30 s, or were damaged, SSH, UART and adb were let in, and the interface
    showed itself unlocked. Now the recovery and the gate stay locked; damaged
    settings can be erased only together with userdata, as Android's reset does.
  - A BOOT or recovery image that named only the MT6833 chip was accepted, so one
    for another phone with the same chip could be flashed. Now it must name the
    SM-A226B.
  - A failed write puts the saved copy back at once, and a write cut short by a
    power loss is finished or undone at the next start.
  - `tools/build-image.sh` checks the build number before it removes its folder.
  - `FLASH_API.md` describes writing the recovery itself.

## 0.6.182 to 0.6.197

- **Why Android did not start** (0.6.183). The log of Android's kernel
  outlives a restart in the phone's memory. The recovery reads it at its start
  and, when Android's last start ended by itself, opens a page that says why,
  with the kernel's own lines: an Android that needs a newer kernel than the
  phone's (Google's Android 15 image asks for 4.19, this phone's Android
  kernel is 4.14), Android's init giving up, or a kernel panic. The page opens
  once for each such start, and the whole log goes with Export diagnostics.
  Before this the reason could only be read over a serial cable.
- **The right Linux BOOT for a new system** (0.6.182). An installation takes
  the BOOT release this recovery was made for: kept on cache, else downloaded.
  An older Linux BOOT that the phone keeps is used only when the release cannot
  be had, and a clean installation replaces an older Linux BOOT that is there.
  Before, the newest BOOT on cache won, and that could be one from an old test.
- **One battery percent for the recovery and the installed systems** (0.6.196,
  recovery kernel #137, BOOT v147 with kernel #138). The kernel's gauge keeps
  the percent it shows in the PMIC, in the byte where Android's gauge keeps its
  own, and starts its count from there while the measured voltage does not
  contradict it; the interface shows that number as it is. On the phone the
  recovery kept 94 %, Debian started from 94 %, went to 93 % under load, and
  the recovery started from 93 %. Builds 0.6.182 to 0.6.193 had the wrong
  register and showed a number of their own; 0.6.192 and 0.6.193 said the
  register could not be written, which was a mistake of the test.
- **The Linux BOOT a new system gets is v147** (0.6.196), whose kernel has that
  gauge.
- **A system that has started is no longer called untested** (0.6.196). The
  list of systems said "boot not yet tested" of every system for ever. A
  system installed by this build notes its own start, and the list reads it.
- **Wi-Fi with IPv4 in a system set up "as in the image"** (0.6.197). A system
  without NetworkManager whose setup needed no network (Debian 13 from the
  catalog, "as in the image") joined Wi-Fi at its start but got only IPv6:
  the script that applies a DHCP lease was written only when the setup itself
  used the network.
- **A full cache gives up older published Linux BOOTs** (0.6.197). Every
  installation keeps the BOOT it replaces on cache, and three Linux BOOTs, the
  stock BOOT and a rooted one filled 160 of its 200 MiB. When room is needed,
  a kept Linux BOOT that is an older release of the mainline project goes, as
  it can be downloaded again; the current release and a BOOT of one's own
  build stay.
- **A pushed file is flushed** (0.6.185). `adb push` to the recovery says
  "pushed" only after the file is on the storage.
- **An image that brings its own Phosh** (0.6.186 to 0.6.188), found with
  Manjaro ARM Phosh on the phone. Such an image has no greetd, which the
  recovery uses for the automatic sign-in, so Phosh stayed disabled and the
  phone stopped at a text login: the image's own `phosh.service` is now used
  for the chosen account. Its Mesa (24.0) keeps this phone's GPU path under the
  name `mediatek`, not `kmsro`: asked for the wrong name it drew in software,
  and Phosh's buttons answered late or not at all. Every session now asks the
  installed Mesa for the name at its start. And phoc's wlroots fix for this
  phone, which was built only where the recovery installed the desktop, is
  now built for such an image too when its phoc needs it.
- **Catalog.** Google's Android 15 images are gone from it: they cannot start
  on this phone's Android kernel.
- **A warning for Android 15 and newer** (0.6.193). The review of an Android
  image or ROM file now says when it holds Android 15 or newer: Google's own
  builds need kernel 4.19 and restart for ever on this phone's Android kernel
  4.14, while ROMs made for older phones (Treble GSIs) start. It is a warning,
  not a refusal.
- **Refusals in your language** (0.6.191). The 33 reasons for which an image
  is refused before anything is written (a damaged or cut-short image, one for
  another phone, a broken device tree or vbmeta) were shown in English only.
- **Plasma Mobile's keyboard on Debian and Ubuntu** (0.6.191). The keyboard is
  still a Qt 5 program there and needs Qt 5's Wayland plugin, which is only
  recommended: it now comes with Plasma Mobile.

## 0.6.176 to 0.6.181

- **Screenshot** (0.6.176): Volume down and Power together, in either order.
  The PNG is packed and goes to `A22xScreenshots` on a USB drive or an SD
  card, else to cache, else to RAM until the restart.
- **Flashlight** (0.6.176, brightness in 0.6.177): the camera's LED from the
  home page, the power menu and Settings, in every level the LED has (13, up
  to 175 mA, the current of Samsung's own factory torch). The level is kept;
  a power action switches the light off first.
- **Battery level** (0.6.178): the interface keeps its own estimate. The
  kernel's gauge starts from one voltage reading taken under load, which can
  be 30 points off in the flat middle of the curve; the estimate takes the
  changes from the kernel's charge counter and its position from the voltage
  corrected for the current, and learns the phone's real series resistance.
- **A copy of Android says how much room it needs** (0.6.178) before the
  first byte is written: samples of each large partition are packed the way
  the archive packs them. Too little room is refused at once, with numbers.
- **Android's data without decryption** (0.6.178): `metadata` and `userdata`
  can go into a copy as they lie on the phone, encrypted, only together and
  only when chosen. What the cell erased reads as zeros, so a copy takes
  about what the data takes. A restore zeroes ranges through the kernel.
  Android opens restored data only while the phone's secure hardware still
  holds the keys it was made with; a start of Android has not proved this yet.
- **The Linux BOOT comes by itself** (0.6.178): a new system on a phone whose
  BOOT holds Android's kernel takes a Linux BOOT kept on cache, else the
  mainline project's release, checked before anything is erased and written
  once the system is in place.
- **What started on this phone** (0.6.178): catalog entries of GSIs carry the
  result of a start on an SM-A226B where one was made.
- **A factory reset asked for in Android's settings** (0.6.179) opens the
  page that erases Android's data by itself; before, the request stayed in
  `misc` and the bootloader came back to the recovery at every start. BOOT is
  not touched, so a root in it stays for the fresh Android.
- **Several ZIPs in one go** (0.6.181), as TWRP adds more ZIPs: each is
  reviewed when it is chosen and joins a list of up to six; one hold runs
  their installers in order and stops at the first that fails, and the result
  says what became of each. A restart of the system afterwards can be asked
  for; it counts down ten seconds and can be stopped.

## 0.6.124 to 0.6.175

### Flashing

- **Flash a partition**: BOOT, RECOVERY, DTBO, vbmeta, vbmeta_system,
  vbmeta_vendor, super, prism and optics, from microSD, a USB stick or
  `userdata`; raw, sparse, gzip, LZ4, XZ or ZSTD. The old content is saved
  first (on the SD card, or in `userdata`'s image store), and the partition is
  read back after writing. RECOVERY and BOOT were flashed this way on the
  phone (2026-11-10).
- **Logical partitions inside super** (`system`, `odm`, `product`, `vendor`):
  an image (a GSI's `system.img`, raw or sparse) goes into one of them; a
  larger image makes the partition grow into super's free space within its
  group, every copy of super's metadata is rewritten and read back. A small
  partition's content is saved first, and the same image is recognised as
  already there. Checked on the phone on `odm`: written, read back, restored
  from the saved copy, super's metadata unchanged (2026-11-10).
- **Wipe** (Install → Wipe), as in TWRP: cache without the recovery's own
  folder (its settings, keys, Wi-Fi networks, plans and scripts stay), or a
  whole volume in Files. Checked on the phone (2026-11-10).
- Images are judged by their **contents**, not by a list of approved hashes
  (`bootimage.py`): a BOOT or recovery image must be complete (the kernel
  unpacks to its end, or its AVB hash matches) and made for this phone (the
  header board `SRPTL28A011`, the device tree, or the ramdisk's
  `ro.product.bootimage.device=a22x`); the check page shows what is inside,
  for example `Linux 7.2.0-a22x+ / Samsung Galaxy A22 5G (SM-A226B)`. A DTBO
  must be a valid DT table and a vbmeta a valid AVB image. An image for another
  phone, or a damaged one, is refused before anything is written.
- **Restart into the system** checks a changed BOOT, DTBO or vbmeta the same
  way, so a stock Android BOOT, a Magisk-patched one or a new Linux kernel needs
  no update of the recovery. A write that stopped part way is caught by the
  kernel stream or the AVB hash. Linux installations accept any complete Linux
  BOOT for this phone whose kernel release matches the platform modules
  (`7.2.0-a22x+`).

### Android

- **Images from archives.** An image is flashed straight from a ZIP
  (`system.img`, its only image, or one chosen by name, its CRC checked) and
  from Samsung's firmware tars (`AP_….tar.md5`: read in place through lz4);
  nothing is unpacked beside it.
- **Samsung firmware** (Install → Android), the way Odin flashes it: the AP
  file is chosen, and the CSC (or HOME_CSC), BL and CP beside it are found.
  Every file's MD5 is checked; `super`, `boot`, `dtbo`, `vbmeta` and
  `vbmeta_system` are written from the AP and `prism`, `optics` from the CSC,
  each image checked as it is read and read back after writing. This recovery
  stays; the bootloader chain (BL, `*-verified`, `tzar`), the modem and the PIT
  are never written. Then, as stock recovery does after Odin, `userdata` is
  formatted for Android (f2fs with the features of Samsung's own
  `userdata.img`: encrypt, extra_attr, project_quota, quota, verity,
  compression, checked after formatting), the start of `metadata` is erased
  (Android creates it again) and cache is wiped but for the recovery's folder.
  A Linux BOOT is saved on cache first.
- **The image catalog has filters**: category (Linux / Android), Android
  version, type (AOSP / Google apps), region (when there are several) and "For
  this phone / All phones". It lists Google's GSIs for Android 13 to 17; 13 to
  15 support this phone's vendor (Samsung's Android 12 vendor, FCM level 5), 16
  and 17 are made for newer vendors and are marked "May not start". An image is
  downloaded into the store, its SHA-256 checked.
- **GSI installation**: `system.img` from the ZIP goes into `super/system`,
  `vbmeta.img` (verification disabled, as Google flashes it) into `vbmeta`, and
  `userdata` is formatted for Android. A GSI starts with Samsung's BOOT and
  vendor, so Samsung's firmware comes first; otherwise the installation does
  not start.
- **`android_rom.py`** reads ROM packages as data, never running update-binary:
  `payload.bin` (full OTAs: REPLACE, REPLACE_XZ, REPLACE_BZ, ZERO, DISCARD, every
  operation's and partition's SHA-256 checked), block-based OTAs, image ZIPs and
  GSIs; the bootloader chain and the modem are refused.
- **Root** (Android → Root, 0.6.158): the recovery asks GitHub for the newest
  Magisk release, downloads the APK checked against the SHA-256 GitHub states,
  and patches the BOOT on the phone with Magisk's own `boot_patch.sh`, its
  `magiskboot` and `busybox` (as in a recovery: `BOOTMODE=false`, `KEEPVERITY`
  and `KEEPFORCEENCRYPT` on; `abort` only reports and unmounts nothing) in a
  private tmpfs. The patched BOOT is checked (same phone and kernel,
  `.backup/.magisk` in the ramdisk), kept on cache and written as any BOOT; the
  BOOT that was there is kept on cache first, so "Remove root" flashes the stock
  one back. Magisk 31 puts no app into BOOT: the Magisk app is installed in
  Android, and Magisk modules in it. KernelSU and KernelSU Next are not offered:
  their modules load only into GKI kernels (5.10+), and this phone's Android
  kernel is 4.14.

- **On the phone (2026-11-11):** Magisk 31.1 installed from Root; Android
  started and `su` gave a root shell. On this Samsung the first root needs
  verification off in vbmeta and Android's data erased once (shown before the
  hold). After that one reset BOOT went Magisk, stock, APatch, stock, Magisk
  and Android kept its data every time.
- **APatch** (0.6.162): KernelPatch goes into the kernel inside BOOT, by the
  steps of the APatch app's own `boot_patch.sh`. The APK's `kptools` needs
  Android's linker, so the recovery carries `kptools` built from KernelPatch's
  source (`apatch/build-kptools.sh`, inputs pinned by SHA-256) and its `kpimg`;
  nothing is downloaded. The SuperKey is typed on the phone, reaches the
  helper in a file of the private RAM folder and is kept nowhere. Checked on
  the phone: KernelPatch 0.13.9 answered from the running Android kernel and
  accepted only the right SuperKey.
- **ZIP with an installer** (0.6.164, TWRP's Install): a flashable ZIP's own
  `update-binary` runs as root in a room of its own (new mount and process
  spaces, a tmpfs root, a busybox shell with `getprop`). Its `/dev` holds only
  boot, dtbo, the vbmeta partitions, super, prism, optics and super's logical
  partitions; the bootloader chain, the modem, this recovery, `userdata` and
  the recovery's folder on cache are out of its reach. The BOOT there is kept
  on cache first, and the result names the partitions that changed. Checked on
  the phone with Magisk's ZIP. For an installer that is a program (edify) the
  room holds Android's property area at `/dev/__properties__` (0.6.167), with
  the phone's names and what the installed Android's `build.prop` files say;
  a ROM package that maps super's partitions itself (edify's
  `map_partition`, `update_dynamic_partitions`) finds the device mapper and
  the nodes it waits for (0.6.172), and what it leaves mapped is removed
  afterwards. Checked on the phone with the updater of a LineageOS 23.2
  package and scripts of our own that write nothing; a whole ROM package has
  not been installed this way yet.
- **The catalog lists LineageOS** 22.2 (plain and with Google apps) and 23.2,
  the GSIs AndyYan publishes, each pinned by SHA-256.
- **Cache looks after itself** (0.6.162): when room is needed, the second copy
  of the same BOOT, older copies of a partition kept before a write and older
  BOOTs with root are removed; the stock BOOT, a Linux BOOT, settings, keys
  and Wi-Fi networks stay.
- **Back returns to the page before** (0.6.161), from every page: the pages
  passed are remembered, a Back pressed while a page is still being read is
  made after the read, and a read that ends for a page already left opens
  nothing.

- **Restore and Verify have two categories, Linux and Android** (0.6.174).
  Copies of Android's partitions are looked for on every mounted SD card and
  USB drive; a card that is not mounted is a row of its own, and a tap mounts
  it read-only and searches it. Without storage for Linux snapshots the page
  opens on Android. The page of a copy shows its partitions (a tap leaves one
  out), checks the copy, restores it by a hold and deletes it.
- **A copy of Android is one compressed archive** (0.6.174): `NAME.tar.zst`
  in `A22xAndroidBackups`, a tar of the partition images and a manifest,
  packed by zstd on every core. A skippable frame after the zstd stream holds
  the manifest again, so a list of copies reads a few kilobytes, and on a
  computer plain `tar --zstd -xf` unpacks the archive. A restore checks the
  whole archive first, writes only the pieces that differ and reads each
  partition back. Recovery and cache are in no copy. The BOOT that was on the
  phone is kept on cache, and a restored Android BOOT gets the mark that
  keeps this recovery. The bootloader locks dtbo and vbmeta while the phone
  runs: when they differ they are left as they are (and with verification on
  in vbmeta the restore refuses before it writes). Folder copies made before
  stay readable. On the phone: super, 6.9 GiB, became 2.93 GiB in about two
  minutes; the seven other partitions, 768 MiB, became 410 MiB; restoring an
  identical copy wrote nothing (the partitions' write counters did not move);
  after the stock BOOT was flashed, a restore rewrote 15 MiB of 32 and the
  SHA-256 of BOOT matched the copy again.
- **"From a file" opens a sheet that asks where the file is** (0.6.174): the
  SD card and USB drives; a tap mounts the one chosen read-only and opens its
  folders, and Back from its top folder returns to the sheet. On a phone whose
  userdata holds Android nothing needs mounting: a clean Linux installation
  is planned on the partition as it will be once formatted, and the format
  itself waits for the confirmed start of the installation. When BOOT holds
  Android's kernel, the New system page says so at once and leads to Flash a
  partition (0.6.175): Linux starts with its own BOOT. Since 0.6.178 the
  installation takes that BOOT with it (see below).
- **"ROM from a file"** in the Android menu (0.6.174): the file is chosen on
  a card, a stick or cache, and the recovery opens the review that installs
  it: a ZIP with an installer, a system image (raw, sparse, xz, gz, or a ZIP
  or 7z that holds one) or Samsung's firmware; a `payload.bin` update for
  phones with two slots is refused with an explanation. Checked on the phone
  up to the review pages.
- **The catalog shows the category of what is being installed** (0.6.174):
  only Linux from New system, only Android from the Android menu, both from
  Home.
- **`adb sideload` also works with Android on userdata** (0.6.173): the file
  goes to the store on a card (or to `cache:/sideload` without one), and a ZIP
  opens its review at once, as TWRP's sideload does. Checked on the phone to
  the end of a test installer.
- **An Android image is downloaded on a phone that runs Android** (0.6.170).
  Saved images lived only beside the Linux systems on userdata, so a phone
  with Android there had no place for a download. Now the store is the same
  folder, `.a22x-images`, on an SD card or a USB drive when userdata holds no
  Linux: the page says "Download to the card", the helper mounts the card for
  the download and leaves it read-only, and the installation is reviewed from
  that card. Linux images keep their place on userdata. Checked on the phone:
  LineageOS 22.2 downloaded to the SD card, its SHA-256 equal to the
  catalog's, and the review of its installation opened; the installation
  itself, which erases Android's data, has not been run.
- **A backup is renamed and deleted on its page** (0.6.167, as on TWRP's
  Restore page): Restore > a backup > Rename, or hold Delete for 3 seconds. The
  backend touches only a folder that loads as a finished backup, and deletes
  it only under its own name. A copy of phone partitions is deleted the same
  way from its list. Checked on the phone on the SD card.
- **Settings are reset** (0.6.167, TWRP's Restore defaults) by a hold at the
  end of Settings: theme, terminal colours, animation, navigation, vibration,
  screen timeout, brightness and refresh rate. The language, the time zone,
  the password with its lock mode, Wi-Fi networks and keys stay.
- **A card is partitioned** (0.6.167, TWRP's Partition SD card): Install >
  Wipe > Partition a card. `sdcard.py` writes a new MBR table with a FAT32
  partition for files and, on request, ext4 for Linux and swap, on 4 MiB
  borders, and makes the filesystems with the tools in the image. Only the
  card in the slot and USB drives are offered; a card that is mounted, held,
  shared over USB or write-protected is refused, and the apply is bound to the
  card as it was shown. On the phone the whole path was run on a loop device
  over a file in RAM (table, kernel reread, `mkdosfs`, `mkfs.ext4`, `mkswap`,
  then `blkid`, mounts and `fdisk -l`); no real card has been erased yet.
