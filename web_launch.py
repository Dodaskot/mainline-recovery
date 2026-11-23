"""Mount the verified A22x browser runtime in a private mount and PID namespace."""
import ctypes
import fcntl
import hashlib
import ipaddress
import json
import os
import re
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import traceback

import filesystem as fs
import web_cache

ENGINE_SHA = 'e203ce1df3ad0328952acb28f1a4498750c01bdecc700d7ad926c601e8d441c6'
ENGINE_SIZE = 145510400
MESA_SHA = '8c59439653fe238003f787ecfe53d03265a57cecffdb46cf699ce8ae88f4c611'
MESA_SIZE = 58843136
DIRECT_SHA = '9d73d0e92044ec3a6ab93d92fc53cc4c66e123f96b99c183a43e58a4f158c854'
DIRECT_SIZE = 122966016
PANFROST_DEVICE = web_cache.PANFROST_DEVICE
PANFROST_DRIVER = web_cache.PANFROST_DRIVER
FULL_CHROMIUM = 'usr/lib/chromium/chromium'
UID = 65534
# The UI's own socket for frame messages (2026-11-20): the compositor sends F0/F1 there and the UI
# answers A0/A1 there, without the Python session on the way. Absent, fd 6 holds /dev/null.
FRAMES_FD = 6
# Root-only switches for measuring (RAM, optional): {"gpu_raster": false, "direct_frames": false}.
OPTIONS = Path('/run/a22x-recovery/web-options.json')


def reserve_frames_fd():
    """Whether fd 6 is the UI's frame socket. Anything else there is replaced by /dev/null, so no
    descriptor opened later takes number 6 and passes into the browser's namespace by mistake."""
    import socket
    try:
        info = os.fstat(FRAMES_FD)
        if stat.S_ISSOCK(info.st_mode):
            probe = socket.socket(fileno=os.dup(FRAMES_FD))
            try:
                if probe.family == socket.AF_UNIX and probe.type == socket.SOCK_SEQPACKET:
                    return True
            finally:
                probe.close()
    except OSError:
        pass
    null = os.open('/dev/null', os.O_RDONLY)
    os.dup2(null, FRAMES_FD, inheritable=True)
    os.close(null)
    return False


def options():
    """The measuring switches, if the recovery wrote any; defaults otherwise."""
    import json
    wanted = {'gpu_raster': True, 'direct_frames': True}
    try:
        info = os.lstat(OPTIONS)
        if stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_size <= 4096:
            value = json.loads(OPTIONS.read_text())
            wanted.update({key: value[key] for key in wanted if isinstance(value.get(key), bool)})
    except (OSError, ValueError, AttributeError):
        pass
    return wanted


CARD_MOUNTS = ('/mnt/backup', '/mnt/volumes/')


def detach_cards(mountinfo=None, umount=None):
    """Let every volume of the recovery go in the browser's own namespace (2026-11-20, on the phone:
    its private copy kept the card mounted as ext4 after Files let it go, the card was then formatted
    FAT32, and the stale mount could have written into it). The browser needs none: downloads wait
    in RAM and are delivered from the recovery's own namespace. Deepest first, detached."""
    text = Path('/proc/self/mountinfo').read_text() if mountinfo is None else mountinfo
    points = []
    for line in text.splitlines():
        fields = line.split(' - ', 1)[0].split()
        if len(fields) < 5:
            continue
        point = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), fields[4])
        if point == CARD_MOUNTS[0] or point.startswith(CARD_MOUNTS[0] + '/') or point.startswith(CARD_MOUNTS[1]):
            points.append(point)
    if umount is None:
        libc = ctypes.CDLL(None, use_errno=True)
        def umount(point):
            if libc.umount2(os.fsencode(point), 2):  # MNT_DETACH
                raise OSError(ctypes.get_errno(), 'Browser could not let a volume go: ' + point)
    for point in sorted(points, key=lambda value: value.count('/'), reverse=True):
        umount(point)
    return points


def mount(*args, keep=()):
    if args[0]=='--bind':
        libc=ctypes.CDLL(None,use_errno=True)
        if libc.mount(os.fsencode(args[1]),os.fsencode(args[2]),None,4096,None):
            raise OSError(ctypes.get_errno(),'Browser bind mount failed: '+str(args[2]))
        return
    subprocess.run(['/bin/mount', *map(str, args)], check=True, pass_fds=keep, stdout=subprocess.DEVNULL)


# Optional offline packages a card may carry. The browser only reads them, once per start,
# into RAM; nothing is ever created or changed on the card. The card's engine has the headless
# shell; its Wayland package adds the full Chromium to it. The RAM engine has the full Chromium.
PACKAGES = {'engine': ('a22x-web-engine.sqfs', ENGINE_SIZE, ENGINE_SHA),
            'mesa': ('a22x-web-mesa-panfrost.sqfs', MESA_SIZE, MESA_SHA),
            'wayland': ('a22x-web-wayland.sqfs', DIRECT_SIZE, DIRECT_SHA)}
RAM_RESERVE = 384 << 20


def ram_available():
    for line in Path('/proc/meminfo').read_text().splitlines():
        if line.startswith('MemAvailable:'):
            return int(line.split()[1]) * 1024
    return 0


def load_package(directory, name, size, expected):
    """Copy a package into a sealed memfd, verifying it on the way; None when the card lacks it."""
    try:
        fd = os.open(name, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC, dir_fd=directory)
    except FileNotFoundError:
        return None
    # Verification and the loop mount consume the same immutable bytes.
    with os.fdopen(fd,'rb') as source:
        st = os.fstat(source.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_size != size:
            raise RuntimeError('Incorrect browser package')
        image = os.memfd_create(name, os.MFD_ALLOW_SEALING)
        try:
            with open(image, 'wb', closefd=False) as verified:
                digest = hashlib.sha256()
                remaining = size
                while remaining:
                    chunk = source.read(min(1<<20, remaining))
                    if not chunk:
                        raise RuntimeError('Incomplete browser package')
                    verified.write(chunk)
                    digest.update(chunk)
                    remaining -= len(chunk)
            if digest.hexdigest() != expected:
                raise RuntimeError('Browser package verification failed')
            fcntl.fcntl(image, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SEAL)
            return image
        except BaseException:
            os.close(image)
            raise


def offline_packages(wanted):
    """Verified copies in RAM of the packages a mounted card carries. The card is only read and
    is released before the browser starts; any problem there simply leaves the package out. Shared: the
    browser opens beside a running operation and must never take storage from it (2026-11-22, the
    owner); an operation that holds storage alone leaves the card unread."""
    images = {}
    try:
        ctx = fs.DeviceContext()
        with ctx.operation_lock(shared=True):
            card = next((v for v in ctx.volumes() if v['id'] == 'sdcard-p1' and v['mounted']), None)
            if card is None:
                return images
            with fs.PinnedVolume(ctx, 'sdcard-p1', card['volume_token']) as pin, pin.directory('/') as directory:
                for key in wanted:
                    name, size, digest = PACKAGES[key]
                    if key == 'wayland' and 'engine' in wanted and 'engine' not in images:
                        continue  # it completes only the card's engine; the RAM engine has Chromium
                    if ram_available() < size + RAM_RESERVE:
                        continue
                    if key == 'engine':
                        web_cache.notify('Loading web engine from SD into RAM')
                    try:
                        image = load_package(directory, name, size, digest)
                    except (OSError, RuntimeError):
                        image = None
                    if image is not None:
                        images[key] = image
                pin.recheck()
    except (OSError, RuntimeError, fs.FilesystemError):
        pass
    except BaseException:
        for image in images.values():
            os.close(image)
        raise
    return images


def mount_image(image, root):
    mount('-o','loop,ro,nosuid,nodev','-t','squashfs',f'/proc/self/fd/{image}',root,keep=(image,))


def panfrost_render_node():
    if (PANFROST_DEVICE/'driver').resolve() != PANFROST_DRIVER:
        module = web_cache.PANFROST_MODULE
        if os.uname().release != web_cache.PANFROST_RELEASE or not module.is_file():
            raise RuntimeError('Matching Panfrost module unavailable')
        subprocess.run(['/bin/busybox','insmod',str(module)], check=True, timeout=5)
    if (PANFROST_DEVICE/'driver').resolve() != PANFROST_DRIVER:
        raise RuntimeError('Panfrost driver unavailable')
    for path in sorted((PANFROST_DEVICE/'drm').glob('renderD*')):
        st = (Path('/dev/dri')/path.name).stat()
        if stat.S_ISCHR(st.st_mode) and os.major(st.st_rdev) == 226 and os.minor(st.st_rdev) >= 128:
            if (path/'dev').read_text().strip() == f'226:{os.minor(st.st_rdev)}':
                return path.name, st.st_rdev
    raise RuntimeError('Panfrost render node unavailable')


def gpu_node_for(root, node):
    """NODE when ROOT can take the GPU's sysfs, else None: an engine tree made before sys was one of
    its mount points (or a card's engine without it) draws in software instead of failing to start
    (2026-11-20, a tester: the browser never opened with the GPU layer)."""
    if node and not (root/'sys').is_dir():
        print('browser: no /sys mount point in its root; drawing without the GPU', file=sys.stderr, flush=True)
        return None
    return node


def bind_render_node(root, node):
    name, device = node
    sysfs = root/'sys'
    mount('-t','tmpfs','-o','size=1m,mode=755,nosuid,nodev,noexec','tmpfs',sysfs)
    for path in ('dev/char', 'class/drm', 'bus/platform', PANFROST_DEVICE.relative_to('/sys')):
        (sysfs/path).mkdir(parents=True)
    for path, _, _ in os.walk(sysfs):
        os.chmod(path,0o555)
    gpu = sysfs/PANFROST_DEVICE.relative_to('/sys')
    mount('--bind',PANFROST_DEVICE,gpu)
    mount('-o','remount,bind,ro,nosuid,nodev,noexec',gpu)
    target = '../../'+str(PANFROST_DEVICE.relative_to('/sys')/'drm'/name)
    os.symlink(target,sysfs/'dev/char'/f'226:{os.minor(device)}')
    os.symlink(target,sysfs/'class/drm'/name)
    mount('-o','remount,ro,nosuid,nodev,noexec',sysfs)
    dri = root/'dev/dri'
    dri.mkdir()
    dri.chmod(0o755)
    os.mknod(dri/name,stat.S_IFCHR|0o600,device)
    os.chown(dri/name,UID,UID)


# Where the browser's sound goes (sound.py, media/a22x_switch.c; 2026-11-22, the owner: YouTube stayed
# on the speaker with Bluetooth headphones connected).
SOUND_SELECT = Path('/run/a22x-recovery/sound/output')
SWITCH_PLUGIN = Path(__file__).with_name('alsa')/'libasound_module_pcm_a22x_switch.so'
MEDIA_RUN = Path('/run/a22x-recovery/media')
BLUEALSA_PLUGIN = MEDIA_RUN/'root/usr/lib/alsa-lib/libasound_module_pcm_bluealsa.so'


def bind_sound_output(root, home):
    """The switch's plugin (from the image) and BlueALSA's (from the media runtime) copied into the
    browser's /tmp/a22x-sound, root's and read only for the browser; the file naming the output as
    ~/.a22x-output, read only; and the media runtime's system bus at /run/dbus, where BlueALSA's plugin
    asks for the headphones' stream (the bus lets the browser's user speak to BlueALSA only,
    media_service). Anything missing leaves the sound on the phone (the switch's fallback)."""
    plugins = root/'tmp/a22x-sound'
    plugins.mkdir(mode=0o755)
    plugins.chmod(0o755)
    for source in (SWITCH_PLUGIN, BLUEALSA_PLUGIN):
        try:
            if source.is_file() and source.stat().st_size <= 4 << 20:
                copy = plugins/source.name
                copy.write_bytes(source.read_bytes())
                copy.chmod(0o644)
        except OSError:
            pass
    if SOUND_SELECT.is_file():
        select = home/'.a22x-output'
        select.touch(0o644)
        mount('--bind', SOUND_SELECT, select)
        mount('-o', 'remount,bind,ro,nosuid,nodev,noexec', select)
    bus = MEDIA_RUN/'run/dbus'
    if (bus/'system_bus_socket').exists() and (root/'run').is_dir():
        mount('-t', 'tmpfs', '-o', 'size=64k,mode=755,nosuid,nodev,noexec', 'tmpfs', root/'run')
        (root/'run/dbus').mkdir(mode=0o755)
        mount('--bind', bus, root/'run/dbus')
        mount('-o', 'remount,bind,ro,nosuid,nodev,noexec', root/'run/dbus')


def bind_sound(root, home):
    """The sound card for the browser (2026-11-20): its nodes, owned by the browser's user, and the
    recovery's ALSA configuration (sound.py) as ~/.asoundrc, read only. Without a card the browser
    runs as before, silent."""
    source, conf = Path('/dev/snd'), Path('/run/a22x-recovery/sound/asoundrc')
    if not source.is_dir() or not conf.is_file():
        return False
    target = root/'dev/snd'
    target.mkdir()
    target.chmod(0o755)
    for node in sorted(source.iterdir()):
        info = node.lstat()
        if stat.S_ISCHR(info.st_mode) and re.fullmatch(r'(controlC0|pcmC0D[0-9]+[pc]|timer)', node.name):
            os.mknod(target/node.name, stat.S_IFCHR|0o600, info.st_rdev)
            os.chown(target/node.name, UID, UID)
    rc = home/'.asoundrc'
    rc.touch(0o644)
    mount('--bind', conf, rc)
    mount('-o', 'remount,bind,ro,nosuid,nodev,noexec', rc)
    bind_sound_output(root, home)
    return True


def full_chromium(layer):
    return (Path(layer)/FULL_CHROMIUM).is_file()


# Schemes of app links that go straight to xdg-open, without Chromium's "Open xdg-open?" dialog: touch did
# not reach it and the tab stayed under it (2026-11-21, #6, a link from Google Play). This layer's
# xdg-open hands the address to web_session, which shows a notice for the app link.
APP_SCHEMES = ('intent', 'market', 'android-app', 'tel', 'sms', 'smsto', 'mms', 'mailto', 'geo', 'maps',
               'whatsapp', 'tg', 'viber', 'signal', 'sgnl', 'fb', 'fb-messenger', 'instagram', 'twitter',
               'snssdk1233', 'spotify', 'zoomus', 'zoommtg', 'msteams', 'skype', 'line', 'kakaotalk', 'upi',
               'comgooglemaps', 'waze', 'itms-apps', 'itms-services', 'steam', 'discord', 'slack',
               'vnd.youtube', 'youtube', 'magnet', 'bitcoin')
XDG_OPEN = '''#!/usr/bin/python3 -I
import os, sys
try:
    fd = os.open('/tmp/a22x-links', os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    os.write(fd, (sys.argv[1] if len(sys.argv) > 1 else '').replace('\\n', ' ').encode('utf-8', 'replace')[:4000] + b'\\n')
    os.close(fd)
except OSError:
    pass
'''


def links_layer(workspace):
    """A layer with Chromium's policy for app links and the xdg-open that hands them over, or None."""
    layer = workspace/'links'
    try:
        # Each folder 0755 by hand: in the overlay the top layer's folder decides the mode of /etc, /usr and
        # /usr/bin, and the launcher's umask made them 0700 (2026-11-21, on the phone: the browser's user could
        # not run /usr/bin/python3).
        for folder in ('', 'etc', 'etc/chromium', 'etc/chromium/policies', 'etc/chromium/policies/managed', 'usr', 'usr/bin'):
            (layer/folder).mkdir(exist_ok=True)
            (layer/folder).chmod(0o755)
        policy = layer/'etc/chromium/policies/managed/a22x-app-links.json'
        policy.write_text(json.dumps({'AutoLaunchProtocolsFromOrigins': [
            {'protocol': scheme, 'allowed_origins': ['*']} for scheme in APP_SCHEMES]}))
        policy.chmod(0o644)
        tool = layer/'usr/bin/xdg-open'
        tool.write_text(XDG_OPEN)
        tool.chmod(0o755)
        return layer
    except OSError:
        return None


def runtime_layers(workspace, engine, images, graphics=None):
    """The layers of the browser's root, top first, and the GPU render node when the GPU serves.
    GRAPHICS is the GPU layer prepared in RAM; a card's Mesa package stands in for it."""
    layers = [engine]
    node = None
    if graphics or 'mesa' in images:
        try:
            if graphics:
                hardware = graphics
            else:
                hardware = workspace/'mesa'
                hardware.mkdir(exist_ok=True)
                mount_image(images['mesa'],hardware)
            node = panfrost_render_node()
            layers.insert(0,hardware)
        except (OSError, RuntimeError, subprocess.SubprocessError):
            node = None
    if 'wayland' in images and not full_chromium(engine):
        desktop = workspace/'wayland'
        desktop.mkdir(exist_ok=True)
        try:
            mount_image(images['wayland'],desktop)
            layers.insert(0,desktop)
        except (OSError, subprocess.SubprocessError):
            pass
    return layers, node


def session(workspace, directory, dest, engine, images, graphics=None, frames=False, profile=None):
    """PROFILE: an open folder that holds the browser's profile across its starts (web_cache.profile),
    or None for a fresh one."""
    switches = options()  # read before the browser's root hides /run
    root = workspace/'root'
    root.mkdir(exist_ok=True)
    if not engine:
        engine = workspace/'engine'
        engine.mkdir(exist_ok=True)
        try:
            mount_image(images['engine'],engine)
        except (KeyError, OSError, subprocess.SubprocessError):
            engine = web_cache.ensure()
    layers, node = runtime_layers(workspace, engine, images, graphics)
    links = links_layer(workspace)
    if links is not None:
        layers.insert(0, links)
    if len(layers) > 1:
        lower = ':'.join(map(str,layers))
        try:
            mount('-t','overlay','-o',f'lowerdir={lower},ro,nosuid,nodev','overlay',root)
        except subprocess.SubprocessError:
            layers, node = [engine], None
    if len(layers) == 1:
        mount('--bind',engine,root)
        mount('-o','remount,bind,ro,nosuid,nodev',root)
    # Direct output needs the full Chromium (the RAM engine, or a card's Wayland package) and the
    # image's compositor; otherwise the screencast serves (web_session picks the executable).
    compositor = Path(__file__).with_name('web-compositor')
    direct = compositor.is_file() and any(full_chromium(layer) for layer in layers)
    mount('-t','proc','-o','nosuid,nodev,noexec','proc',root/'proc')
    mount('-t','tmpfs','-o','size=256m,mode=1777,nosuid,nodev','tmpfs',root/'tmp')
    mount('-t','tmpfs','-o','size=1m,mode=755,nosuid,noexec','tmpfs',root/'dev')
    for name, minor in [('null',3),('zero',5),('random',8),('urandom',9)]:
        os.mknod(root/'dev'/name,stat.S_IFCHR|0o666, os.makedev(1,minor))
        os.chmod(root/'dev'/name,0o666)
    (root/'dev/shm').mkdir()
    mount('-t','tmpfs','-o','size=64m,mode=1777,nosuid,nodev,noexec','tmpfs',root/'dev/shm')
    os.symlink('/proc/self/fd',root/'dev/fd')
    node = gpu_node_for(root,node)
    if node:
        bind_render_node(root,node)
    resolvers = []
    for line in Path('/etc/resolv.conf').read_text().splitlines():
        fields = line.split()
        if len(fields)>=2 and fields[0]=='nameserver':
            resolvers.append(str(ipaddress.ip_address(fields[1])))
    dns = root/'tmp/resolv.conf'
    dns.write_text(''.join('nameserver '+v+'\n' for v in resolvers))
    dns.chmod(0o444)
    mount('--bind',dns,root/'etc/resolv.conf')
    mount('--bind',Path(__file__).with_name('web_session.py'),root/'opt/web_session.py')
    if direct:
        mount('--bind',compositor,root/'opt/web-compositor')
        mount('-o','remount,bind,ro,nosuid,nodev',root/'opt/web-compositor')
    # Fresh per-session directory. A web download cannot replace a recovery image.
    downloads=os.open(dest,os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory)
    mount('--bind',f'/proc/self/fd/{downloads}',root/'downloads',keep=(downloads,))
    os.close(downloads)
    # The browser's home in its scratch space, with the profile of this recovery session in it.
    home = root/'tmp/home'
    home.mkdir(mode=0o700)
    os.chown(home, UID, UID)
    if profile is not None:
        (home/'profile').mkdir(mode=0o700)
        os.chown(home/'profile', UID, UID)
        mount('--bind', f'/proc/self/fd/{profile}', home/'profile', keep=(profile,))
    sound = bind_sound(root, home)
    # The recovery root is initramfs. Stack the private runtime at the namespace
    # root so Chromium can create its own user namespace after setuid.
    libc=ctypes.CDLL(None,use_errno=True)
    os.chdir(root)
    if libc.mount(b".",b'/',None,8192,None):
        raise OSError(ctypes.get_errno(),'Cannot switch browser mount root')
    os.chroot(".")
    os.chdir('/')
    os.closerange(3,5)
    os.closerange(FRAMES_FD+1,65536)  # fd 6: the UI's frame socket, or /dev/null
    os.mkdir('/tmp/runtime',0o700)
    os.chown('/tmp/runtime',UID,UID)
    os.setgroups([])
    os.setgid(UID)
    os.setuid(UID)
    if ctypes.CDLL(None).prctl(38,1,0,0,0):
        raise RuntimeError('Cannot restrict browser privileges')
    env = dict(HOME='/tmp/home',PATH='/usr/bin:/bin',XDG_RUNTIME_DIR='/tmp/runtime',LANG='C.UTF-8',WEB_DOWNLOAD_FOLDER='Download finished')
    if sound:
        # The whole ALSA configuration (sound.py): an engine from a card has no /usr/share/alsa.
        env.update(ALSA_CONFIG_PATH='/tmp/home/.asoundrc', A22X_WEB_SOUND='1')
    if node:
        env.update(A22X_WEB_GPU='1', EGL_PLATFORM='surfaceless', MESA_LOADER_DRIVER_OVERRIDE='panfrost',
                   GBM_BACKENDS_PATH='/usr/lib/gbm', LIBGL_DRIVERS_PATH='/usr/lib/dri')
        if not switches['gpu_raster']:
            env['A22X_WEB_RASTER'] = '0'
    if direct:
        env['A22X_WEB_WAYLAND'] = '1'
        if frames and switches['direct_frames']:
            env['A22X_WEB_FRAMES'] = '1'
    os.execve('/usr/bin/python3',['python3','-I','-B','/opt/web_session.py'],env)


def run(ram_only=False, frames=False):
    """The whole session lives in RAM: the engine (RAM cache, or a card's package copied into RAM),
    its scratch space and its downloads. Nothing is created on a card; when the browser closes its
    namespace, mounts and RAM copies go away and an unused download folder is removed.
    The GPU layer prepared in RAM after Wi-Fi joined is used when it is there; a browser started
    before it is ready runs without it (a card's Mesa package can stand in).
    FRAMES: fd 6 is the UI's own socket for frame messages (reserve_frames_fd)."""
    with tempfile.TemporaryDirectory(prefix='web-') as path:
        engine = web_cache.cached()
        gpu = web_cache.gpu_supported()
        graphics = web_cache.cached(web_cache.GPU_MANIFEST) if gpu else None
        wanted = [key for key, need in (('engine', not engine), ('mesa', gpu and not graphics),
                                        ('wayland', not engine)) if need]
        images = {} if ram_only else offline_packages(wanted)
        try:
            if engine is None and 'engine' not in images:
                engine = web_cache.ensure()
            if engine is not None and gpu and not graphics and 'mesa' not in images and not ram_only:
                # The GPU layer is waited for, as the engine is (2026-11-21, on the owner's phone and a
                # tester's: a browser opened in the first minute, before the layer prepared after Wi-Fi
                # was ready, started without the GPU, and Chromium's GPU process then failed three
                # times: "GPU process isn't usable. Goodbye.").
                try:
                    graphics = web_cache.ensure(manifest=web_cache.GPU_MANIFEST)
                except Exception as error:  # no network, no room: without it, for this start
                    print('browser: GPU layer not prepared: ' + str(error)[:120], file=sys.stderr, flush=True)
                    graphics = None
            if engine is not None and gpu and not graphics:
                web_cache.prefetch_in_background()  # the GPU layer, for the next start
            folder = web_cache.downloads()
            directory = os.open(folder, os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            profile_path, profile = session_profile()
            try:
                dest='Browser-downloads-'+os.urandom(5).hex()
                os.mkdir(dest,0o700,dir_fd=directory)
                destfd=os.open(dest,os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=directory)
                try:
                    os.fchown(destfd,UID,UID)
                    # In the recovery's own namespaces: the step that moves finished downloads to a card.
                    ended = start_delivery(destfd)
                    os.unshare(os.CLONE_NEWNS|os.CLONE_NEWIPC)
                    mount('--make-rprivate','/')
                    detach_cards()
                    os.unshare(os.CLONE_NEWPID)
                    pid=os.fork()
                    if not pid:
                        # getppid() is 0 for PID 1 when its parent lives outside the namespace.
                        ctypes.CDLL(None).prctl(1,signal.SIGKILL,0,0,0)
                        try:
                            os.unshare(os.CLONE_NEWNS)
                            # A bind mount needs a source inside this new namespace: open the
                            # folder again here and make sure it is the same one.
                            local=os.open(folder,os.O_DIRECTORY|os.O_NOFOLLOW)
                            kept=None
                            try:
                                if not os.path.samestat(os.fstat(local),os.fstat(directory)):
                                    raise RuntimeError('Download folder changed')
                                if profile is not None:
                                    kept=os.open(profile_path,os.O_DIRECTORY|os.O_NOFOLLOW)
                                    if not os.path.samestat(os.fstat(kept),os.fstat(profile)):
                                        raise RuntimeError('Browser profile folder changed')
                                session(Path(path),local,dest,engine,images,graphics,frames,kept)
                            finally:
                                os.close(local)
                                if kept is not None:
                                    os.close(kept)
                        except Exception as exc:
                            os.write(0,b'S'+str(exc).encode()[:128])
                            traceback.print_exc()  # to the recovery's log, beside the note
                        os._exit(1)
                    # The session holds its own references; the RAM copies go when it ends.
                    for image in images.values():
                        os.close(image)
                    images = {}
                    if frames:
                        # Only the session's copy of the frame socket may keep it open.
                        null = os.open('/dev/null', os.O_RDONLY)
                        os.dup2(null, FRAMES_FD, inheritable=True)
                        os.close(null)
                    _,status=os.waitpid(pid,0)
                    if ended is not None:
                        os.close(ended)  # the delivery moves what is left, then ends
                    return os.waitstatus_to_exitcode(status)
                finally:
                    try:
                        if os.path.samestat(os.fstat(destfd),os.stat(dest,dir_fd=directory,follow_symlinks=False)):
                            os.rmdir(dest,dir_fd=directory)
                    except OSError:
                        pass  # Finished downloads stay in RAM until the recovery restarts.
                    os.close(destfd)
            finally:
                os.close(directory)
                if profile is not None:
                    os.close(profile)
        finally:
            for image in images.values():
                os.close(image)


def session_profile():
    """The browser's profile kept for this recovery session (web_cache.profile): its path and an
    open folder, or (None, None) when it cannot be had; the browser then starts with a fresh one."""
    try:
        path = web_cache.profile(UID)
        fd = os.open(path, os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    except (OSError, RuntimeError):
        traceback.print_exc()
        return None, None
    # The last browser has ended with its whole PID namespace. Its "profile in use" marks name a
    # PID that the new namespace may give to another of its processes: they go before it starts.
    for name in SINGLETON:
        try:
            os.unlink(name, dir_fd=fd)
        except FileNotFoundError:
            pass
        except OSError:
            traceback.print_exc()
    return path, fd


SINGLETON = ('SingletonLock', 'SingletonSocket', 'SingletonCookie')


def start_delivery(destfd):
    """Fork web_downloads.follow for the RAM folder DESTFD, before the browser's namespaces: it
    sees the cards as the recovery mounted them. Returns the pipe end whose closing tells it that
    the browser has finished (None when it could not start; downloads then stay in RAM)."""
    try:
        import web_downloads
        ended, keep = os.pipe2(os.O_CLOEXEC)
    except (ImportError, OSError):
        traceback.print_exc()
        return None
    pid = os.fork()
    if not pid:
        try:
            os.close(keep)
            source = fcntl.fcntl(destfd, fcntl.F_DUPFD_CLOEXEC, 100)
            reader = fcntl.fcntl(ended, fcntl.F_DUPFD_CLOEXEC, 100)
            os.dup2(source, 3, inheritable=False)
            os.dup2(reader, 4, inheritable=False)
            # Nothing else of the browser: its frame socket, images and folders are not held here.
            os.closerange(5, 65536)
            web_downloads.follow(3, UID, 4, control=0)
        except BaseException:
            traceback.print_exc()
        os._exit(0)
    os.close(ended)
    return keep


if __name__ == '__main__':
    try:
        import sys
        frames = reserve_frames_fd()  # before anything else can take fd 6
        raise SystemExit(run(sys.argv[1:]==['--ram'], frames))
    except Exception as exc:
        os.write(0,b'S'+str(exc).encode()[:128])
        traceback.print_exc()  # to the recovery's log, beside the note
        raise SystemExit(1)
