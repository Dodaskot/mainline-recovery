"""Unprivileged web session. stdin is the private recovery control socket, fd 5 is one frame."""
import base64
import fcntl
import io
import json
import mmap
import os
import re
import select
import socket
import subprocess
import sys
import threading
import time
from collections import deque
from urllib.parse import quote_plus, unquote, urlsplit

from PIL import Image

# The page fills the screen under the browser's toolbar, as in Chrome on Android (2026-11-20): 686 CSS
# pixels is 1372 of the interface's, from its toolbar down to just above the gesture handle.
CSS_WIDTH, CSS_HEIGHT, PIXEL_RATIO = 360, 686, 3
WIDTH, HEIGHT = CSS_WIDTH * PIXEL_RATIO, CSS_HEIGHT * PIXEL_RATIO
# "Desktop site", as Chrome on Android requests it: a 980 CSS pixel wide layout drawn into the same
# 1080 pixels, and the user agent of Chrome on Linux (2026-11-20, the owner).
DESKTOP_WIDTH = 980
DESKTOP_HEIGHT = round(CSS_HEIGHT * DESKTOP_WIDTH / CSS_WIDTH)
# A video in full screen fills the whole panel (2026-11-20, the owner): upright 360 x 800 CSS pixels, or
# on its side 800 x 360 when the video is wider than tall; the interface turns the frame (V messages).
FULL_UPRIGHT, FULL_SIDEWAYS = (360, 800), (800, 360)
# The page's full screen, told by a watcher in the session's own world of the page (2026-11-21): its
# binding and its marks live there, invisible to the page's scripts (before, a22xFullscreen, __a22xFull,
# __a22xTap and __a22xFocus were globals any script could find). It is told, not asked: a session that
# asked every 0.35 s made YouTube stop every video at 60 s on the owner's phone, three times of three.
WORLD = 'a22x'
# Two live UI tabs keep ordinary tab switching cheap on the 4 GB phone. Other
# cards keep their address and thumbnail in the UI and load again on demand.
LIVE_TABS = 2
LIVE_TARGETS = 4  # includes script-opened popup parents
PENDING_COMMANDS = 32
FULLSCREEN_WATCH = (
    "(()=>{if(window.__a22xFull)return;window.__a22xFull=1;const tell=()=>{const e=document.fullscreenElement||"
    "document.webkitFullscreenElement;let w=0,h=0;if(e){const v=e.tagName==='VIDEO'?e:e.querySelector('video');"
    "if(v&&v.videoWidth){w=v.videoWidth;h=v.videoHeight}else{const r=e.getBoundingClientRect();w=r.width;h=r.height}}"
    "try{a22xFullscreen(JSON.stringify({on:!!e,w:w,h:h}))}catch(x){}};"
    "document.addEventListener('fullscreenchange',tell,true);document.addEventListener('webkitfullscreenchange',tell,true)})()")
# 2026-11-22, a tester (#6): a 4K YouTube video ended in "Aw, Snap! Error code: 9": the kernel's OOM killer
# took Chromium (350 MB anonymous, 810 MB shared memory of decoded frames; nothing decodes video in hardware
# here, and 4 GB hold the recovery too). In the page's own world, a video of more pixels than 1080p is said
# to be unsupported, so sites pick 1080p or less; an upright 1080 x 1920 video keeps its size.
MEDIA_CAP = (
    "(()=>{if(window.__a22xMedia)return;window.__a22xMedia=1;const most=1920*1088;"
    "const big=t=>{const w=/width=(\\d+)/.exec(t||''),h=/height=(\\d+)/.exec(t||'');"
    "return !!(w&&h&&(+w[1])*(+h[1])>most)};"
    "for(const n of ['MediaSource','ManagedMediaSource','WebKitMediaSource']){const M=window[n];"
    "if(M&&typeof M.isTypeSupported==='function'){const f=M.isTypeSupported.bind(M);"
    "M.isTypeSupported=t=>big(t)?false:f(t)}}"
    "const c=navigator.mediaCapabilities;if(c&&c.decodingInfo){const d=c.decodingInfo.bind(c);"
    "c.decodingInfo=q=>{const v=q&&q.video;if(v&&v.width*v.height>most)"
    "return Promise.resolve({supported:false,smooth:false,powerEfficient:false});return d(q)}}})()")
# What a page plays, for the interface's quick settings (2026-11-22, the owner: the browser's media is
# controlled from the shade). Told as the full screen is, from the session's world, on the media events
# only (never timeupdate, never asked): {p: playing, v: video, t: title, a: artist or site, c/d: position
# and length in ms}; '' when nothing plays any more. The controls act on that element.
MEDIA_WATCH = (
    "(()=>{if(window.__a22xMediaWatch)return;window.__a22xMediaWatch=1;let last=null,cur=null,held=[];"
    "const all=()=>[...document.querySelectorAll('video,audio')];"
    "const seen=e=>{if(e.tagName==='AUDIO')return 1;const r=e.getBoundingClientRect();"
    "const w=Math.min(r.right,innerWidth)-Math.max(r.left,0),h=Math.min(r.bottom,innerHeight)-Math.max(r.top,0);return w>0&&h>0?w*h:0};"
    # what plays: the element heard and seen most (a page can hold several: YouTube's Shorts keep the next ones)
    "const pick=()=>{const on=all().filter(e=>!e.paused&&!e.ended);if(on.length){on.sort((a,b)=>(b.muted?0:1)-(a.muted?0:1)||seen(b)-seen(a));return cur=on[0]}"
    "return cur&&cur.isConnected?cur:null};"
    "const tell=()=>{const m=pick();let s='';"
    "if(m&&(m.currentTime>0||!m.paused)){const md=navigator.mediaSession&&navigator.mediaSession.metadata;"
    "s=JSON.stringify({p:!m.paused&&!m.ended,v:m.tagName==='VIDEO',t:String((md&&md.title)||document.title||'').slice(0,150),"
    "a:String((md&&md.artist)||location.hostname||'').slice(0,100),c:Math.max(0,Math.round(m.currentTime*1000)),"
    "d:isFinite(m.duration)?Math.round(m.duration*1000):0})}"
    "if(s!==last){last=s;try{a22xMedia(s)}catch(x){}}};"
    "window.__a22xMediaReport=()=>{last=null;tell()};"
    "for(const n of ['play','playing','pause','ended','seeked','durationchange','emptied'])document.addEventListener(n,()=>setTimeout(tell,0),true);"
    # pause: everything that plays (the sound stops, whichever element it came from); play: what was paused here
    "window.__a22xMediaDo=(op,v)=>{const m=pick();if(op==='next'||op==='previous'){const done=!document.dispatchEvent(new CustomEvent("
    "'a22x-media-action',{detail:op==='next'?'nexttrack':'previoustrack',cancelable:true}));if(op==='previous'&&m&&!done)m.currentTime=0;return}"
    "if(op==='pause'){held=all().filter(e=>!e.paused&&!e.ended);held.forEach(e=>e.pause());return}"
    "if(op==='play'){const back=held.filter(e=>e.isConnected);held=[];(back.length?back:(m?[m]:[])).forEach(e=>e.play().catch(()=>{}));return}"
    "if(m&&op==='seek')m.currentTime=v/1000}})()")
# In the page's own world: the page's next/previous handlers (navigator.mediaSession), kept in a closure
# and called on the session world's event. Nothing of it is a global of the page.
MEDIA_ACTIONS = (
    "(()=>{const s=navigator.mediaSession;if(!s||!s.setActionHandler)return;const h={};const f=s.setActionHandler.bind(s);"
    "s.setActionHandler=(a,fn)=>{h[a]=fn;return f(a,fn)};"
    "document.addEventListener('a22x-media-action',e=>{const fn=h[e.detail];if(fn){e.preventDefault();try{fn({action:e.detail})}catch(x){}}},true)})()")
ENGINE = '/usr/lib/chromium/chromium-headless-shell'
# The RAM engine (2026-11-20) has only the full Chromium: Wayland output, or the screencast in its
# --headless=new mode. A card's engine package has the headless shell.
FULL = '/usr/lib/chromium/chromium'


COMPOSITOR = '/opt/web-compositor'
FRAMES_FD = 6  # the UI's own socket for frame messages, when web_launch passes one


def screencast_engine():
    return ENGINE if os.path.exists(ENGINE) else FULL


SEARCH = 'https://www.google.com/search?q='
HOST = re.compile(r'(?:localhost|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}|[0-9]{1,3}(?:\.[0-9]{1,3}){3})(?::[0-9]{1,5})?', re.I)


def address(value):
    """What was typed in the address bar: an http(s) address as it is, a bare host ("example.org",
    "example.org/path") with https://, anything else as a Google search (2026-11-20, a tester, #6:
    "expects valid https links and doesn't do a Google search")."""
    value = (value or '').strip()
    if not value or any(ord(c) < 32 or ord(c) == 127 for c in value) or len(value) > 2048:
        raise ValueError('Invalid address')
    if '://' in value and not any(c.isspace() for c in value):
        parsed = urlsplit(value)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError('Enter an HTTP or HTTPS address')
        return value
    host = re.split(r'[/?#]', value, maxsplit=1)[0]
    if not any(c.isspace() for c in value) and HOST.fullmatch(host):
        return 'https://' + value
    return SEARCH + quote_plus(value)


# The page the browser shows when it closes, opened again at its next start in this recovery
# session (2026-11-20, a tester, #6: "doesn't resume its session after exiting it for a brief period").
# It lives in the browser's profile, which stays in RAM until the recovery restarts (web_launch).
LAST_PAGE = 'a22x-last-page'


def remember_page(folder, url):
    """Keep URL (http or https only) as the page to open at the next start; errors are ignored."""
    if urlsplit(url).scheme not in ('http', 'https') or len(url) > 2048:
        return
    try:
        temporary = os.path.join(folder, '.' + LAST_PAGE + '.new')
        with open(temporary, 'w', encoding='utf-8') as out:
            out.write(url)
        os.replace(temporary, os.path.join(folder, LAST_PAGE))
    except OSError:
        pass


def last_page(folder):
    try:
        with open(os.path.join(folder, LAST_PAGE), encoding='utf-8') as source:
            url = source.read(2049)
    except (OSError, UnicodeDecodeError):
        return None
    try:
        return url if address(url) == url and urlsplit(url).scheme in ('http', 'https') else None
    except ValueError:
        return None


TAP_SLOP = 8  # CSS pixels a finger may move and still tap


def engine_arguments(executable, direct):
    gpu = os.environ.get('A22X_WEB_GPU') == '1'
    graphics = (['--enable-gpu', '--use-gl=angle', '--use-angle=gles-egl'] if gpu else ['--disable-gpu'])
    if gpu and os.environ.get('A22X_WEB_RASTER') != '0':
        # 2026-11-20: tiles rastered by the Mali GPU instead of the little CPU cores. Chromium's list
        # of GPUs it distrusts would otherwise keep Panfrost to CPU raster and slow scrolling down.
        graphics += ['--ignore-gpu-blocklist', '--enable-gpu-rasterization']
    # No --disable-frame-rate-limit (2026-11-21): it reached 90 frames a second but drew without pause,
    # two cores busy over a paused video, and YouTube stuttered. The compositor's presentation
    # feedback (90 Hz refresh) paces Chromium instead.
    display = (['--ozone-platform=wayland', '--kiosk', '--app=about:blank',
                '--disable-backgrounding-occluded-windows', '--disable-renderer-backgrounding']
               if direct else ['--headless' if executable == ENGINE else '--headless=new', 'about:blank'])
    return [executable, '--remote-debugging-pipe',
            f'--window-size={CSS_WIDTH},{CSS_HEIGHT}', f'--force-device-scale-factor={PIXEL_RATIO}',
            # Without the GPU the engine may draw in software (2026-11-21: with the GPU off and no software
            # path its GPU process failed three times and the browser ended).
            *graphics, *(['--disable-software-rasterizer'] if gpu else []), '--no-first-run', '--no-default-browser-check',
            '--disable-background-networking', '--disable-dev-shm-usage',
            # The control pipe alone sets navigator.webdriver, which YouTube takes for a bot and
            # stops its videos after a minute (2026-11-20, a tester, #6; checked on the host).
            '--disable-blink-features=AutomationControlled',
            # The profile stays for the session (web_launch); its page cache is the session's only.
            '--disk-cache-dir=/tmp/cache', '--disk-cache-size=67108864',
            # Errors only, read by forward_errors (2026-11-20).
            '--enable-logging=stderr', '--log-level=2',
            # Sound (2026-11-20): the audio service reads the recovery's ALSA file from ALSA_CONFIG_PATH,
            # which its own sandbox would refuse; the recovery's namespace jail still holds it.
            # Frames of other sites in the page's own process (2026-11-21, #6: Cloudflare's check failed, 'Verification
            # failed'): a frame in a process of its own kept the engine's own user agent while the page had the
            # override, and the check saw two browsers. Checked on the phone: it passes so. One --disable-features
            # only: Chromium reads the last of several.
            '--disable-site-isolation-trials',
            '--disable-features=' + ','.join((['AudioServiceSandbox'] if os.environ.get('A22X_WEB_SOUND') == '1' else [])
                                             + ['IsolateOrigins', 'site-per-process']),
            *([] if os.environ.get('A22X_WEB_SOUND') == '1' else ['--mute-audio']),
            '--user-data-dir=' + os.path.join(os.environ['HOME'], 'profile'), *display]


ADDRESS = re.compile(r'\b[a-z][a-z0-9+.-]*://\S+', re.I)


def forward_errors(fd, limit=200, out=None):
    """Chromium's errors to the recovery's log (2026-11-20, a tester: the browser stayed blank and
    the log said nothing): only its ERROR and FATAL lines, addresses masked, at most LIMIT of them.
    Reads FD to its end in a thread of its own, which it returns."""
    def pump():
        count = 0
        with os.fdopen(fd, 'rb') as stream:
            for raw in stream:
                line = raw.decode('utf-8', 'replace').rstrip()
                # No D-Bus in the browser's namespace: those errors are expected and filled the
                # log's quota at every start (2026-11-20, on the owner's phone). Neither is there a
                # keyboard layout: "No current XKB state" came dozens of times a minute (2026-11-21, #3 logs).
                if (count < limit and (':ERROR:' in line or ':FATAL:' in line) and ':ERROR:dbus/' not in line
                        and 'No current XKB state' not in line):
                    count += 1
                    print('browser: ' + ADDRESS.sub('<address>', line)[:300], file=out or sys.stderr, flush=True)
    thread = threading.Thread(target=pump, daemon=True)
    thread.start()
    return thread


def start_engine(executable, direct):
    arguments = engine_arguments(executable, direct)
    incoming, writer = os.pipe()
    reader, outgoing = os.pipe()
    errors, error_writer = os.pipe()
    pid = os.fork()
    if not pid:
        try:
            # Duplicate them first: a pipe end can already be fd 2, 3 or 4.
            a, b, e = [fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 8) for fd in (incoming, outgoing, error_writer)]
            os.dup2(a, 3)
            os.dup2(b, 4)
            null = os.open('/dev/null', os.O_RDWR)
            os.dup2(null, 0)
            os.dup2(null, 1)
            os.dup2(e, 2)
            os.closerange(5, 65536)
            os.execv(executable, arguments)
        finally:
            os._exit(127)
    os.close(incoming)
    os.close(outgoing)
    os.close(error_writer)
    forward_errors(errors)
    return reader, writer


def start_compositor(frames=False):
    """The off-screen Wayland compositor that draws into fd 5, and whether its frame messages go
    straight to the UI's socket (fd 6, FRAMES) rather than through this session; (None, False)
    when it does not start. A compositor that takes no frame socket is started without one."""
    for direct_frames in ((True, False) if frames else (False,)):
        compositor, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        process = None
        try:
            with child:
                argv = [COMPOSITOR, str(child.fileno())] + ([str(FRAMES_FD)] if direct_frames else [])
                keep = (child.fileno(), 5) + ((FRAMES_FD,) if direct_frames else ())
                process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, pass_fds=keep)
            compositor.settimeout(5)
            if compositor.recv(2) == b'S':
                compositor.settimeout(None)
                return compositor, direct_frames
        except OSError:
            pass
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        compositor.close()
    return None, False


# Links to apps (2026-11-21, #6): web_launch's policy sends these schemes to xdg-open at once, and its
# xdg-open writes the address here. Chromium otherwise asked "Open xdg-open?" in a dialog that touch did
# not reach, and the tab stayed under it.
LINKS = '/tmp/a22x-links'
APP_NOTE = 'This link opens an Android app. The recovery has none, so the page stays as it was.'
OTHER_NOTE = 'This link opens another app. The recovery has none, so the page stays as it was.'
APP_FALLBACK_NOTE = 'This Android app link has a web fallback. Recovery could not identify the tab that opened it.'


def external_link_note(url):
    """The xdg-open FIFO does not include a Chromium target ID."""
    scheme = url.split(':', 1)[0].lower()
    if scheme == 'intent':
        for part in url.partition('#Intent;')[2].split(';'):
            if part.startswith('S.browser_fallback_url='):
                target = unquote(part.split('=', 1)[1])
                if target.lower().startswith(('https://', 'http://')) and len(target) <= 2048:
                    return APP_FALLBACK_NOTE
    return APP_NOTE if scheme in ('intent', 'market', 'android-app') else OTHER_NOTE


def queue_command(queue, packet):
    if len(queue) < PENDING_COMMANDS:
        queue.append(packet)
    elif packet.startswith(b'I'):
        # The UI waits for the latest selection's acknowledgement. Ordinary
        # commands keep their order and one overflow slot holds that selection.
        if len(queue) == PENDING_COMMANDS:
            queue.append(packet)
        else:
            queue[-1] = packet


def open_links():
    """The pipe xdg-open writes to; held open for writing too, so it never reads as ended."""
    try:
        os.mkfifo(LINKS, 0o600)
    except FileExistsError:
        pass
    except OSError:
        return None
    try:
        fd = os.open(LINKS, os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return None
    # Far above the engine's pipe ends (3 and 4 for --remote-debugging-pipe) and the frame map (5): taken
    # first, the low number went to the engine and select failed with EBADF (2026-11-21, on the phone).
    try:
        return fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 64)
    except OSError:
        return None
    finally:
        os.close(fd)


def run(executable=None, downloads='/downloads'):
    control = socket.socket(fileno=0)
    direct = os.environ.get('A22X_WEB_WAYLAND') == '1'
    compositor, _ = start_compositor(os.environ.get('A22X_WEB_FRAMES') == '1') if direct else (None, False)
    # The compositor keeps its own copy of the UI's frame socket, or nobody uses it: the UI then
    # sees it end and takes every frame message from the control socket, as before.
    try:
        os.close(FRAMES_FD)
    except OSError:
        pass
    if compositor:
        os.environ['WAYLAND_DISPLAY'] = 'recovery-wayland'
        executable = FULL
    else:
        # Without the compositor the same engine serves the screencast, more slowly.
        direct = False
        executable = executable or screencast_engine()
        frame = mmap.mmap(5, WIDTH * HEIGHT * 4)
    reader, writer = start_engine(executable, direct)
    links = open_links()
    serial = 0
    session = None
    tab_ready = False
    pending = {}
    incoming = bytearray()
    waiting_frame = None
    staged_frame = None
    visible = True
    queue = deque()
    active_tab = None
    selection = None
    tabs = {}  # UI tab ID -> popup ancestry and current Chromium target, least recent first
    evicted = set()
    sessions = {}  # CDP stays attached to hidden pages, including their document scripts
    titles = {}
    startup_target = None
    activation = 0
    main_frame = None
    world = None          # the execution context of WORLD in the main frame's document, once created
    world_asked = False
    location_until = next_location = 0
    pending_loader = None
    active_target = None
    ua_override = None
    profile = os.path.join(os.environ['HOME'], 'profile')
    touching = False
    touch_start = [0, 0, False]  # x, y and whether it moved beyond a tap
    loading = False
    transfers = {}
    names = {}
    shown_progress = None
    shown_title = None
    desktop = False
    dark = False        # dark versions of sites (L1), as Chrome's "Dark theme for sites"
    fullscreen = None   # None, 'P' (upright) or 'L' (on its side)
    focus_checks = []
    desktop_ua = None

    def call(method, params=None, *, tab=True, reply=None, target_session=None, scoped=False):
        nonlocal serial
        serial += 1
        msg = dict(id=serial, method=method, params=params or {})
        if tab:
            msg['sessionId'] = target_session or session
        if reply:
            pending[serial] = (method, activation if tab or scoped else None, reply)
        packet = memoryview(json.dumps(msg).encode() + b'\0')
        while packet:
            packet = packet[os.write(writer, packet):]

    def set_loading(value):
        # L1/L0 drive the small activity ring in the browser header.
        nonlocal loading
        if value != loading:
            loading = value
            control.send(b'L1' if value else b'L0')

    def show_progress():
        # P<0..100> for one known size, P- while any size is unknown, P when none is left.
        nonlocal shown_progress
        if not transfers:
            value = b''
        elif None in transfers.values():
            value = b'-'
        else:
            value = str(min(transfers.values())).encode()
        if value != shown_progress:
            shown_progress = value
            control.send(b'P' + value)

    def has_parent():
        return len(tabs[active_tab]) > 1

    def trim_tabs():
        while len(tabs) > LIVE_TABS or sum(map(len, tabs.values())) > LIVE_TARGETS:
            oldest = next(iter(tabs))
            close_tab(oldest)
            evicted.add(oldest)

    def send_title(title):
        nonlocal shown_title
        if title != shown_title:
            shown_title = title
            control.send(b'W' + title[:300].encode()[:600])

    def leave_target():
        nonlocal touching
        if not session:
            return
        if touching:
            call('Input.dispatchTouchEvent', dict(type='touchCancel', touchPoints=[]))
            touching = False
        if fullscreen:
            in_world('document.fullscreenElement&&document.exitFullscreen()')
            set_fullscreen(None)
        in_world("window.__a22xMediaDo&&window.__a22xMediaDo('pause',0)")
        if not direct:
            drop_staged_frame()
            call('Page.stopScreencast')
        call('Page.setWebLifecycleState', dict(state='frozen'))

    def activate(target, restore=None, discarded=False):
        nonlocal active_target, activation, session, tab_ready, main_frame, world, world_asked
        nonlocal location_until, next_location, pending_loader
        active_target, tab_ready = target, False
        drop_staged_frame()
        activation += 1
        focus_checks.clear()
        location_until, next_location, pending_loader = 0, 0, None
        main_frame, world, world_asked = None, None, False
        session = sessions.get(target)

        def show(_result):
            call('Page.getFrameTree', reply=lambda tree: ready_tab(tree, restore, discarded))
        def configure():
            call('Page.setWebLifecycleState', dict(state='active'))
            call('Target.activateTarget', dict(targetId=target), tab=False, scoped=True,
                 reply=lambda _: apply_metrics(reply=show))
        def attached(result):
            nonlocal session
            session = sessions[target] = result['sessionId']
            call('Page.enable')
            call('Runtime.enable')  # for the binding's calls
            call('Runtime.addBinding', dict(name='a22xFullscreen', executionContextName=WORLD))
            call('Runtime.addBinding', dict(name='a22xMedia', executionContextName=WORLD))
            call('Page.addScriptToEvaluateOnNewDocument', dict(source=MEDIA_WATCH, worldName=WORLD))
            call('Page.addScriptToEvaluateOnNewDocument', dict(source=MEDIA_ACTIONS))
            call('Page.addScriptToEvaluateOnNewDocument', dict(source=FULLSCREEN_WATCH, worldName=WORLD))
            call('Page.addScriptToEvaluateOnNewDocument', dict(source=MEDIA_CAP))
            configure()

        if session:
            configure()
        else:
            call('Target.attachToTarget', dict(targetId=target, flatten=True), tab=False, scoped=True, reply=attached)

    def close_tab(tab):
        for target in reversed(tabs.pop(tab, [])):
            sessions.pop(target, None)
            titles.pop(target, None)
            call('Target.closeTarget', dict(targetId=target), tab=False)
        evicted.discard(tab)

    def select_tab(tab, request, restore):
        nonlocal active_tab, active_target, activation, selection, session, startup_target, tab_ready
        leave_target()
        active_tab, selection, tab_ready = tab, request, False
        active_target = session = None
        activation += 1
        active = tabs.pop(tab, None)
        if active:
            tabs[tab] = active
            activate(active[-1])
            return
        discarded = tab in evicted
        evicted.discard(tab)

        def created(target):
            tabs[tab] = [target]
            trim_tabs()
            activate(target, restore, discarded)

        if startup_target:
            target, startup_target = startup_target, None
            created(target)
        else:
            # A background target in the existing kiosk window. Activating the
            # target switches Chromium's contents in the same Wayland surface.
            call('Target.createTarget', dict(url='about:blank', background=True), tab=False,
                 reply=lambda result: created(result['targetId']))

    def ensure_world():
        """The session's own world in the current document, asked for once per document."""
        nonlocal world_asked
        if world is not None or world_asked or not main_frame:
            return
        world_asked = True
        frame = main_frame

        def created(result):
            nonlocal world, world_asked
            world_asked = False
            if frame == main_frame:
                world = result.get('executionContextId')
                in_world(FULLSCREEN_WATCH)  # once per document; a document made after the attach has it already
                in_world(MEDIA_WATCH + ";window.__a22xMediaReport()")
        call('Page.createIsolatedWorld', dict(frameId=frame, worldName=WORLD), reply=created)

    def in_world(expression, reply=None):
        """EXPRESSION in the session's world; False while that world is not there yet."""
        ensure_world()
        if world is None:
            return False
        call('Runtime.evaluate', dict(expression=expression, contextId=world, returnByValue=True), reply=reply)
        return True

    def page_size():
        if fullscreen:
            return FULL_SIDEWAYS if fullscreen == 'L' else FULL_UPRIGHT
        return (DESKTOP_WIDTH, DESKTOP_HEIGHT) if desktop else (CSS_WIDTH, CSS_HEIGHT)

    def apply_metrics(reply=None):
        width, height = page_size()
        scale = PIXEL_RATIO if fullscreen else WIDTH / width
        metrics = dict(width=width, height=height, screenWidth=width, screenHeight=height,
                       deviceScaleFactor=scale, mobile=bool(fullscreen) or not desktop)
        if fullscreen:
            metrics['screenOrientation'] = (dict(type='landscapePrimary', angle=90) if fullscreen == 'L'
                                            else dict(type='portraitPrimary', angle=0))
        call('Emulation.setDeviceMetricsOverride', metrics)
        call('Emulation.setTouchEmulationEnabled', dict(enabled=True, maxTouchPoints=1))
        apply_dark()
        call('Emulation.setUserAgentOverride', desktop_ua if desktop else ua_override, reply=reply)

    def apply_dark():
        """Dark sites (2026-11-21, the owner): a page with a dark version of its own gets it through
        prefers-color-scheme; the engine darkens the others, and leaves alone those that declare
        their own dark colours (Chrome's auto dark mode)."""
        call('Emulation.setEmulatedMedia',
             dict(features=[dict(name='prefers-color-scheme', value='dark')] if dark else []))
        call('Emulation.setAutoDarkModeOverride', dict(enabled=True) if dark else {})

    def dispatch_ready(packet):
        try:
            dispatch(packet)
        except ValueError as err:
            control.send(b'S' + str(err).encode()[:96])

    def drain_queue():
        while tab_ready and queue:
            dispatch_ready(queue.popleft())

    def ready_tab(tree, restore, discarded):
        nonlocal tab_ready, loading, shown_title, selection
        tab_ready = True
        if selection is not None:
            # The UI ignores old tab messages until this ordered control reply.
            control.send(f'I{selection}'.encode())
            selection = None
        loading, shown_title = False, None
        control.send(b'L0')
        control.send(b'M')
        show_location(tree)
        ensure_world()
        send_title(titles.get(active_target, ''))
        refresh_history()
        if not direct:
            start_screencast()
        control.send(b'SReady')
        if discarded and restore:
            control.send(b'SReloading tab to limit browser memory')
        if restore:
            dispatch_ready(b'N' + restore.encode())
        drain_queue()

    def engine_version(result):
        nonlocal ua_override, desktop_ua
        version = result['product'].split('/')[-1]
        if not re.fullmatch(r'[0-9]+(?:\.[0-9]+){3}', version):
            raise RuntimeError('Unrecognized browser engine version')
        major = version.split('.')[0]
        desktop_ua = {
            'userAgent': ('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
                          f'(KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36'),
            'platform': 'Linux x86_64',
            'userAgentMetadata': {'brands': [{'brand':'Chromium','version':major}, {'brand':'Google Chrome','version':major},
                                             {'brand':'Not_A Brand','version':'24'}],
                                  'fullVersionList': [{'brand':'Chromium','version':version}, {'brand':'Google Chrome','version':version},
                                                      {'brand':'Not_A Brand','version':'24.0.0.0'}],
                                  'platform':'Linux', 'platformVersion':'6.0.0', 'architecture':'x86',
                                  'model':'', 'mobile':False, 'bitness':'64'},
        }
        ua_override = {
            'userAgent': ('Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 '
                          f'(KHTML, like Gecko) Chrome/{major}.0.0.0 Mobile Safari/537.36'),
            'platform': 'Linux armv8l',
            # As Chrome on Android names itself (2026-11-20: a page that knows only Chromium may
            # treat it as an unusual client).
            'userAgentMetadata': {'brands': [{'brand':'Chromium','version':major},
                                             {'brand':'Google Chrome','version':major},
                                             {'brand':'Not_A Brand','version':'24'}],
                                  'fullVersionList': [{'brand':'Chromium','version':version},
                                                      {'brand':'Google Chrome','version':version},
                                                      {'brand':'Not_A Brand','version':'24.0.0.0'}],
                                  'platform':'Android', 'platformVersion':'10.0.0', 'architecture':'',
                                  'model':'', 'mobile':True, 'bitness':''},
        }
        call('Target.getTargets', tab=False, reply=initial_window)

    def start_screencast():
        if visible:
            call('Page.startScreencast', dict(format='png', maxWidth=WIDTH, maxHeight=HEIGHT))

    def ack_screencast(frame_session, stamp):
        call('Page.screencastFrameAck', dict(sessionId=stamp), target_session=frame_session)

    def drop_staged_frame():
        nonlocal staged_frame
        if staged_frame:
            frame_session, data = staged_frame
            ack_screencast(frame_session, data['sessionId'])
            staged_frame = None

    def publish_screencast(frame_session, data):
        nonlocal waiting_frame
        with Image.open(io.BytesIO(base64.b64decode(data['data']))) as image:
            if image.size != (WIDTH, HEIGHT):
                # The compositor can emit a frame from before the size override.
                ack_screencast(frame_session, data['sessionId'])
                return
            frame[:] = image.convert('RGB').tobytes('raw', 'BGRX')
        control.send(b'F')
        waiting_frame = (frame_session, data['sessionId'])

    def initial_window(result):
        def ready(target):
            nonlocal startup_target, tab_ready
            startup_target, tab_ready = target, True
            drain_queue()

        window = next((target for target in result['targetInfos'] if target['type'] == 'page'), None)
        if window:
            ready(window['targetId'])
        else:
            call('Target.createTarget', dict(url='about:blank'), tab=False,
                 reply=lambda result: ready(result['targetId']))

    def show_location(result):
        nonlocal main_frame, location_until
        frame_info = result['frameTree']['frame']
        main_frame = frame_info['id']
        if pending_loader and frame_info.get('loaderId') == pending_loader:
            location_until = 0
        report_location(frame_info)

    def report_location(frame_info):
        failed = frame_info.get('unreachableUrl')
        url = failed or frame_info['url'] + frame_info.get('urlFragment', '')
        if url == 'chrome://new-tab-page/':
            url = 'about:blank'
        control.send(b'U' + url.encode()[:2048])
        if failed:
            control.send(b'SPage failed to load')
        else:
            remember_page(profile, url)

    def refresh_history(direction=0):
        def updated(history):
            index, entries = history['currentIndex'], history['entries']
            # Chromium can create several startup entries before the first web page.
            first_page = next((i for i, entry in enumerate(entries)
                               if urlsplit(entry['url']).scheme in ('http', 'https')), len(entries))
            back, forward = has_parent() or index > first_page, index + 1 < len(entries)
            control.send(f'H{int(back)}{int(forward)}'.encode())
            if direction < 0 and index <= first_page and has_parent():
                call('Target.closeTarget', dict(targetId=active_target), tab=False)
            elif direction and first_page <= index + direction < len(entries):
                call('Page.navigateToHistoryEntry', dict(entryId=entries[index + direction]['id']))
        call('Page.getNavigationHistory', reply=updated)

    def set_fullscreen(value):
        """The page went into or out of full screen: the window takes that size (the compositor
        configures it) and the interface turns its picture (VP, VL, V0)."""
        nonlocal fullscreen
        if value == fullscreen:
            return
        fullscreen = value
        width, height = page_size()
        if compositor:
            pixels = (width * PIXEL_RATIO, height * PIXEL_RATIO) if fullscreen else (WIDTH, HEIGHT)
            compositor.send(b'S%d %d' % pixels)
        apply_metrics()
        control.send(b'V' + (fullscreen or '0').encode())

    def set_dark(value):
        nonlocal dark
        if value != dark:
            dark = value
            if session:
                apply_dark()

    def nonlocal_desktop(value):
        nonlocal desktop
        if value != desktop:
            desktop = value
            if session:
                apply_metrics()
                set_loading(True)
                call('Page.reload')

    # K1/K0: a field of the page has the focus after a tap, or not; the interface shows its keyboard
    # (2026-11-20). Asked after the tap and once more a moment later: the click that focuses can follow.
    # A field is typed in after a tap that focused it or landed on it (2026-11-20, on the phone: a
    # page that focuses its search box by itself, Wikipedia's, brought the keyboard up at every scroll).
    # The element focused before the tap is kept in __a22xFocus at its touchStart.
    FOCUS_BEFORE = "window.__a22xFocus=document.activeElement,0"
    FOCUSED = ("(()=>{let e=document.activeElement;while(e&&e.shadowRoot&&e.shadowRoot.activeElement)e=e.shadowRoot.activeElement;"
               "if(!e)return false;let typed=e.isContentEditable;const t=(e.tagName||'').toLowerCase();"
               "if(t==='textarea')typed=!e.readOnly&&!e.disabled;else if(t==='input')typed=!e.readOnly&&!e.disabled&&"
               "!/^(button|submit|checkbox|radio|range|color|file|image|reset|hidden)$/i.test(e.type||'');"
               "if(!typed)return false;if(document.activeElement!==window.__a22xFocus)return true;"
               "const p=window.__a22xTap,h=p&&document.elementFromPoint(p[0],p[1]);return !!h&&(e===h||e.contains(h)||h.contains(e))})()")

    def check_focus(again=True):
        def answered(result):
            value = bool(result.get('result', {}).get('value'))
            control.send(b'K1' if value else b'K0')
        if not in_world(FOCUSED, reply=answered):
            control.send(b'K0')
        if again:
            focus_checks.append(time.monotonic() + 0.3)

    def dispatch(packet):
        nonlocal location_until, next_location, pending_loader, touching
        op, value = chr(packet[0]), packet[1:].decode()
        if op == 'I':
            request, tab, restore = value.split(' ', 2)
            request, tab = int(request), int(tab)
            if min(request, tab) < 1 or max(request, tab) > 0xffffffff:
                return
            select_tab(tab, request, restore or None)
        elif op == 'O':
            if value:
                tab = int(value)
                if tab != active_tab:
                    close_tab(tab)
            else:
                for tab in set(tabs) - {active_tab}:
                    close_tab(tab)
                evicted.clear()
        elif op == 'L' and value in ('0', '1'):
            set_dark(value == '1')
        elif op == 'Y' and value in ('0', '1'):
            nonlocal_desktop(value == '1')
        elif not session:
            return
        elif op == 'N':
            url = address(value)
            set_fullscreen(None)
            location_until, next_location = time.monotonic() + 25, 0
            pending_loader = None
            def navigated(result):
                nonlocal pending_loader
                pending_loader = result.get('loaderId')
                if result.get('errorText'):
                    set_loading(False)
                    control.send(b'S' + result['errorText'].encode()[:80])
                call('Page.getFrameTree', reply=show_location)
            set_loading(True)
            call('Page.navigate', dict(url=url), reply=navigated)
        elif op == 'T':
            call('Input.insertText', dict(text=value))
        elif op == 'K' and value in ('Backspace', 'Enter'):
            key = dict(key=value, code=value, windowsVirtualKeyCode=8 if value=='Backspace' else 13)
            call('Input.dispatchKeyEvent', dict(type='rawKeyDown', **key))
            if value == 'Enter':
                call('Input.dispatchKeyEvent', dict(type='char', text='\r', **key))
            call('Input.dispatchKeyEvent', dict(type='keyUp', **key))
        elif op == 'W':
            # A mouse's wheel over the page (2026-11-22): the page scrolls as under a desktop's mouse.
            x, y, delta = map(int, value.split())
            if fullscreen or not (0 <= x < CSS_WIDTH and 0 <= y < CSS_HEIGHT) or abs(delta) > 4000:
                return
            if desktop:
                x, y, delta = x * DESKTOP_WIDTH // CSS_WIDTH, y * DESKTOP_WIDTH // CSS_WIDTH, delta * DESKTOP_WIDTH // CSS_WIDTH
            call('Input.dispatchMouseEvent', dict(type='mouseWheel', x=x, y=y, deltaX=0, deltaY=delta))
        elif op in ('D', 'M'):
            x, y = map(int, value.split())
            width, height = page_size()
            if fullscreen:  # the interface sends the page's own CSS pixels then (turned on its side)
                if not (0 <= x < width and 0 <= y < height):
                    return
            elif not (0 <= x < CSS_WIDTH and 0 <= y < CSS_HEIGHT):
                return
            elif desktop:  # the interface counts in the phone's CSS pixels; the page is 980 wide
                x, y = x * DESKTOP_WIDTH // CSS_WIDTH, y * DESKTOP_WIDTH // CSS_WIDTH
            if op == 'D':
                if touching:
                    call('Input.dispatchTouchEvent', dict(type='touchCancel', touchPoints=[]))
                touching = True
                kind = 'touchStart'
                touch_start[:] = [x, y, False]
                in_world(FOCUS_BEFORE)
            elif touching:
                kind = 'touchMove'
                if abs(x - touch_start[0]) > TAP_SLOP or abs(y - touch_start[1]) > TAP_SLOP:
                    touch_start[2] = True
            else:
                return
            call('Input.dispatchTouchEvent', dict(type=kind, touchPoints=[dict(x=x,y=y,id=0)]))
        elif op in ('E', 'X') and touching:
            touching = False
            call('Input.dispatchTouchEvent', dict(type='touchEnd' if op=='E' else 'touchCancel', touchPoints=[]))
            if op == 'E' and not touch_start[2]:  # a tap; a scroll leaves the keyboard as it is
                in_world('window.__a22xTap=[%d,%d],0' % (touch_start[0], touch_start[1]))
                check_focus()
        elif op in ('B', 'G'):
            refresh_history(-1 if op == 'B' else 1)
        elif op == 'R':
            set_loading(True)
            call('Page.reload')
        elif op == 'J':
            # The shade's controls for what the page plays (2026-11-22; M is a finger's move).
            parts = value.split()
            if len(parts) == 1 and parts[0] in ('play', 'pause', 'next', 'previous'):
                in_world(f"window.__a22xMediaDo&&window.__a22xMediaDo('{parts[0]}',0)")
            elif len(parts) == 2 and parts[0] == 'seek' and parts[1].isdigit() and len(parts[1]) <= 10:
                in_world(f"window.__a22xMediaDo&&window.__a22xMediaDo('seek',{int(parts[1])})")
        elif op == 'F' and value == '0':
            # Back in full screen: the page leaves it (its own control would do the same).
            in_world('document.fullscreenElement&&document.exitFullscreen()')
        elif op == 'C':
            # Clear browsing data: cookies and the page cache of this recovery session.
            call('Network.clearBrowserCookies')
            call('Network.clearBrowserCache')
            control.send(b'SBrowsing data cleared')
        elif op == 'Z':
            set_fullscreen(None)
            # Home clears the selected tab. A new card instead selects a separate target.
            location_until = 0
            set_loading(False)
            call('Page.navigate', dict(url='about:blank'))

    call('Browser.setDownloadBehavior', dict(behavior='allow', downloadPath=downloads, eventsEnabled=True), tab=False)
    call('Target.setDiscoverTargets',dict(discover=True),tab=False)
    call('Browser.getVersion', tab=False, reply=engine_version)
    while True:
        now = time.monotonic()
        if tab_ready and session and now < location_until and now >= next_location:
            # Chrome can commit the first page before its lifecycle listener
            # is attached. Read the committed top frame directly for redirects.
            call('Page.getFrameTree', reply=show_location)
            next_location = now + 0.75
        if tab_ready and session and focus_checks and now >= focus_checks[0]:
            focus_checks.pop(0)
            check_focus(again=False)
        timeout = 0.75 if now < location_until else None
        if focus_checks:
            timeout = max(0.0, min(timeout if timeout is not None else 1.0, focus_checks[0] - now))
        sources = [reader, control, compositor] if compositor else [reader, control]
        if links is not None:
            sources.append(links)
        ready, _, _ = select.select(sources, [], [], timeout)
        if links is not None and links in ready:
            try:
                asked = os.read(links, 16384).decode('utf-8', 'replace').splitlines()
            except BlockingIOError:
                asked = []
            for url in asked[:4]:
                control.send(b'S' + external_link_note(url.strip()).encode())
        if control in ready:
            packet = control.recv(4096)
            if not packet or packet == b'Q':
                return
            if packet in (b'V0', b'V1'):
                shown = packet == b'V1'
                if visible != shown:
                    visible = shown
                    if compositor:
                        compositor.send(packet)
                    elif tab_ready and session:
                        if visible:
                            start_screencast()
                        else:
                            # The UI still owns any frame already sent. Its A can arrive after V1.
                            drop_staged_frame()
                            call('Page.stopScreencast')
            elif compositor and packet in (b'A', b'A0', b'A1'):
                compositor.send(packet)
            elif packet == b'A':
                if waiting_frame:
                    ack_screencast(*waiting_frame)
                    waiting_frame = None
                if staged_frame:
                    publish_screencast(*staged_frame)
                    staged_frame = None
            elif tab_ready:
                dispatch_ready(packet)
            else:
                queue_command(queue, packet)
        if compositor in ready:
            rendered = compositor.recv(32)
            if not rendered.startswith(b'F'):
                raise RuntimeError('Browser compositor stopped')
            control.send(rendered)
        if reader not in ready:
            continue
        chunk = os.read(reader, 65536)
        if not chunk:
            raise RuntimeError('Web engine stopped')
        incoming.extend(chunk)
        if len(incoming) > 12 * 1024 * 1024:
            raise RuntimeError('Web engine message too large')
        while 0 in incoming:
            end = incoming.index(0)
            msg = json.loads(incoming[:end])
            del incoming[:end+1]
            request = pending.pop(msg.get('id'), None)
            if request:
                method, requested_activation, callback = request
                if requested_activation is not None and requested_activation != activation:
                    continue
                if 'error' in msg:
                    if method in ('Page.getFrameTree', 'Page.getNavigationHistory'):
                        continue  # The document can change while we query it.
                    if method in ('Page.createIsolatedWorld', 'Runtime.evaluate'):
                        world, world_asked = None, False  # its document is gone: asked again for the next
                        continue
                    raise RuntimeError(f'Web engine command failed ({method})')
                callback(msg['result'])
            event = msg.get('method')
            data = msg.get('params', {})
            if event == 'Target.targetCreated':
                info = data['targetInfo']
                opener = info.get('openerId')
                if info.get('type') == 'page' and opener in sessions:
                    if opener != active_target or not tab_ready or len(tabs[active_tab]) >= LIVE_TARGETS:
                        call('Target.closeTarget', dict(targetId=info['targetId']), tab=False)
                    else:
                        leave_target()
                        tabs[active_tab].append(info['targetId'])
                        trim_tabs()
                        activate(info['targetId'])
            elif event == 'Runtime.bindingCalled' and data.get('name') == 'a22xMedia' and tab_ready and msg.get('sessionId') == session:
                control.send(b'M' + str(data.get('payload') or '').encode()[:1000])
            elif event == 'Runtime.bindingCalled' and data.get('name') == 'a22xFullscreen' and tab_ready and msg.get('sessionId') == session:
                try:
                    state = json.loads(data.get('payload') or '{}')
                except ValueError:
                    state = {}
                on, w, h = bool(state.get('on')), float(state.get('w') or 0), float(state.get('h') or 0)
                set_fullscreen(('L' if w > h else 'P') if on else None)
            elif event == 'Target.targetInfoChanged':
                info = data['targetInfo']
                target = info['targetId']
                if target in sessions or target == active_target:
                    titles[target] = str(info.get('title') or '')
                    if target == active_target and tab_ready:
                        send_title(titles[target])
            elif event == 'Target.targetDestroyed':
                target = data['targetId']
                sessions.pop(target, None)
                titles.pop(target, None)
                for tab, targets in tuple(tabs.items()):
                    if target not in targets:
                        continue
                    targets.remove(target)
                    if target == active_target:
                        if targets:
                            activate(targets[-1])
                        else:
                            # A script can close its own target.
                            del tabs[tab]
                            session = None
                            select_tab(tab, selection, None)
                    break
            elif (event in ('Page.frameStartedLoading', 'Page.frameStoppedLoading') and tab_ready and msg.get('sessionId') == session
                  and (main_frame is None or data.get('frameId') == main_frame)):
                set_loading(event == 'Page.frameStartedLoading')
            elif event == 'Page.loadEventFired' and tab_ready and msg.get('sessionId') == session:
                if not direct and visible:
                    # The capture can otherwise stay with the old render
                    # surface when a navigation replaces it with a static page.
                    call('Page.stopScreencast')
                    start_screencast()
                set_loading(False)
                call('Page.getFrameTree',reply=show_location)
                refresh_history()
            elif event == 'Page.screencastFrame':
                frame_session = msg['sessionId']
                if not visible or not tab_ready or frame_session != session:
                    ack_screencast(frame_session, data['sessionId'])
                elif waiting_frame:
                    # Native has the shared buffer until it acknowledges F.
                    # Preserve the latest picture of a static page meanwhile.
                    drop_staged_frame()
                    staged_frame = (frame_session, data)
                else:
                    publish_screencast(frame_session, data)
            elif event == 'Page.frameNavigated' and tab_ready and msg.get('sessionId') == session and 'parentId' not in data['frame']:
                main_frame = data['frame']['id']
                world, world_asked = None, False  # a new document has a new world
                report_location(data['frame'])
                refresh_history()
            elif event == 'Page.navigatedWithinDocument' and tab_ready and msg.get('sessionId') == session and data.get('url') and data.get('frameId') == main_frame:
                control.send(b'U' + data['url'].encode()[:2048])
                remember_page(profile, data['url'])
                refresh_history()
            elif event == 'Browser.downloadWillBegin' and isinstance(data.get('guid'), str) and len(transfers) < 64:
                transfers[data['guid']] = None
                names[data['guid']] = str(data.get('suggestedFilename') or '')[:200]
                show_progress()
            elif event == 'Browser.downloadProgress' and data.get('state') == 'inProgress' and data.get('guid') in transfers:
                total, received = data.get('totalBytes') or 0, data.get('receivedBytes') or 0
                transfers[data['guid']] = min(100, int(received * 100 // total)) if total > 0 else None
                show_progress()
            elif event == 'Browser.downloadProgress' and data.get('state') in ('completed','canceled'):
                transfers.pop(data.get('guid'), None)
                name = names.pop(data.get('guid'), '')
                show_progress()
                if data['state'] == 'completed':
                    # Y<name>: one download has finished (2026-11-20: the interface opens its Downloads page).
                    control.send(b'Y' + name.encode()[:400])
                control.send(b'S' + (os.environ.get('WEB_DOWNLOAD_FOLDER','Downloads').encode() if data['state']=='completed' else b'Download canceled'))


if __name__ == '__main__':
    try:
        run()
    except (OSError, RuntimeError, ValueError, KeyError) as exc:
        try:
            os.write(0, b'S' + str(exc).encode()[:96])
        except OSError:
            pass
        sys.exit(1)
