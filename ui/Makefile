CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Werror -Wno-format-truncation -fstack-protector-strong -D_FORTIFY_SOURCE=2
LDFLAGS ?= -Wl,--build-id=none
LDLIBS ?= -lm
CROSS_COMPILE ?= aarch64-linux-gnu-
# MT6833 has Cortex-A76 and A55 cores, which share this instruction set.
ARM64_TUNE ?= -O3 -mcpu=cortex-a76 -fno-semantic-interposition
UI_HEADERS = web_ui.h sound_ui.h android_tools_types.h android_tools_ui.h android_session_ui.h automount_ui.h android_format_ui.h android_data_backup_ui.h androidlog_ui.h updates_ui.h json_min.h font_data.h font_extra.h clock_font.h native_canvas.h i18n_data.h flash_ui.h theme.h theme_files.h theme_editor.h theme_assets.h kinetic_scroll.h terminal_model.h terminal_ui.h terminal_font.h systems_ui.h install_types.h install_ui.h wifi_ui.h installer_ui.h images_ui.h adb_ui.h packages_ui.h identity_ui.h android_plan_ui.h wipe_ui.h android_ui.h card_ui.h copies_ui.h source_ui.h screenshot_ui.h charger_ui.h shells_ui.h locale_ui.h zones_data.h app_icons_data.h linuxdata_ui.h \
	qs_types.h shade_ui.h media_ui.h media_client.h player_ui.h bluetooth_ui.h file_install_ui.h recents_ui.h

all: a22x-recovery-ui

i18n:
	python3 -B tools/extract_i18n.py
	python3 -B tools/update_po.py
	python3 -B tools/generate_i18n.py

a22x-recovery-ui: recovery_ui.c json_min.c $(UI_HEADERS)
	$(CC) $(CFLAGS) recovery_ui.c json_min.c $(LDFLAGS) -o $@ $(LDLIBS)

static:
	$(CC) $(CFLAGS) recovery_ui.c json_min.c $(LDFLAGS) -static -o a22x-recovery-ui-static $(LDLIBS)

arm64:
	$(CROSS_COMPILE)gcc $(CFLAGS) $(ARM64_TUNE) recovery_ui.c json_min.c $(LDFLAGS) -static -o a22x-recovery-ui-aarch64 $(LDLIBS)
	$(CROSS_COMPILE)strip a22x-recovery-ui-aarch64

test: a22x-recovery-ui
	./a22x-recovery-ui --self-test
	python3 tools/test_cpu_policy.py

# The browser compositor on the host (2026-11-20): frame slots, acknowledgements and the UI's own
# frame socket, with a Wayland client drawing numbered frames. Needs wayland-server/-client and
# wayland-protocols; the phone's build is musl (see docs/browser-fps-20261120.uk.md).
WAYLAND_PROTOCOLS ?= /usr/share/wayland-protocols
WL = .web-compositor-test
web-compositor-test: web_compositor.c web_dmabuf.h test_web_compositor.c
	mkdir -p $(WL)
	wayland-scanner server-header $(WAYLAND_PROTOCOLS)/stable/xdg-shell/xdg-shell.xml $(WL)/xdg-shell-server-protocol.h
	wayland-scanner client-header $(WAYLAND_PROTOCOLS)/stable/xdg-shell/xdg-shell.xml $(WL)/xdg-shell-client-protocol.h
	wayland-scanner private-code $(WAYLAND_PROTOCOLS)/stable/xdg-shell/xdg-shell.xml $(WL)/xdg-shell-protocol.c
	wayland-scanner server-header $(WAYLAND_PROTOCOLS)/unstable/linux-dmabuf/linux-dmabuf-unstable-v1.xml $(WL)/linux-dmabuf-server-protocol.h
	wayland-scanner private-code $(WAYLAND_PROTOCOLS)/unstable/linux-dmabuf/linux-dmabuf-unstable-v1.xml $(WL)/linux-dmabuf-protocol.c
	wayland-scanner server-header $(WAYLAND_PROTOCOLS)/stable/presentation-time/presentation-time.xml $(WL)/presentation-time-server-protocol.h
	wayland-scanner client-header $(WAYLAND_PROTOCOLS)/stable/presentation-time/presentation-time.xml $(WL)/presentation-time-client-protocol.h
	wayland-scanner private-code $(WAYLAND_PROTOCOLS)/stable/presentation-time/presentation-time.xml $(WL)/presentation-time-protocol.c
	$(CC) -std=c17 -O2 -Wall -Wextra -Werror -I$(WL) web_compositor.c $(WL)/xdg-shell-protocol.c $(WL)/linux-dmabuf-protocol.c $(WL)/presentation-time-protocol.c -lwayland-server -o $(WL)/web-compositor
	$(CC) -std=c17 -O2 -Wall -Wextra -Werror -I$(WL) test_web_compositor.c $(WL)/xdg-shell-protocol.c $(WL)/presentation-time-protocol.c -lwayland-client -o $(WL)/test-web-compositor
	./$(WL)/test-web-compositor ./$(WL)/web-compositor direct
	./$(WL)/test-web-compositor ./$(WL)/web-compositor relay

integration: a22x-recovery-ui
	python3 tools/test_integration.py

card-ui-integration: a22x-recovery-ui
	python3 tools/test_card_ui.py

files-integration: a22x-recovery-ui
	python3 tools/test_filesystem_integration.py

v03-integration: a22x-recovery-ui
	python3 tools/test_v03_integration.py

interaction-integration: a22x-recovery-ui
	python3 tools/test_v04_interaction.py

motion-integration: a22x-recovery-ui
	python3 tools/test_v05_interaction.py

linux-integration: a22x-recovery-ui
	python3 tools/test_v05_linux.py

usb-ui-integration: a22x-recovery-ui
	python3 tools/test_v05_usb_ui.py

terminal-model-test: test_terminal_model.c terminal_model.h
	$(CC) $(CFLAGS) test_terminal_model.c $(LDFLAGS) -o terminal-model-test $(LDLIBS)
	./terminal-model-test

terminal-ui-test: test_terminal_ui.c recovery_ui.c json_min.c $(UI_HEADERS)
	$(CC) $(CFLAGS) test_terminal_ui.c json_min.c $(LDFLAGS) -o terminal-ui-test $(LDLIBS)

terminal-ui-integration: terminal-ui-test
	python3 tools/test_terminal_ui.py

display-ui-test: test_display_ui.c recovery_ui.c json_min.c $(UI_HEADERS)
	$(CC) $(CFLAGS) test_display_ui.c json_min.c $(LDFLAGS) -o display-ui-test $(LDLIBS)

display-ui-integration: display-ui-test
	python3 tools/test_display_ui.py

locale-ui-test: test_locale_ui.c recovery_ui.c json_min.c $(UI_HEADERS)
	$(CC) $(CFLAGS) test_locale_ui.c json_min.c $(LDFLAGS) -o locale-ui-test $(LDLIBS)
	./locale-ui-test

shells-ui-test: test_shells_ui.c recovery_ui.c json_min.c $(UI_HEADERS)
	$(CC) $(CFLAGS) test_shells_ui.c json_min.c $(LDFLAGS) -o shells-ui-test $(LDLIBS)
	./shells-ui-test

charger-ui-test: test_charger_ui.c recovery_ui.c json_min.c $(UI_HEADERS)
	$(CC) $(CFLAGS) test_charger_ui.c json_min.c $(LDFLAGS) -o charger-ui-test $(LDLIBS)
	mkdir -p charger-ui-work && ./charger-ui-test charger-ui-work

screenshot-test: test_screenshot.c recovery_ui.c json_min.c $(UI_HEADERS)
	$(CC) $(CFLAGS) test_screenshot.c json_min.c $(LDFLAGS) -o screenshot-test $(LDLIBS)
	python3 tools/test_screenshot.py

identity-ui-test: test_identity_ui.c recovery_ui.c json_min.c $(UI_HEADERS)
	$(CC) $(CFLAGS) test_identity_ui.c json_min.c $(LDFLAGS) -o identity-ui-test $(LDLIBS)

identity-ui-integration: identity-ui-test
	python3 tools/test_identity_ui.py

flash-chain-test: test_flash_chain.c recovery_ui.c json_min.c $(UI_HEADERS)
	$(CC) $(CFLAGS) test_flash_chain.c json_min.c $(LDFLAGS) -o flash-chain-test $(LDLIBS)
	mkdir -p flash-chain-work && ./flash-chain-test flash-chain-work

# Where Back leads: every page through its buttons, and the reads that end after a page was left.
nav-ui-test: test_nav_ui.c recovery_ui.c json_min.c $(UI_HEADERS)
	$(CC) $(CFLAGS) test_nav_ui.c json_min.c $(LDFLAGS) -o nav-ui-test $(LDLIBS)
	mkdir -p nav-ui-work && ./nav-ui-test nav-ui-work

catalog-chain-test: test_catalog_chain.c recovery_ui.c json_min.c $(UI_HEADERS)
	$(CC) $(CFLAGS) test_catalog_chain.c json_min.c $(LDFLAGS) -o catalog-chain-test $(LDLIBS)
	mkdir -p catalog-chain-work && ./catalog-chain-test catalog-chain-work

touch-input-test: test_touch_input.c recovery_ui.c json_min.c $(UI_HEADERS)
	$(CC) $(CFLAGS) test_touch_input.c json_min.c $(LDFLAGS) -o touch-input-test $(LDLIBS)
	./touch-input-test

systems-ui-test: test_systems_ui.c recovery_ui.c json_min.c $(UI_HEADERS)
	$(CC) $(CFLAGS) test_systems_ui.c json_min.c $(LDFLAGS) -o systems-ui-test $(LDLIBS)

systems-ui-integration: systems-ui-test
	python3 tools/test_systems_ui.py

install-ui-test: test_install_ui.c recovery_ui.c json_min.c $(UI_HEADERS)
	$(CC) $(CFLAGS) test_install_ui.c json_min.c $(LDFLAGS) -o install-ui-test $(LDLIBS)

install-ui-integration: install-ui-test
	python3 tools/test_install_ui.py

install-backend-ui-test: test_install_backend_ui.c recovery_ui.c json_min.c $(UI_HEADERS)
	$(CC) $(CFLAGS) test_install_backend_ui.c json_min.c $(LDFLAGS) -o install-backend-ui-test $(LDLIBS)

install-backend-integration: install-backend-ui-test
	python3 tools/test_install_backend_ui.py

install-preview: test_install_preview.c recovery_ui.c json_min.c $(UI_HEADERS)
	$(CC) $(CFLAGS) test_install_preview.c json_min.c $(LDFLAGS) -o install-preview $(LDLIBS)

preview: a22x-recovery-ui
	mkdir -p previews
	./a22x-recovery-ui --preview home --render previews/home.ppm
	./a22x-recovery-ui --preview backup --render previews/backup.ppm
	./a22x-recovery-ui --preview plan --render previews/plan.ppm
	./a22x-recovery-ui --preview device-restore --render previews/device-restore.ppm
	./a22x-recovery-ui --preview files --render previews/files.ppm
	./a22x-recovery-ui --preview file-browser --render previews/file-browser.ppm
	./a22x-recovery-ui --preview file-editor --render previews/file-editor.ppm
	./a22x-recovery-ui --preview file-confirm --render previews/file-confirm.ppm
	./a22x-recovery-ui --preview file-locked --render previews/file-locked.ppm
	./a22x-recovery-ui --preview file-editor --render-native previews/file-editor-native.ppm
	./a22x-recovery-ui --preview file-browser --render-native previews/file-browser-native.ppm
	for screen in home backup power download-confirm tools tools-export file-info file-symlink file-permissions display display-unavailable file-scroll volume-scroll editor-scroll text-scroll linux-prepare linux-plan linux-space-blocked linux-wipe linux-restore usb-files usb-active usb-unavailable; do ./a22x-recovery-ui --preview $$screen --render-native previews/$$screen-native.ppm; done
	python3 tools/ppm_to_png.py previews

clean:
	rm -f theme-editor-test a22x-recovery-ui a22x-recovery-ui-static a22x-recovery-ui-aarch64 android-unlock-test android-format-test android-policy-settings-test

.PHONY: android-unlock-test android-format-test i18n all static arm64 test integration files-integration v03-integration interaction-integration motion-integration linux-integration usb-ui-integration terminal-model-test terminal-ui-integration display-ui-integration touch-input-test systems-ui-integration install-ui-integration install-backend-integration preview clean

android-unlock-test: test_android_unlock.c recovery_ui.c json_min.c $(UI_HEADERS)
	$(CC) $(CFLAGS) test_android_unlock.c json_min.c $(LDFLAGS) -o android-unlock-test $(LDLIBS)
	./android-unlock-test

android-format-test: test_android_format.c recovery_ui.c json_min.c $(UI_HEADERS)
	$(CC) $(CFLAGS) test_android_format.c json_min.c $(LDFLAGS) -o android-format-test $(LDLIBS)
	./android-format-test

# Mounting at start end to end: the interface, automount.py and filesystem.py on fixture volumes.
.PHONY: automount-ui-test
automount-ui-test: test_automount_ui.c recovery_ui.c json_min.c $(UI_HEADERS)
	$(CC) $(CFLAGS) test_automount_ui.c json_min.c $(LDFLAGS) -o automount-ui-test $(LDLIBS)
	./automount-ui-test .. $(shell command -v python3)

.PHONY: android-session-test
android-session-test: test_android_session.c recovery_ui.c json_min.c $(UI_HEADERS)
	$(CC) $(CFLAGS) test_android_session.c json_min.c $(LDFLAGS) -o android-session-test $(LDLIBS)
	./android-session-test

.PHONY: android-policy-settings-integration
android-policy-settings-test: test_android_policy_settings.c recovery_ui.c json_min.c $(UI_HEADERS)
	$(CC) $(CFLAGS) test_android_policy_settings.c json_min.c $(LDFLAGS) -o android-policy-settings-test $(LDLIBS)

android-policy-settings-integration: android-policy-settings-test
	python3 -B tools/test_android_policy_settings.py

.PHONY: android-media-ui-integration
android-data-backup-ui-test: test_android_data_backup_ui.c recovery_ui.c json_min.c $(UI_HEADERS)
	$(CC) $(CFLAGS) test_android_data_backup_ui.c json_min.c $(LDFLAGS) -o $@ $(LDLIBS)

android-media-ui-integration: android-data-backup-ui-test
	python3 -B tools/test_android_media_ui.py

ui-audit-test: test_ui_audit.c recovery_ui.c json_min.c $(UI_HEADERS)
	$(CC) $(CFLAGS) test_ui_audit.c json_min.c $(LDFLAGS) -o ui-audit-test $(LDLIBS)
	./ui-audit-test

android-tools-test: test_android_tools.c recovery_ui.c json_min.c $(UI_HEADERS)
	$(CC) $(CFLAGS) test_android_tools.c json_min.c $(LDFLAGS) -o android-tools-test $(LDLIBS)
	./android-tools-test

.PHONY: android-tools-report-test
android-tools-report-test: android-tools-test
	PYTHONDONTWRITEBYTECODE=1 python3 -B ../tests/test_android_tools_ui.py

theme-editor-test: test_theme_editor.c recovery_ui.c json_min.c $(UI_HEADERS)
	$(CC) $(CFLAGS) test_theme_editor.c json_min.c $(LDFLAGS) -o $@ $(LDLIBS)

.PHONY: theme-editor-integration
theme-editor-integration: theme-editor-test
	@set -e; root=$$(mktemp -d); trap 'rm -rf "$$root"' EXIT; \
	echo '{"schema":"a22x.filesystem.fixture.v1","volumes":[]}' > "$$root/filesystem-fixture.json"; \
	A22X_THEMES_RAM="$$root/ram" A22X_THEMES_BUNDLED="$$root/bundled" \
	A22X_RECOVERY_THEMES_HELPER="$(abspath ../themes.py)" ./theme-editor-test "$$root"
