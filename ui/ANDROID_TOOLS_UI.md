# Android report and module rescue UI — P0 (2026-11-17)

The Android menu adds a read-only compatibility report and module rescue. Existing Samsung/GSI installation still performs a clean installation and erases userdata. The compatibility page has no install action.

## Contracts and authority

`android_compat.py --device inspect --volume V --volume-token T --path P` reads the selected package using the existing Files source picker. The page shows every admitted check (including decrypt, application-data, transition and rollback checks), current/target build IDs, and separate rollback warnings before and after first boot. Unknown checks remain unknown. A report with `preserve_allowed: true` is refused by this P0 UI contract.

`android_modules.py --device inventory` supplies framework identity and module status. Mutations require the exact Magisk 31.0 or 31.1 marker adapter, authenticated mounted userdata, confirmed RW access and a valid volume token. APatch, KernelSU, unknown versions and unsupported modules are read-only. Unsupported directory names remain visible as bounded diagnostic labels with no actions, so a malformed neighbour does not hide valid modules. Pending copies are admitted only by the backend adapter; the UI verifies every active/pending marker path.

Disable, enable, remove, cancel removal and disable-all first request a backend preview. Apply requires a two-second hold and sends only the exact action, optional module ID, expected plan SHA-256 and explicit confirmation. The UI verifies framework/access/token binding, marker direction and unique exact paths. Back, Home, opening Files, invalid JSON and abandoned preview replies discard plan authority. The backend revalidates the complete plan before writing. The apply response must bind the same SHA, changed count and applied journal status before the UI refreshes inventory.

Open Android data uses the existing Files volume/password and mount lifecycle. It selects userdata explicitly, clears stale file selection, and returns to a fresh module inventory after mount. There is no second password implementation.

## Limits

The UI admits full bounded 32-image analyzer reports and refuses reports above 192 checks, inventories above 96 modules, and previews above 192 marker changes instead of silently showing a partial review. UI navigation and summaries have English, Ukrainian and German text; backend diagnostic evidence remains verbatim. This UI does not add module ZIP installation, a dedicated module-backup workflow, a data-preserving writer, selective migration, other Android users or checkpoints.

Removal is deferred until Android starts; Android may run the module uninstall script then. Recovery does not run it. Disable/remove does not reverse persistent changes previously made by a module or global boot scripts. Synthetic host previews and tests do not qualify Android activation, storage remount persistence or a build transition on hardware.

## Host verification

`make -C ui a22x-recovery-ui android-tools-test nav-ui-test android-format-test`

`ui/a22x-recovery-ui --self-test`

`make -C ui android-tools-report-test` passes a real maximum-image Python analyzer report through the C parser and checks rejection beyond its display bound.

The Android-tools test covers malformed inventory/report/plan refusal, exact adapters, pending copies, stale RO access, path/marker/action/token binding, disabled buttons, hold duration, cancellation, late read replies, source-picker mode retention, userdata selection, and a real asynchronous host-only CLI preview/apply/inventory cycle. Synthetic previews: `android-compat`, `android-modules-locked`, `android-modules`, `android-module-confirm`.
