# Design Document: Persistent Storage for Confidential Space Workloads

**Status**: Merged (PR #16); runtime auto-grow added in PR #26
**Date**: 2026-03-13 (runtime auto-grow section added 2026-04-27)

---

## 1. Problem Statement

Workloads running inside Confidential VMs need access to persistent storage that survives container restarts and VM reboots. The storage must be encrypted at rest using LUKS, with the encryption key provided externally (e.g. derived from a KMS mnemonic). The launcher must support two deployment modes:

1. **With a secondary persistent disk** -- LUKS-encrypted volume, formatted on first boot, reopened on subsequent boots.
2. **Without a secondary disk** -- Graceful fallback to a directory on the boot disk (which is already encrypted by the platform).

---

## 2. Architecture Overview

```
Run()
  |
  v
SetupSecondaryEncryptedVolume(logger, mnemonicProvider)
  |
  |-- Detect secondary device at /dev/disk/by-id/google-persistent_storage_1
  |
  |-- [no device found]
  |     +-- mkdir /mnt/disks/userdata on boot disk -> return
  |
  |-- [device found]
  |     |-- Call mnemonicProvider() to obtain encryption key material
  |     |-- Derive 32-byte key, hex-encode for cryptsetup
  |     |
  |     |-- [no LUKS header on device]  (first boot)
  |     |     |-- cryptsetup luksFormat
  |     |     |-- cryptsetup luksOpen
  |     |     +-- mkfs.ext4
  |     |
  |     |-- [LUKS header exists]  (reboot)
  |     |     +-- cryptsetup luksOpen
  |     |
  |     |-- mkdir /mnt/disks/userdata
  |     +-- mount /dev/mapper/userdata -> /mnt/disks/userdata
  |
  v
Update container spec with bind mount
  |-- /mnt/disks/userdata (host) -> /mnt/disks/userdata (container), rw
  |
  v
Start workload container
  |-- USER_PERSISTENT_DATA_PATH=/mnt/disks/userdata available as env var
```

---

## 3. Design Decisions

### 3.1 Separation of User Data and System Data

**Decision**: Use a dedicated secondary persistent disk for user data, separate from the boot disk that holds the OS and launcher.

**Rationale**: If user data and system data live on the same disk, the OS image cannot be upgraded without losing user data -- the boot disk is replaced wholesale during image updates. By placing user data on an independent persistent disk, the system disk can be swapped for a new OS version while the user data disk is simply reattached to the new VM. This separation ensures workload state survives OS upgrades, not just reboots.

### 3.2 Device Detection by Google Device Name

**Decision**: Detect the secondary storage device at the fixed path `/dev/disk/by-id/google-persistent_storage_1`.

**Constraint**: The raw device path for a persistent disk varies depending on the device driver and machine type. For example, the same disk may appear as `/dev/sdb` on one machine type and `/dev/nvme0n2` on another. This makes raw device paths unreliable for detection.

**Rationale**: GCE provides stable symlinks under `/dev/disk/by-id/google-<device-name>` based on the persistent disk's operator-assigned device name. By pinning the expected device name to `persistent_storage_1`, we get a stable path regardless of the underlying driver. The operator sets this device name when attaching the disk. See `launcher/internal/storage/encrypted_volume.go` for the implementation.

### 3.3 LUKS with First-Boot Detection

**Decision**: Use `cryptsetup isLuks` to detect whether the device has already been formatted, then branch into first-boot (format + open + mkfs) vs. reboot (open only) paths.

**Rationale**: This lets the same code handle both initial provisioning and subsequent reboots without requiring external state or flags. The LUKS header on the device itself is the source of truth.

### 3.4 Post-CEL Container Spec Update

**Decision**: Add the user-data bind mount to the container spec *after* CEL measurement, using `container.Update()` with `typeurl.MarshalAny`.

**Rationale**: The encrypted volume must be set up before it can be bind-mounted, but CEL measurement must happen before the TEE server starts (to lock PCR values). Since mounts are not currently included in CEL measurements, adding the mount post-measurement is safe. A comment in the code flags this ordering dependency for future reviewers.

### 3.5 Shared Mount Point for Both Modes

**Decision**: Use the identical path `/mnt/disks/userdata` for both the host-side mount and the container-side bind mount destination, regardless of whether storage is backed by a LUKS volume or a boot-disk directory.

**Rationale**: Both `MountPoint` and `ContainerMountPoint` are set to the same value. The workload container always sees the same `USER_PERSISTENT_DATA_PATH` and the same bind mount destination. Application code does not need to know which backend is in use, and host-side debugging is simplified because the paths match.

### 3.6 Online PD Auto-Grow

**Decision**: Grow the secondary PD online from inside the launcher, via a background poller that runs for the lifetime of the workload container. No VM restart, no unmount, no passphrase re-entry.

**Rationale**: Operators resize the underlying GCE persistent disk via `gcloud compute disks resize`. For the workload to actually see the new capacity, three layers must grow in order: kernel-visible block device -> LUKS mapper -> ext4 filesystem. Doing this online (rather than at boot) means operators can expand storage under a running workload with zero downtime. The poller lives inside the launcher process because its lifetime is already tied to the container: when the workload exits, the poller exits; no systemd unit to manage.

**Flow per tick** (see `launcher/internal/storage/resize.go`, orchestrated by `GrowOnce`):
1. `kernelRescanPD` -- best-effort write to `/sys/block/<dev>/device/rescan`. On SCSI this nudges the kernel to re-read capacity; on NVMe this sysfs node does not exist and the write errors. Errors are intentionally swallowed -- see "Driver-agnostic rescan" below.
2. `blockdev --getsize64` on the backing PD and on `/dev/mapper/userdata`. Feed both sizes into `growNeeded` -- proceed only when `pdSize - mapperSize > luksHeaderBytes` (see "LUKS2 header tolerance" below). Otherwise the tick is a no-op.
3. `cryptsetup resize userdata` grows the dm-crypt mapper to match the PD. This does not require the passphrase -- it only manipulates the kernel's active device-mapper entry.
4. `resize2fs /dev/mapper/userdata` grows ext4 online. The mount stays up throughout.

**LUKS2 header tolerance**: Strict `pdSize == mapperSize` equality is the wrong guard. The LUKS2 header reserves 16 MiB at the start of the backing device, so after a successful `cryptsetup resize` the mapper is permanently exactly 16 MiB smaller than the PD. A strict-equality guard reads that steady state as "grow needed" and re-runs `cryptsetup resize` + `resize2fs` on every tick, forever, with no real work to do. The `growNeeded(pdSize, mapperSize uint64) bool` helper encodes the correct contract: return true only when the PD exceeds the mapper by more than the header reservation (`luksHeaderBytes = 16 * 1024 * 1024`). Both `GrowOnce` (per tick) and `GrowOnceBoot` (boot-time one-shot) gate on this helper, so neither path spins on the header delta. Test coverage (`TestGrowNeeded`, `TestGrowOnce/noop_*`) locks in the boundary: equal sizes, shrink, exactly-at-header-delta, one byte short, and one byte over.

**Driver-agnostic rescan**: The code never parses or assumes a particular device node naming scheme. It operates on the stable GCE symlink `/dev/disk/by-id/google-persistent_storage_1`, resolves it with `filepath.EvalSymlinks` + `filepath.Base`, and joins the result onto `/sys/block/<name>/device/rescan`. Whether that path exists is driver-specific:

| Driver | Device node | `/sys/block/<name>/device/rescan` | Capacity-change notification |
|---|---|---|---|
| SCSI (e.g. N1, N2) | `/dev/sdb` | exists, writable | hypervisor capacity-change interrupt |
| NVMe (e.g. C3, C3D) | `/dev/nvme0nN` | absent (NVMe has `rescan_controller` at the controller level, not per-namespace) | NVMe Asynchronous Event Notification |

On both drivers, the kernel **auto-detects** the capacity change on its own -- on SCSI via the hypervisor-issued capacity-change interrupt, on NVMe via the AEN. By the time `gcloud compute disks resize` returns, `blockdev --getsize64` already reports the new size. The explicit `kernelRescanPD` write is therefore defense-in-depth for environments where auto-detection might lag or be disabled; on NVMe it returns ENOENT and the caller (`GrowOnce` / `GrowOnceBoot`) logs-and-continues. This "rescan is best-effort, not a correctness requirement" contract is the invariant the tests `TestGrowOnce{,Boot}Exported_SwallowsRescanError` lock in.

**`--disable-keyring` on luksOpen**: `cryptsetup resize <name>` does not talk to the LUKS header -- it only adjusts the kernel dm entry -- so in principle no passphrase should be needed. In practice, on cryptsetup >= 2.6 (default on cos-tdx-113) the volume key is stored in the user keyring after `luksOpen`, and `cryptsetup resize` refuses to operate without re-authentication when that keyring entry is present. The fix is to pass `--disable-keyring` at open time: the volume key stays inside dm-crypt's kernel state only, not the user keyring, and `resize` works without the passphrase. This matters because the launcher does not keep the mnemonic-derived key in memory after the volume is opened, by design. See the `luksOpen` doc comment in `encrypted_volume.go` for the full contract.

**Cadence**: `DefaultPollInterval = 60s`. Chosen to make operator resize experience feel near-real-time (worst case: ~1 min after `gcloud disks resize` completes before the mapper + fs catch up) while keeping the subprocess overhead negligible.

**Safety**: Each tick runs inside a `recover()`-guarded function so a panic in one iteration cannot kill the loop. Every command path is allowlisted against `secondaryDevicePath` / `luksMapperName` / `MountPoint` -- the package refuses to operate on any other device, mapper, or mount point, which keeps the surface area small even though the launcher runs as root.

---

### 3.7 No Integrity Check on Encrypted Volume

**Decision**: The LUKS-encrypted volume uses encryption only (`cryptsetup luksFormat` with default cipher) and does not enforce integrity verification.

**What integrity checking provides**: With integrity checking enabled, every write to disk is accompanied by an HMAC computed with a key only the OS holds. On read, the OS recomputes the HMAC and verifies it against the stored value. This means a malicious cloud provider (or any adversary with physical disk access) cannot modify the data and produce a matching HMAC -- the OS will detect the tampering and reject the read. Without integrity checking, the encrypted volume protects confidentiality (data cannot be read) but not authenticity -- a malicious provider could mutate the ciphertext on disk and the container would consume the modified data without detecting the corruption.

**Limitation**: Even with integrity checking enabled, `dm-integrity` does not protect against replay attacks -- an adversary who previously captured a valid sector and its HMAC tag can overwrite the current sector with that old snapshot, and the OS will accept it because the data and tag are internally consistent. This is a narrow attack that requires the adversary to have previously captured the old sector contents and tags, but it is not detectable by HMAC-based integrity alone. Full protection against replay would require additional mechanisms such as a Merkle tree over the disk (e.g. `dm-verity`) or a monotonic counter tied to the volume state.

**Rationale for deferring**: Enabling integrity checking (e.g. `--integrity hmac-sha256` with `dm-integrity`) requires an initial integrity wipe that iterates over every sector of the disk to initialize the HMAC tags. For large persistent disks this can take minutes to tens of minutes on first boot, which is unacceptable for workload startup latency. The current implementation prioritizes fast provisioning. See `launcher/internal/storage/encrypted_volume.go` for the LUKS format parameters.

---

## 4. Component Details

### 4.1 Runtime Grow (`launcher/internal/storage/poller.go`, `resize.go`)

**`Poller`**: Single-goroutine ticker loop. Started by the launcher after `SetupSecondaryEncryptedVolume` succeeds; runs until the workload container exits (launcher process lifetime). Per-tick panic recovery ensures a single bad call cannot silently kill the loop.

**`GrowOnce(ctx, logger)`**: The orchestrator called each tick. Sequence: `kernelRescanPD` (best-effort) -> size-check PD vs mapper -> `growNeeded` tolerance check -> `cryptsetup resize userdata` if grow is needed -> `resize2fs /dev/mapper/userdata`. Each step is idempotent; at the LUKS2-header steady state (`pdSize - mapperSize == luksHeaderBytes`) the whole call is a no-op aside from the structured size log.

**`GrowOnceBoot(ctx, logger)`**: One-shot variant run synchronously at launcher boot, before the workload starts. Same `growNeeded` tolerance as the per-tick path. Ensures any PD grow that occurred while the VM was stopped is applied before workload code sees the filesystem.

**`growNeeded(pdSize, mapperSize uint64) bool`**: Single source of truth for "is a resize required?". Returns true iff `pdSize > mapperSize + luksHeaderBytes`. Shared by `GrowOnce` and `GrowOnceBoot` so both paths have identical tolerance semantics.

**Log levels**: Steady-state per-tick messages (no-op skips, best-effort `kernelRescanPD` ENOENT on NVMe, poller tick failures) log at `Debug`. Only actual grow events (`pd is larger than mapper, resizing` / `resize complete`) and the structured `disk sizes` telemetry log at `Info`. This keeps an idle pre-grow VM silent at the default log level while preserving a clear operator signal when a real grow happens.

**Allowlist constants** (single source of truth in `encrypted_volume.go`, aliased in `resize.go`):
- `allowedBackingDevice = secondaryDevicePath`
- `allowedMapper = mapperPath`
- `allowedMountPoint = MountPoint`
- `luksMapperName = "userdata"`

Every primitive (`pdSizeBytes`, `mapperSizeBytes`, `kernelRescanPD`, `luksResize`, `resizeExt4`) gates its input against these constants and returns `ErrDeviceNotAllowed` on mismatch. Any new caller MUST use the constants; hard-coding paths is rejected at review.

**Structured logging**: Each tick emits `disk sizes` with `pd_size_bytes`, `mapper_size_bytes`, `fs_size_bytes`, `fs_available_bytes`. This is the operator-facing signal for "is the grow being applied?" -- no separate metrics pipeline.

---

### 4.2 Encrypted Volume (`launcher/internal/storage/encrypted_volume.go`)

**Constants**:
- `MountPoint = "/mnt/disks/userdata"` -- Host-side mount path
- `ContainerMountPoint = "/mnt/disks/userdata"` -- Container-side bind mount destination
- `secondaryDevicePath = "/dev/disk/by-id/google-persistent_storage_1"` -- Expected device path
- `luksName = "userdata"` -- dm-crypt mapper name
- `mapperPath = "/dev/mapper/userdata"` -- Opened LUKS device path

**`MnemonicProvider func() (string, error)`**: Type alias for the callback that provides the mnemonic. Only called when a secondary device is detected.

**`SetupSecondaryEncryptedVolume(logger, mnemonicProvider) error`**:

| Scenario | Behavior |
|---|---|
| No secondary device | `os.MkdirAll(MountPoint)` on boot disk. Provider **not** called. |
| Device found, no LUKS header | Call provider -> derive key -> `luksFormat` -> `luksOpen` -> `mkfs.ext4` -> `mount` |
| Device found, LUKS header exists | Call provider -> derive key -> `luksOpen` -> `mount` |

**LUKS helpers** (all unexported):
- `findSecondaryDevice()` -- `os.Stat` on the expected device path
- `isLuksDevice(device)` -- Runs `cryptsetup isLuks`; non-zero exit = not LUKS
- `luksFormat(device, key)` -- `cryptsetup luksFormat --pbkdf pbkdf2 <device> -` with key on stdin
- `luksOpen(device, name, key)` -- `cryptsetup luksOpen <device> <name> -` with key on stdin
- `mkfsExt4(device)` -- `mkfs.ext4 <device>`
- `mount(source, target)` -- `mount <source> <target>`

### 4.3 Container Runner Integration (`launcher/container_runner.go`)

**In `NewRunner()`**:
- Appends `USER_PERSISTENT_DATA_PATH=/mnt/disks/userdata` to the workload environment variables.

**In `Run()`** (after TEE server starts, before container task creation):
1. Defines a `mnemonicProvider` closure that wraps the external key source.
2. Calls `storage.SetupSecondaryEncryptedVolume(logger, mnemonicProvider)`.
3. Updates the container spec via `container.Update()` to add a read-write bind mount:
   - Source: `/mnt/disks/userdata` (host)
   - Destination: `/mnt/disks/userdata` (container)

**`appendUserDataMount(mounts)`**: Helper that appends the bind mount spec (`rbind`, `rw`) to an existing mount list.

---

## 5. Operator Configuration

### Attaching a Secondary Disk

```bash
gcloud compute instances attach-disk <vm-name> \
    --disk=<disk-name> \
    --device-name=persistent_storage_1
```

The device name `persistent_storage_1` is required. GCE creates the stable symlink at `/dev/disk/by-id/google-persistent_storage_1`.

If no secondary disk is attached, the launcher falls back to a plain directory on the boot disk. No configuration change is needed.

### Workload Access

Inside the container, persistent data is available at:
- **Path**: `/mnt/disks/userdata` (read-write bind mount)
- **Env var**: `USER_PERSISTENT_DATA_PATH=/mnt/disks/userdata`

The workload can read and write files under this path. Data persists across container restarts and (with a secondary disk) across VM reboots.

---

## 6. Files

| File | Description |
|---|---|
| `launcher/internal/storage/encrypted_volume.go` | Device detection, LUKS lifecycle, mount point management |
| `launcher/internal/storage/resize.go` | Online grow primitives: kernel rescan, `cryptsetup resize`, `resize2fs`; allowlist guards |
| `launcher/internal/storage/poller.go` | Background ticker driving `GrowOnce` over the workload lifetime |
| `launcher/container_runner.go` | Mnemonic provider wiring, volume setup call, container spec update with bind mount, poller start |

---

## 7. Security Properties

| Property | Mechanism |
|---|---|
| **Key never on disk** | Derived in memory; passed to `cryptsetup` via stdin |
| **Key never in process table** | stdin, not CLI arguments |
| **Key never logged** | Only success/failure messages; key value excluded from all log statements |
| **Key bytes zeroed after use** | `ZeroBytes()` called on raw key bytes after hex-encoding for LUKS |
| **No fallback to placeholder** | Missing mnemonic is a fatal error; hardcoded `defaultKey` removed |
| **Boot disk fallback is safe** | Boot disk is already platform-encrypted; no LUKS needed |

---

## 8. Future Considerations

- **Integrity protection via dm-integrity / dm-clone**: The current LUKS setup provides encryption only (see decision 3.5). A future iteration should add integrity verification using `dm-integrity` with `dm-clone` (or `dm-zero` as an alternative). `dm-clone` can hydrate the integrity metadata in the background while the volume is already online, avoiding the upfront full-disk wipe that blocks first boot. See `launcher/internal/storage/encrypted_volume.go` for the current LUKS format path where this would be integrated.
- **CEL measurement of mounts**: If container mounts are ever added to CEL measurements, the post-measurement mount update ordering must be revisited.
- **Multiple persistent disks**: Currently supports exactly one secondary disk (`persistent_storage_1`). Supporting multiple disks would require extending device detection, key derivation (per-disk DST), and mount logic.
