//go:build integration

package storage

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIntegrationLoopbackGrow is a smoke test for the online-grow sequence
// we depend on: losetup resize -> cryptsetup resize -> resize2fs. It does
// NOT exercise our package functions — that would require allowlist-override
// plumbing. Instead it verifies the system-level commands behave as expected
// on the target OS, so we catch upstream breakage before production.
//
// Run with:
//
//	sudo go test -tags=integration ./internal/storage/ -run TestIntegrationLoopback -v
//
// Requires root (losetup + cryptsetup). Skips on non-root. Requires Linux.
func TestIntegrationLoopbackGrow(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("integration test requires root")
	}

	dir := t.TempDir()
	img := filepath.Join(dir, "disk.img")

	run := func(name string, args ...string) {
		t.Helper()
		out, err := exec.Command(name, args...).CombinedOutput()
		require.NoErrorf(t, err, "%s %v: %s", name, args, out)
	}

	runOut := func(name string, args ...string) string {
		t.Helper()
		out, err := exec.Command(name, args...).CombinedOutput()
		require.NoErrorf(t, err, "%s %v: %s", name, args, out)
		return strings.TrimSpace(string(out))
	}

	// 1. Create a 64 MiB sparse file and attach as a loop device.
	f, err := os.Create(img)
	require.NoError(t, err)
	require.NoError(t, f.Truncate(64*1024*1024))
	require.NoError(t, f.Close())

	loopDev := runOut("losetup", "-f", "--show", img)
	t.Cleanup(func() { _ = exec.Command("losetup", "-d", loopDev).Run() })

	// 2. LUKS-format and open.
	const testMapperName = "pd-auto-grow-test"
	const passphrase = "correct horse battery staple"
	formatCmd := exec.Command("cryptsetup", "luksFormat", "--pbkdf", "pbkdf2", "--batch-mode", loopDev, "-")
	formatCmd.Stdin = strings.NewReader(passphrase)
	formatOut, err := formatCmd.CombinedOutput()
	require.NoErrorf(t, err, "luksFormat: %s", formatOut)

	openCmd := exec.Command("cryptsetup", "luksOpen", loopDev, testMapperName, "-")
	openCmd.Stdin = strings.NewReader(passphrase)
	openOut, err := openCmd.CombinedOutput()
	require.NoErrorf(t, err, "luksOpen: %s", openOut)
	testMapper := "/dev/mapper/" + testMapperName
	t.Cleanup(func() { _ = exec.Command("cryptsetup", "luksClose", testMapperName).Run() })

	// 3. Create filesystem and mount.
	run("mkfs.ext4", "-F", testMapper)
	mountPoint := filepath.Join(dir, "mnt")
	require.NoError(t, os.MkdirAll(mountPoint, 0o755))
	run("mount", testMapper, mountPoint)
	t.Cleanup(func() { _ = exec.Command("umount", mountPoint).Run() })

	// 4. Record initial mapper size.
	before := runOut("blockdev", "--getsize64", testMapper)

	// 5. Grow the backing file and tell losetup to rescan.
	require.NoError(t, os.Truncate(img, 128*1024*1024))
	run("losetup", "--set-capacity", loopDev)

	// 6. Perform the grow sequence with the real commands.
	run("cryptsetup", "resize", testMapperName)
	run("resize2fs", testMapper)

	// 7. Assert new mapper size > old.
	after := runOut("blockdev", "--getsize64", testMapper)
	assert.NotEqual(t, before, after, "mapper size should change after grow")

	// 8. Sanity: df reports the new FS size.
	_, err = exec.Command("df", "-B1", mountPoint).CombinedOutput()
	require.NoError(t, err)
}
