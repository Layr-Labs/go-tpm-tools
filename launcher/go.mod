module github.com/Layr-Labs/go-tpm-tools/launcher

go 1.24.0

toolchain go1.24.4

require (
	cloud.google.com/go/compute/metadata v0.9.0
	cloud.google.com/go/logging v1.13.0
	github.com/Layr-Labs/eigenx-kms v0.0.0-20260225212422-401bde321d28
	github.com/Layr-Labs/go-tpm-tools v0.4.8-0.20260224231618-3df231bf0b04
	github.com/Layr-Labs/go-tpm-tools/verifier v0.4.4
	github.com/cenkalti/backoff/v4 v4.3.0
	github.com/containerd/containerd v1.7.23
	github.com/containerd/containerd/v2 v2.0.1
	github.com/containerd/typeurl/v2 v2.2.3
	github.com/coreos/go-systemd/v22 v22.5.0
	github.com/golang-jwt/jwt/v4 v4.5.1
	github.com/google/go-cmp v0.7.0
	github.com/google/go-configfs-tsm v0.3.3
	github.com/google/go-tdx-guest v0.3.2-0.20241009005452-097ee70d0843
	github.com/google/go-tpm v0.9.6
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/image-spec v1.1.0
	github.com/opencontainers/runtime-spec v1.2.0
	golang.org/x/crypto v0.43.0
	golang.org/x/oauth2 v0.33.0
	google.golang.org/api v0.256.0
	google.golang.org/genproto/googleapis/api v0.0.0-20251111163417-95abcf5c77ba
	google.golang.org/grpc v1.76.0
	google.golang.org/protobuf v1.36.10
)

require (
	cloud.google.com/go v0.123.0 // indirect
	cloud.google.com/go/auth v0.17.0 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.8 // indirect
	cloud.google.com/go/confidentialcomputing v1.9.3-0.20250902151313-51583bd5c9b8 // indirect
	cloud.google.com/go/longrunning v0.7.0 // indirect
	filippo.io/edwards25519 v1.0.0-rc.1 // indirect
	github.com/AdaLogics/go-fuzz-headers v0.0.0-20240806141605-e8a1dd7889d6 // indirect
	github.com/AdamKorcz/go-118-fuzz-build v0.0.0-20231105174938-2b5cbb29f3e2 // indirect
	github.com/Layr-Labs/eigenx-contracts v0.0.0-20260223155637-6137f1b215df // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/Microsoft/hcsshim v0.12.9 // indirect
	github.com/StackExchange/wmi v1.2.1 // indirect
	github.com/bits-and-blooms/bitset v1.20.0 // indirect
	github.com/blendle/zapdriver v1.3.1 // indirect
	github.com/btcsuite/btcd v0.24.0 // indirect
	github.com/btcsuite/btcd/btcec/v2 v2.2.0 // indirect
	github.com/btcsuite/btcd/btcutil v1.1.5 // indirect
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0 // indirect
	github.com/cenkalti/backoff/v5 v5.0.0 // indirect
	github.com/consensys/gnark-crypto v0.18.0 // indirect
	github.com/containerd/cgroups/v3 v3.0.3 // indirect
	github.com/containerd/containerd/api v1.8.0 // indirect
	github.com/containerd/continuity v0.4.4 // indirect
	github.com/containerd/errdefs v1.0.0 // indirect
	github.com/containerd/errdefs/pkg v0.3.0 // indirect
	github.com/containerd/fifo v1.1.0 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/containerd/platforms v1.0.0-rc.0 // indirect
	github.com/containerd/ttrpc v1.2.6 // indirect
	github.com/crate-crypto/go-eth-kzg v1.3.0 // indirect
	github.com/crate-crypto/go-ipa v0.0.0-20240724233137-53bbb0ceb27a // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/deckarep/golang-set/v2 v2.6.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/docker/go-events v0.0.0-20190806004212-e31b211e4f1c // indirect
	github.com/ethereum/c-kzg-4844/v2 v2.1.0 // indirect
	github.com/ethereum/go-ethereum v1.16.2 // indirect
	github.com/ethereum/go-verkle v0.2.2 // indirect
	github.com/fatih/color v1.16.0 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/fsnotify/fsnotify v1.7.0 // indirect
	github.com/gagliardetto/binary v0.8.0 // indirect
	github.com/gagliardetto/solana-go v1.13.0 // indirect
	github.com/gagliardetto/treeout v0.1.4 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/goccy/go-json v0.10.5 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/google/certificate-transparency-go v1.1.2 // indirect
	github.com/google/go-attestation v0.5.1 // indirect
	github.com/google/go-eventlog v0.0.2-0.20241003021507-01bb555f7cba // indirect
	github.com/google/go-sev-guest v0.14.1 // indirect
	github.com/google/go-tspi v0.3.0 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/google/s2a-go v0.1.9 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.7 // indirect
	github.com/googleapis/gax-go/v2 v2.15.0 // indirect
	github.com/gorilla/websocket v1.5.0 // indirect
	github.com/holiman/uint256 v1.3.2 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/compress v1.17.11 // indirect
	github.com/lestrrat-go/blackmagic v1.0.4 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc/v3 v3.0.0 // indirect
	github.com/lestrrat-go/jwx/v3 v3.0.10 // indirect
	github.com/lestrrat-go/option v1.0.1 // indirect
	github.com/lestrrat-go/option/v2 v2.0.0 // indirect
	github.com/logrusorgru/aurora v2.0.3+incompatible // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/miguelmota/go-ethereum-hdwallet v0.1.3 // indirect
	github.com/mitchellh/go-testing-interface v1.14.1 // indirect
	github.com/moby/locker v1.0.1 // indirect
	github.com/moby/sys/mountinfo v0.7.2 // indirect
	github.com/moby/sys/sequential v0.6.0 // indirect
	github.com/moby/sys/signal v0.7.1 // indirect
	github.com/moby/sys/user v0.3.0 // indirect
	github.com/moby/sys/userns v0.1.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/mostynb/zstdpool-freelist v0.0.0-20201229113212-927304c0c3b1 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/opencontainers/selinux v1.11.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/segmentio/asm v1.2.0 // indirect
	github.com/shirou/gopsutil v3.21.4-0.20210419000835-c7a38de76ee5+incompatible // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/streamingfast/logging v0.0.0-20230608130331-f22c91403091 // indirect
	github.com/supranational/blst v0.3.14 // indirect
	github.com/tklauser/go-sysconf v0.3.12 // indirect
	github.com/tklauser/numcpus v0.6.1 // indirect
	github.com/tyler-smith/go-bip39 v1.1.0 // indirect
	go.mongodb.org/mongo-driver v1.12.2 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.63.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.61.0 // indirect
	go.opentelemetry.io/otel v1.38.0 // indirect
	go.opentelemetry.io/otel/metric v1.38.0 // indirect
	go.opentelemetry.io/otel/trace v1.38.0 // indirect
	go.uber.org/atomic v1.7.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.21.0 // indirect
	golang.org/x/net v0.46.0 // indirect
	golang.org/x/sync v0.18.0 // indirect
	golang.org/x/sys v0.37.0 // indirect
	golang.org/x/term v0.36.0 // indirect
	golang.org/x/text v0.30.0 // indirect
	golang.org/x/time v0.14.0 // indirect
	google.golang.org/genproto v0.0.0-20250922171735-9219d122eba9 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251111163417-95abcf5c77ba // indirect
)

replace (
	github.com/Layr-Labs/go-tpm-tools v0.4.4 => ../
	github.com/Layr-Labs/go-tpm-tools/verifier v0.4.4 => ../verifier
)
