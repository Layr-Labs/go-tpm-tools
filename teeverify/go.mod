module github.com/Layr-Labs/go-tpm-tools/teeverify

go 1.23.0

toolchain go1.24.4

replace github.com/Layr-Labs/go-tpm-tools => ..

require (
	github.com/Layr-Labs/go-tpm-tools v0.4.4
	github.com/google/go-sev-guest v0.14.0
	github.com/google/go-tdx-guest v0.3.2-0.20241009005452-097ee70d0843
	github.com/google/go-tpm v0.9.6
	google.golang.org/protobuf v1.36.7
)

require (
	github.com/google/certificate-transparency-go v1.1.2 // indirect
	github.com/google/go-attestation v0.5.1 // indirect
	github.com/google/go-configfs-tsm v0.3.3 // indirect
	github.com/google/go-eventlog v0.0.2-0.20241003021507-01bb555f7cba // indirect
	github.com/google/go-tspi v0.3.0 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.41.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
)
