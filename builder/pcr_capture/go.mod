module github.com/Layr-Labs/go-tpm-tools/builder/pcr_capture

go 1.24.0

toolchain go1.24.2

replace github.com/Layr-Labs/go-tpm-tools => ../..

require (
	github.com/Layr-Labs/go-tpm-tools v0.4.4
	google.golang.org/protobuf v1.36.11
)

require (
	github.com/google/go-sev-guest v0.14.1 // indirect
	github.com/google/go-tdx-guest v0.3.2-0.20241009005452-097ee70d0843 // indirect
)
