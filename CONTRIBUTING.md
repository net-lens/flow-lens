# Contributing to Flow Lens

Thanks for helping improve Flow Lens! This guide covers the basics for proposing changes.

## Getting Started
1. Fork the repo and clone your fork.
2. Install prerequisites: Go 1.23+, clang/llvm, bpftool, Docker (for image builds).
3. Run `make all` to ensure you can build both the eBPF object and the Go binary.

## Workflow
- Create a feature branch from `main`.
- Keep PRs focused; smaller changes are easier to review.
- If you add Go dependencies, run `go mod tidy`.
- For BPF changes, regenerate `bpf/include/vmlinux.h` only when necessary. To rebuild it on a machine that has `/sys/kernel/btf/vmlinux`, run:

  ```bash
  bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/include/vmlinux.h
  ```

  (Requires root or the capabilities needed to read kernel BTF data.)

## Testing & Linting
Before opening a PR:

```
make ebpf        # rebuild eBPF objects if needed
go test ./...    # run unit tests
golangci-lint run ./...   # static analysis + formatting
```

The GitHub Actions workflows (`Unit Tests`, `Go Lint`) enforce the same checks.

## Commit & PR Tips
- Use clear, descriptive commit messages.
- Reference related issues with `Fixes #123` when applicable.
- Include context in the PR description: what changed, why, and how it was tested.

## Release Workflow
Tags following `vX.Y.Z` trigger `.github/workflows/release.yaml`, building multi-arch images and pushing to GHCR. Don’t force-push tags; create new ones for retries (e.g., `v0.0.2`).

## Code Style
- Go code follows `gofmt`.
- Prometheus metrics live in `internal/common.MetricsRegistry`.
- Favor small, composable packages in `internal/`.

## Questions
Open a GitHub issue or start a discussion if you need clarification before investing time in a change.

Happy hacking!
