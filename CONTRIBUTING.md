# Contributing

Contributions are welcome through GitHub issues and pull requests.

Before opening a pull request, run:

```sh
gofmt -l .            # must print nothing
go vet ./...
go test -race ./...
go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./...
```

`test/e2e/smoke.sh <image>` exercises a built container image end to end
(`CONTAINER_CLI=podman` to use Podman).

Keep changes focused, add regression coverage for behavior changes, and retain
the development-only security model described in the README.
