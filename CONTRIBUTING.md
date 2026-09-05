# Contributing

Thanks for taking the time. This is a security scanning service, so a few of
the rules below are stricter than they would be elsewhere.

## Getting set up

```bash
git clone https://github.com/bryanwahyu/automaton-sec.git
cd automaton-sec
cp config.yaml.example config.yaml   # then fill it in
go test ./...
```

You need Go 1.24+. A database and MinIO are only needed to run the service;
the test suite uses in-memory fakes and needs neither.

For the full stack:

```bash
docker compose up --build -d
docker compose logs -f security-api
```

## Before you open a pull request

```bash
gofmt -l .          # must print nothing
go vet ./...
go test -race ./...
```

CI runs exactly these, plus `govulncheck` and a Docker build. A PR that fails
`gofmt` will fail CI, so run it locally first.

## What a good change looks like

- **One concern per PR.** A bug fix and a refactor in the same diff are hard to
  review and harder to revert.
- **Tests for behaviour, not for coverage.** If you fix a bug, add the test that
  would have caught it. The existing tests in
  `internal/domain/scans/validate_test.go` and
  `internal/application/scans/services_test.go` are a reasonable model.
- **Match the surrounding code.** The layering is hexagonal: `domain` holds
  entities and ports, `application` holds use cases, `infra` holds adapters.
  Domain code must not import infrastructure.
- **Explain the why in the commit message,** not the what. The diff already
  says what changed.

## Adding a scanner

Five places, in this order:

1. `internal/domain/scans/entity.go` — the `Tool` constant, `KnownTools`, and
   `ScansFilesystem` if it reads a path.
2. `internal/domain/scans/analyst.go` — a parser producing `SeverityCounts`,
   with a test using a fixture of real output.
3. `internal/infra/executor/docker/runner.go` — the command, and an entry in
   `findingsExitCode` if the tool exits non-zero merely to report findings.
4. `Dockerfile` — install it in the fetch stage, pinned to a version build arg.
5. `README.md` — the tool table, an example, and the version list.

Never pass a request value into a command line without routing it through
`TargetPolicy` first.

## Security

Do not open a public issue for a vulnerability in this project. See
[SECURITY.md](SECURITY.md).

Scan targets come from untrusted request bodies and end up as arguments to
external binaries. Any change touching `internal/domain/scans/validate.go`,
`internal/infra/executor/docker/runner.go`, or the auth middleware will be
reviewed with that in mind — expect questions.

## Licence

By contributing you agree that your contributions are licensed under the MIT
Licence, the same terms that cover the rest of the project.
