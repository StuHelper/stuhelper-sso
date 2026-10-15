# StuHelper SSO

This public repository owns the Casdoor source, StuHelper authentication extensions,
synthetic regression tests, and signed component artifacts. Production deployment is
owned by `StuHelper/StuHelper`; this repository receives no production credentials.

- Start ordinary feature branches from current `origin/develop`. Keep unrelated work isolated.
- Preserve upstream history. Upstream synchronization PRs use merge commits; never squash
  an upstream integration or overwrite the tree with an archive.
- Pin the latest stable upstream commit in `.stuhelper/upstream.json`. Review the final
  diff **against that upstream tree**. Port only the still-needed StuHelper behaviors;
  use equivalent upstream implementations where available. `web-old/` remains upstream archival source.
- `develop -> main` release PRs use merge commits. No direct push to either long-lived
  branch after the initial repository bootstrap. No force pushes or moving release tags.
- A release is `v<upstream>-stuhelper.<revision>`. The owner has authorized automatic
  stable upstream updates, including major versions, through the tested PR and protected
  `sso-release` pipeline. Ordinary CI only builds/tests. The main consumer must complete
  migration and backup restoration rehearsal before every automatic production upgrade.
- Keep Casdoor the identity/session authority; the target organization user's `IsAdmin`
  remains the only source for StuHelper `super_admin`. Never authorize from arbitrary provider roles.
- Preserve opaque OIDC nonce/state, separate `stuhelper_authz`, server-verified MFA context,
  constrained refresh scope, SAML correlation/replay checks, required account completion,
  boolean-string claim mappings, and audit redaction.
- Use `.stuhelper/toolchains.json`. Go code uses the upstream organization; this is not
  the main application's Handler/Service/Repository implementation.
- Run `python3 .stuhelper/test-go.py`, `go test -tags skipCi ./... -run '^$'`, and in `web/`
  run frozen install, `yarn typecheck`, `yarn lint`, `yarn test`, and `yarn build`.
- Config and credentials come from environment or mounted runtime files. Never add real
  accounts, tokens, private keys, production exports, or personal data to this public source.
- A cross-major database rollback must restore the pre-upgrade backup before starting
  the old binary. Never describe an image-only rollback as database compatibility proof.

See `.stuhelper/UPSTREAM.md` for provenance, behavior mapping, and validation boundaries.
