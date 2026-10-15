# Casdoor v4 source and StuHelper overlays

The active implementation is official Casdoor **v4.20.0**, commit
`ef7754b1a55e473b9622422bad6a266b7a06b277`, verified as the latest stable release on
2026-10-15. The complete upstream commit is a real Git ancestor. The v4 TypeScript
frontend under `web/` is built; `web-old/` matches upstream and is not shipped.

The old runtime source was reconstructed at v3.156.2 solely to retain the six
reviewed StuHelper source changes as individual commits before the v4 merge.
`.stuhelper/legacy-source.json` records each original/effective patch hash and its
source commit. This proves source extraction; it does not assert old dependency,
binary, database, or production equivalence. Patch files are no longer build inputs.

| Existing customization | v4 disposition and regression coverage |
| --- | --- |
| MFA authentication context | Add verified `amr` / `acr` to v4 JWT options; use upstream `NumericDate` and distinct ID tokens. Preserve proof across refresh/consent. Master verification codes never prove MFA. |
| Account completion | Keep one-time legacy username correction and verified-phone completion before OAuth credentials; port UI to v4 React/TypeScript. |
| Registration policy hints / account switches | Port to v4 signup/user components; partial-column updates preserve backend authorization. |
| SAML correlation | Keep session/provider/RelayState binding and atomic single-use request consumption; retain v4 signed assertion checks and replay storage. Adapt Redis to v4 cluster-capable configuration. |
| Boolean claims | Retain explicit string substitution for IsAdmin/IsForbidden/IsDeleted. |
| OpenPlatform binding | Keep nonce and authorization envelope independent through code, consent, WebAuthn, device and refresh flows. Preserve scope binding, revocation checks and structural audit redaction. |
| Organization update authorization | Retire the redundant legacy helper; test v4's existing request-object resolution directly. |
| OAuth redirect encoding | Retain v4 response-mode handling and issuer parameter. Add a single-completion guard and test byte-preserved state. |

The targeted Go suite uses temporary SQLite databases and generated synthetic
certificates. It also covers all four JWT formats, signatures, separate ID-token
audience, `at_hash`/`c_hash`, MFA assurance, nonce/envelope preservation, and refresh.
Frontend tests execute the actual v4 backend modules with a synthetic fetch runtime.
Typecheck, lint and production build cover the complete v4 frontend.

These tests do not perform production logins, send messages, or query customer data.
A production v3-to-v4 migration still requires an authorized database backup/restore
rehearsal and consumer acceptance against the exact signed image digest. Source CI,
artifact publication, deployment and real-user acceptance remain separate stages.

The independent publisher owns `ghcr.io/stuhelper/stuhelper-sso`. The main
repository verifies its exact signature/provenance/SBOM and copies the unchanged
manifest digest into its existing private `ghcr.io/stuhelper/casdoor` deployment
package before issuing a separate deployment approval. The old private package
is not granted to this public repository, and only the main deployer updates
`component-current`. Existing production image references and historical package
access remain valid while build ownership moves to this repository.

Public source/CI uses GitHub-hosted runners. GitHub environments and branch/tag
protection are configured separately from the YAML; the release workflow alone is
not evidence that an environment reviewer has been configured.

## Automatic stable updates

The owner approved all stable upstream versions, including major releases, on
2026-10-15. `upstream.yml` checks every six hours and resumes when CI/release runs
complete. It uses the repository token with explicit workflow dispatch, so it
needs no cross-repository PAT or paid coding-agent API. Conflicts and failed
compatibility checks produce an idempotent issue and retain the candidate for
manual repair; pushing the repair lets the controller resume.

The controller preserves `.github/`, `.stuhelper/`, `AGENTS.md` and the Node pin
from the trusted branch before committing an upstream merge. It never runs
upstream source with a write token. Required CI passes on the exact PR head;
branch protections also apply to the merge API. Upstream and release PRs use
merge commits, and release ancestry is merged back into develop through a PR.

Release builds and tests run with read-only permissions. A separate protected job
loads the validated OCI archive without running it, signs source provenance and
SBOM, and publishes the immutable version. It never receives production secrets.
The main repository discovers the public release, independently verifies the
exact publisher, approves the digest, and enforces database rehearsal on the
production host before switching the service. Publication alone is not deployment.

## Migration maintenance gate

The main deployment controller owns the private transaction marker
`/conf/stuhelper-maintenance` in the existing configuration directory mount.
A candidate boot with this marker serves only read-only OIDC discovery/JWKS and
returns 503 for every other HTTP path, including direct internal API calls.
Background sync, LDAP, webhook delivery, expiry and cleanup jobs wait until the
controller commits the migration. HTTP admission opens only after their startup
initialization completes. The marker has no HTTP mutation endpoint.

The consumer performs online isolated restoration rehearsal first. It then
freezes the identity writer, verifies a final backup by restoring and booting the
old image, starts the candidate behind the gate, and commits only after runtime
checks. Once the gate is released, database rollback is forbidden because new
identity writes or external background work may have occurred; late ledger errors
require forward reconciliation. Automatic production maintenance starts only in
the owner-approved Beijing 03:00–05:00 window, enforced in the consumer repository.

## Built-in API authorization projection

Casdoor replaces `casbin_api_rule` from `authz.InitApi` on every startup. The
image includes the exact source-derived policy at `/stuhelper/api-policy.json`,
with its SHA-256 in `io.stuhelper.sso.api-policy-sha256`. Migration validates the
old projection before and after old-image boot, validates the new table against
this immutable image file, and validates the restored old projection separately.
User identities, organization roles and administrator-owned permission/model
tables remain exact preservation invariants. Generated row IDs are not policy.

For v3.156.2 → v4.20.0, upstream removes the application-wide wildcard and the
anonymous `run-casbin-command` / `refresh-engines` rules; it adds SAML logout,
POST userinfo and first-admin setup routes. Existing nonempty admin credentials
must remain unchanged and must not enter the first-admin setup state.

The 2026-10-16 manual candidate audit upgraded Coraza to 3.8.1 and x/net to
0.60.0 for the upstream advisories [GHSA-6gcq-wc29-5xf2](https://github.com/corazawaf/coraza/security/advisories/GHSA-6gcq-wc29-5xf2),
[GHSA-6r3q-mjv7-xr8m](https://github.com/corazawaf/coraza/security/advisories/GHSA-6r3q-mjv7-xr8m),
and [GO-2026-6611](https://pkg.go.dev/vuln/GO-2026-6611). The Alpine image pins
available OpenSSL 3.5.9 packages. This does not introduce an automatic CVE release
gate; source contracts, signed provenance, SBOM and migration proof remain the
automatic release and deployment boundaries.
