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

The OCI image name stays `ghcr.io/stuhelper/casdoor` for existing consumer compatibility.
The publisher identity moves to `StuHelper/stuhelper-sso/.github/workflows/release.yml`
on `main`; the main repository must verify that exact identity and issue a separate
deployment approval. Give the new repository Actions access to that GHCR package
before the first authorized publication. Only the main deployer updates `component-current`.

Public source/CI uses GitHub-hosted runners. GitHub environments and branch/tag
protection are configured separately from the YAML; the release workflow alone is
not evidence that an environment reviewer has been configured.
