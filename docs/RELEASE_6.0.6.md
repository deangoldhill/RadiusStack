# RadiusStack 6.0.6

Changes relative to the published 6.0.5 source archive:

- Added the Android companion application's source, Gradle wrapper, mobile navigation and release contract to the source distribution. This is source code, not a signed Android package; Android app versioning is independent of the server release.
- Added the `origin_node` authentication-log migration and fresh-schema field, stamped new FreeRADIUS authentication events, and displayed Server 1/Server 2 (or Unknown for historical events) in Auth Logs.
- Corrected selected-tenant plan counts, usage-baseline joins, top-usage detail and depleted-user sorting in the Plans API and UI.
- Tightened selected-tenant administrator 2FA enforcement: the selected tenant must match the target, while Global super-administrators retain platform authority.
- Updated the Platform Guide and API catalogue to distinguish Global read-only operational views from selected-tenant writes, explain HA and downstream routing/activation, and document deletion risks, RadSec credential retrieval, user TOTP/usage resets and operational safety.
- Included the current source upgrade script, migration ledger/checks, deployment documentation, tests and production Compose configuration. The release archive contains public `.env.example` defaults as `.env`, not the installation's private `.env`.

The source archive is intended for both new installations and version-checked upgrades. Back up your database and certificates before using `upgrade.sh`; follow `docs/UPGRADE.md` and validate the archive digest before any downtime. HA peers must run compatible code before operational reconciliation. No live HA failover or signed Android build is claimed by this source release.
