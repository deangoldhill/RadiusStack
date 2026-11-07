# RadiusStack 6.1.0

Changes since 6.0.6:

- Settings cards can be expanded and collapsed. Less-used Global and tenant settings start collapsed; frequently used settings start expanded. Global-only and tenant-only sections remain scoped, and the tenant certificate card is now titled **RadSec**.
- Global Settings no longer shows User TOTP or Reply Attribute Catalogue, and Global navigation no longer shows NAS Clients or Downstream RADIUS.
- Global Active Sessions displays sessions across tenants with tenant names, read-only controls, and a visible loading error. Tenant views retain their own scoped sessions and session actions.
- Pushbullet notifications are configured per scope, with optional recipient email, an authorized **Send test message** action, and sanitized diagnostics that distinguish authentication, provider, and transport failures. Global-only events remain Global-only.

This file declares the source version; it is **not** a published GitHub Release. Dean creates the tag and release asset separately. Do not run an asset-based upgrade until tag `6.1.0`, `radiusstack-source.tar.gz`, and its release digest have been published and independently verified. Keep the installation's private `.env`, database, certificates, and Compose overrides; back up data and follow [UPGRADE.md](UPGRADE.md) before upgrading. The declared version is verified on the development host, not as a published-release upgrade rehearsal or live two-member HA failover.
