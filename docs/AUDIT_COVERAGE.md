# Audit coverage additions

These source changes extend the existing database/syslog audit mechanism. They do not change authorization gates, HA replication guarantees, backup formats or deployment configuration.

## Automatic actions

- **MAC auto-create:** one system event after a genuinely new device commits, with its owning tenant (or explicit Global scope), MAC/device identifier and selected profile/plan identifiers. Existing/ignored duplicate devices and rolled-back creations do not produce creation events.
- **Scheduled backup outcome:** Global system completion/failure event after a claimed run, containing job/type, successful artifact ID/size or a sanitized failure reason. Busy/not-due polling is not audited. Manual successful runs retain their existing administrator audit rather than gaining a duplicate system event.
- **Plan usage cycles:** system events for an actual automatic rollover or missing-baseline initialization, scoped to the affected identity's tenant. Zero-row updates and idle scans do not generate events.

## HA controls

All nine operator commands are audited in Global scope: pause, resume, full sync, log reconciliation, promotion, demotion, local statistics reset, manual sync and RadSec certificate sync. Actor identity comes from the authenticated administrator lookup, never from request-body fields.

HTTP success, denial, failure and interrupted responses are distinguished. A successful **full sync** audit means the operation was **queued**, not that the peer completed it. A reconciliation HTTP 202 records its start; a separate terminal event records completed/partial/failed outcome and allowlisted table counts/run ID. Replicated records, SQL and certificate contents are excluded.

## Additional operator/security actions

- EAP server/CA certificate and private-key exports (Global).
- One-time RadSec client artifact downloads and public tenant/server-trust CA downloads (requesting tenant). Download tokens and query strings are not logged.
- Notification and syslog test actions; a notification test returning HTTP 200 with `ok:false` is not a successful test.
- Own-account theme changes, using the validated account identity and account-wide scope.
- Container restart requests before invoking Docker, so API self-restart can be represented even if the process never reaches its completion callback. Existing completion/failure events remain.
- Downstream destination changes that were saved but could not be activated, explicitly distinguishing persisted configuration from unsuccessful RADIUS activation.

## Existing-event corrections

Existing administrator key/MFA operations, accounting deletion, user TOTP reset/enrollment and self-password events retain their existing action semantics while gaining validated tenant attribution where available. Unverified credentials are not assigned to an inferred tenant. Rejected tenant selection, forbidden Global-context operations and Global-only privilege denials now create explicit denial events without copying the rejected header or full resource URL.

Profile attribute audit metadata does not copy arbitrary attribute values. Auth-log deletion records only bounded known filters, not unrestricted query objects. Restore audit metadata does not copy raw database error/warning values. Full request bodies, API keys, passwords, enrollment/download tokens and private key material are not added to the new operation events.

## Noise and failure policy

Status polling, ordinary list/report reads, internal `/api/sync/*` replication, idle maintenance scans and per-packet activity are not blanket-audited. Existing successful CRUD audits are not duplicated by the explicit operation catalog.

The existing audit writer is best-effort: a database outage or abrupt process/host death can still prevent persistence. Post-response events distinguish an interrupted response from proven success; they are not a transactionally durable command journal. Audit adapter failures must not roll back already committed MAC records, suppress notifications, or turn a successful background operation into a claimed operational failure.
