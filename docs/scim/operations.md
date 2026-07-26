# Operations: day-two runbook

What to do once provisioning is live: the lifecycle each member moves through,
and the failures you are most likely to hit.

For behaviour that surprises people but is working as designed, see
**[reference.md](reference.md)**. For upgrades and downtime, see
**[upgrading.md](upgrading.md)**.

## Operational lifecycle

1. Entra assigns user, SCIM creates membership at *Invited*, invite mail sent.
2. User clicks the invite, creates or logs into their account (*Accepted*).
3. An org admin confirms the member in the web vault (*Confirmed*). This is
   the manual step; the admin's client wraps the org key for the member.
4. Entra unassigns or soft deletes, SCIM revokes immediately. Vault access
   stops on the member's next sync.
5. Re-assignment restores the membership exactly as it was, including the
   confirmed state, with no new invite or confirmation needed.

## Reading the SCIM audit trail

Web vault -> the organization -> **Reporting** -> **Event logs**. SCIM-driven
changes appear under the synthetic actor `vaultwarden-scim-...`, which is how you
tell a provisioning change apart from something a human did in the vault.

Events SCIM emits:

| Event | Raised when |
|---|---|
| `OrganizationUserInvited` | A member was provisioned |
| `OrganizationUserUpdated` | `externalId` changed |
| `OrganizationUserRevoked` | Deprovisioned (`active:false` or DELETE) |
| `OrganizationUserRestored` | Reprovisioned (`active:true`) |
| `GroupCreated` / `GroupUpdated` / `GroupDeleted` | Group lifecycle |
| `OrganizationUpdated` | A SCIM token was minted, disabled, or deleted - logged under the **acting Owner**, not the SCIM actor, because it is an interactive re-authenticated action |

**None of this is recorded unless `ORG_EVENTS_ENABLED=true`.** Upstream's
`log_event` returns on its first line otherwise, so on a default deployment every
call above is silently a no-op. The server prints a startup warning when
`SCIM_ENABLED` is set without it. If you are relying on the event log for
compliance evidence, confirm the setting rather than assuming.

## Running more than one instance

Two things change, and neither is obvious from a health check:

- **The rate limiter is per process.** `check_limit_scim` keys on client IP in
  in-memory state with no shared store, so your effective limit is
  `SCIM_RATELIMIT_MAX_BURST` x the number of replicas. Size the value against a
  single replica and accept the multiple, or expect the limiter to be much looser
  than configured.
- **Live sync degrades.** WebSocket notifications are held per process with no
  bus between replicas, so a change written on one replica is not pushed to a
  client connected to another. Clients converge on their next sync. Full detail,
  and the shared-state requirements, in
  [upgrading.md](upgrading.md#step-4-the-multi-instance-rolling-upgrade).

## Pausing provisioning without re-configuring Entra

`PUT /api/organizations/<org_id>/scim/api-key/enabled` with `{"enabled": false}`
plus password/OTP re-auth, as an **Owner**. Every SCIM request then gets the
uniform 401 immediately.

Use this rather than deleting the key when you want provisioning to stop *now*
but expect to resume: deleting destroys the digest, so resuming means minting a
new token and pasting it into Entra. Disabling keeps the digest, so re-enabling
restores the same token and the IdP never needs touching.

Reach for it when a sync is doing something you did not intend, during a
maintenance window, or while investigating. To revoke a credential you believe
has leaked, **rotate** instead - disabling a leaked token still leaves it valid
the moment someone re-enables it.

## Is the credential actually being used?

`GET /api/organizations/<org_id>/scim/status` reports `lastUsedAt`.

- `null` - the key has never authenticated a request. Either it was never
  pasted into Entra, or the IdP cannot reach you.
- A timestamp hours old during a working sync is normal: it is recorded at
  **hour resolution** deliberately, so a full sync does not turn every one of
  thousands of authenticated requests into a database write.
- A timestamp weeks old on a key you believe is live means provisioning has
  silently stopped. Check the Entra provisioning log.

Only successful authentications count, so an attacker guessing against the
endpoint cannot keep the field warm and make a dead key look active.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Entra **Test Connection fails** | Endpoint not reachable over HTTPS, wrong Tenant URL, or wrong/expired Secret Token | Confirm the URL is `https://<domain>/scim/v2/<org_id>` exactly; re-mint the token (B4); check `GET .../scim/status` shows `keyEnabled: true` |
| All requests return **401** | `SCIM_ENABLED` not set, no key configured for the org, token/org mismatch, or a rotated/deleted token | Verify Part A config and restart; check `/scim/status`; the token's embedded org must match the Tenant URL's org id |
| **429** in provisioning logs | Rate limiter tripped, usually because every request is being attributed to one IP | Check **both** halves: the proxy must set `IP_HEADER` (`X-Real-IP`), **and** the proxy's own address must be covered by `IP_HEADER_TRUSTED_PROXIES` or the header is ignored and the peer address is used instead. Then raise `SCIM_RATELIMIT_MAX_BURST` for large initial syncs |
| Users provision but **never get an invite** | SMTP not working, or `userName` mapped to a non-mailbox UPN | Fix SMTP; map `userName` from `mail`. Provisioning still succeeds (201) when the invite mail fails, so the membership exists and an admin can re-send the invite from the web vault; the server log records the failure |
| New users are refused with **400 `invalidValue`** ("Creating new accounts is disabled" / "Email domain is not eligible") | `INVITATIONS_ALLOWED=false`, or the address is outside `SIGNUPS_DOMAINS_WHITELIST` | These are the same two gates the web vault's own invite applies, and SCIM deliberately does not bypass them. Allow the domain, or enable invitations. Members whose account already exists are unaffected |
| Large group assignment returns **400 `invalidValue`** | More than 1000 member values in one request | Let Entra page the membership update, or split the group. The cap exists because every member value costs a database round trip. The keyword is `invalidValue`, not `tooMany`: RFC 7644 section 3.12 defines `tooMany` as a *filter* keyword, and a client branching on it would retry with a narrower filter, which never fixes an oversized body |
| A **policy-blocked restore** retries forever | An org policy (SingleOrg, 2FA-required) refuses the member; the condition never clears on its own | Search the server log for `SCIM restore of member ... is blocked by an organization policy`, which names the member and org. Resolve the policy conflict or unassign the user in Entra |
| Entra reports a user **quarantined / skipped** | `userName` value is not a valid email, or a case/format mismatch on the correlation key | Map to a real lowercased email; matching is case-insensitive on the email but `externalId` must be stable |
| A user **deleted and recreated in Entra** can no longer sign in, and gets no session | SSO binds an account to the IdP's *subject* id, not to the email. A recreated directory entry carries a **new subject**, and the server refuses a second identity for an address that is already bound. Nothing in the SCIM or SSO flow clears it, so the user cannot recover this themselves | Admin panel -> Users -> the affected user -> **Delete SSO Association** (`DELETE /admin/users/<user_id>/sso`), then have them sign in again to bind the new subject. To avoid it: **disable and re-enable** an existing directory entry rather than deleting and recreating it |
| Group sync does nothing / returns **501** | `ORG_GROUPS_ENABLED` is false on the server | Set `ORG_GROUPS_ENABLED=true` and restart, or leave Entra group provisioning disabled |
| A **revoked user reappears** with access | Restore is IdP-authoritative (see below) | Deprovision from Entra, not only in the vault |
| An **Owner/Admin/Manager will not re-activate**, 400 `mutability` | SCIM never reinstates or links an administrative membership | Restore the member in the web vault. Deprovisioning them from Entra still works normally. Better: exclude administrators from the SCIM app assignment |
| **Adding a member to a group fails** with 400 `mutability` ("not managed by SCIM") | The group grants collection access and carries no `externalId` - i.e. an admin created it in the web vault - or it grants access to all collections. SCIM can remove members from such a group but not add them, because group membership confers real plaintext access to the group's collections | Add the member in the web vault, or let the IdP own the group: create it through SCIM (so it carries an `externalId`) and grant that group its collections once in the web vault. Removals and deprovisioning are unaffected |
| A **displayName, externalId or userName is refused** with 400 `invalidValue` ("must be at most N characters") | The value exceeds the narrowest database column it lands in: 100 for a group `displayName`, 300 for `externalId`, 255 for `userName` | Shorten the value in the directory. The cap is enforced in SCIM deliberately, because letting the backend decide gave a 500 on PostgreSQL and silent truncation on MySQL - and Entra retries a 500 forever |
| The org's **only Owner cannot be deprovisioned**, 400 `mutability` | The last active Owner is protected, and if that Owner is still Invited or Accepted, SCIM also cannot restore it afterwards (`reject_privileged_grant`), so Entra will re-send the refused change every cycle | Confirm a second Owner in the web vault, then deprovision the first from Entra. Or remove the member in the web vault and unassign them in Entra. An organization should never have exactly one Owner that the IdP also manages - see the `breakGlassWarning` on `GET .../scim/status` |

---
