# SCIM v2 provisioning

A SCIM v2 provisioning server (RFC 7643 / RFC 7644) for this Vaultwarden fork,
so organization membership can be driven from an identity provider.

Standard SCIM 2.0, so any compliant provisioning engine works. **Microsoft Entra
ID**, **Okta**, **AWS IAM Identity Center** and **Google Workspace** each have
their documented request cycle covered end to end by the test suite - see
[providers.md](providers.md), including the honest limits of what "covered"
means without a live tenant.

> [!WARNING]
> **No identity provider has been validated against a live tenant yet. Do not
> roll this out to production without testing it yourself first.**
>
> Entra ID, Okta, AWS IAM Identity Center and Google Workspace are covered by
> tests written from each vendor's *published documentation*, not from observed
> traffic. Authentik is the one exception, verified end to end, but it is not one
> of the major cloud providers. Run the full lifecycle against a **throwaway**
> tenant and a test organisation before any rollout - never against production.
> See [providers.md](providers.md) for what is verified per provider, and
> [testing.md](testing.md) for the free rungs that get you most of the way.

## What it does, honestly

It automates **invite**, **update**, **group sync**, and **deprovision**. It does
**not** automate the final *confirm* step, and it cannot.

Confirming a member means wrapping the organization's symmetric key under that
member's public key. Under end-to-end encryption only a client holding the
organization key can do that, so no server-side code path can produce it. This
is a property of the encryption model, not a gap in the implementation, and it
applies equally to upstream's own `ldap_import`.

So the honest description is **automated invite plus automated deprovision, with
confirmation gated on key availability**. Deprovision is the highest-value half:
it is immediate, needs no crypto, and is the thing manual offboarding usually
gets wrong.

Full reasoning, with diagrams: **[design.md](design.md)**.

---

## Documentation map

Start at the top and work down; each assumes the one before.

| Guide | What it covers | Read it when |
|---|---|---|
| **[deployment.md](deployment.md)** | Cloud-agnostic containers, PostgreSQL, secrets, SSO, and the break-glass Owner | Building the environment |
| **[setup.md](setup.md)** | Server config, minting the org token, the Entra enterprise application, choosing which users and groups sync | Standing it up for the first time |
| **[providers.md](providers.md)** | Entra ID, Okta, AWS IAM Identity Center and Google Workspace: what each sends, what "supported" is verified to mean, and why only one provider can be tested in CI | Using anything other than Entra |
| **[client-rollout.md](client-rollout.md)** | Pointing staff Bitwarden apps at your server, zero-touch via browser policy and MDM, manual fallback | Getting users onto it |
| **[operations.md](operations.md)** | The member lifecycle and the troubleshooting table | Running it day to day |
| **[reference.md](reference.md)** | Deliberate behaviours, deviations, and named RFC divergences | Something looks wrong but may be by design |
| **[upgrading.md](upgrading.md)** | Whether an upgrade needs downtime, how to tell, and the exact sequence | Before any deploy |
| **[testing.md](testing.md)** | What the suite covers, which feedback loop to use when, the rungs up to a live tenant, and how to add a test | Validating a change |
| **[design.md](design.md)** | Architecture, the E2EE security model, threat model, decision log | Changing the implementation |


---

## The one operational fact to read first

**Deprovision from the IdP, not from the vault.**

Restore is lossless, so a member you revoke in the web vault is silently
re-activated on the next sync if the IdP still shows them active. To offboard
someone, unassign or disable them in Entra.

This catches people out more than anything else in the feature. The full
explanation is in [reference.md](reference.md).

---

## Quick start

0. Stand up the server, PostgreSQL, and the break-glass Owner **before** wiring
   in the identity provider - [deployment.md](deployment.md).
1. Set `SCIM_ENABLED=true` (and `ORG_EVENTS_ENABLED=true` for an audit trail) -
   [setup.md](setup.md#part-a---enable-scim-on-the-server).
2. Mint the organization's token as an **Owner** -
   [setup.md](setup.md#part-b---generate-the-organizations-scim-token).
3. Point the Entra enterprise application at
   `https://<domain>/scim/v2/<org_id>` with that token -
   [setup.md](setup.md#part-c---configure-the-entra-enterprise-application).
4. Scope who syncs, and keep administrators out of scope -
   [setup.md](setup.md#part-d---choose-which-users-and-groups-sync).
5. Roll the server URL out to client apps -
   [client-rollout.md](client-rollout.md).
