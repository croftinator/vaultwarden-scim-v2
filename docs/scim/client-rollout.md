# Zero-touch client rollout: pointing staff apps at your server

**Short answer: yes, for managed devices. Fully zero-touch on browser
extensions and MDM-managed mobile, near-zero on desktop, and the web vault
needs nothing at all.**

Covers both the zero-touch fleet rollout and the manual per-app fallback for
unmanaged devices. Assumes the server is already provisioning members - see
[setup.md](setup.md) if not.

---

## The problem being solved

Every Bitwarden client ships pointed at the public `bitwarden.com` cloud. Before
a user can accept a SCIM invite or log in, their app must be pointed at your
server. That setting lives on the **login screen, before authentication** - so
it cannot be pushed by anything that requires the user to already be logged in,
and SCIM cannot do it either. SCIM creates accounts; it has no channel to the
client.

**SSO does not remove this.** Even with `SSO_ONLY=true`, the client has to know
which server to ask about SSO before it can start the flow. The bootstrap
problem is the same.

So the server URL must arrive through the **device management channel**, not
through Bitwarden and not through your IdP.

---

## Decision: what to actually deploy

Ranked by leverage. Do them in this order.

| Client | Zero-touch? | Mechanism | Effort |
|---|---|---|---|
| **Web vault** | Inherent | It *is* your server | None |
| **Browser extension** | **Yes** | Enterprise browser policy → extension managed storage | Low |
| **Mobile (iOS/Android)** | **Yes** | MDM managed app configuration (AppConfig) | Low-medium |
| **Desktop** | Partial | Packaged install + first-run instruction, or seeded config | Medium |
| **CLI** | Yes | `bw config server` in provisioning scripts | Trivial |

**The highest-value single action is the browser extension policy.** It is the
client most staff use daily, and it is genuinely zero-touch on any
Chrome/Edge/Firefox estate you already manage.

**Recommendation: lead with the web vault, ship the extension policy alongside
it, and treat desktop as opt-in.** That gets most users to zero configuration
without waiting on an MDM project.

---

## Important: verify key names before a fleet rollout

Bitwarden's managed-configuration key names and schema **have changed between
releases**. Everything below is given as a concrete starting point, but treat
the exact keys as *unverified against your installed client version* until you
have run the validation in [Step 0](#step-0-validate-on-one-device-first).

This is not hedging for its own sake - a policy that is silently ignored looks
identical to one that has not deployed yet, and you will not find out until a
user reports the app still points at bitwarden.com. Validate on one device.

The durable references are Bitwarden's own help centre, searched for your
platform plus "self-hosted environment" or "deploy" / "managed configuration".

---

## Step 0: validate on one device first

Before touching the fleet, prove the mechanism works on exactly one machine.

1. Enrol a single test device in the relevant policy/MDM group.
2. Push the configuration.
3. **Fully remove and reinstall the Bitwarden client on that device** - managed
   storage is usually read at first run, so an already-configured install can
   mask a broken policy.
4. Open the client and go to the login screen **without logging in**.
5. Confirm the server/region control already shows your self-hosted URL and,
   ideally, is greyed out or non-editable.
6. Log in with a test account and confirm it reaches your server.

If step 5 fails, the key name or schema is wrong. Fix it there, not across 200
devices.

---

## Browser extension (highest value)

The Bitwarden extension reads a **managed storage** object supplied by the
browser's enterprise policy system. You push a small JSON blob keyed by the
extension's ID.

Extension IDs (verify against the store listing you actually deploy):

| Browser | Extension ID |
|---|---|
| Chrome | `nngceckbapebfimnlniiiahkandclblb` |
| Edge | `jbkfoedolllekgbhcbcoahefnbanhhlh` |
| Firefox | `{446900e4-71c2-419f-a6a7-df9c091e268b}` |

The managed-storage payload sets the self-hosted environment. The shape is an
`environment` object carrying the base URL:

```json
{
  "environment": {
    "base": "https://vault.example.com"
  }
}
```

### Chrome / Edge via Windows Group Policy or Intune

Use the browser's **3rdparty extension policy** channel.

- **Registry path (Chrome):**
  `HKLM\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\nngceckbapebfimnlniiiahkandclblb\policy`
- **Registry path (Edge):**
  `HKLM\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\jbkfoedolllekgbhcbcoahefnbanhhlh\policy`

Set a value named `environment` containing the JSON above (as a string, or as
nested values depending on your tooling).

In Intune, deliver this as an **OMA-URI / Administrative Template** setting, or
via a Settings Catalog policy for the browser's third-party extension settings.

Pair it with **force-install** so the extension is present in the first place:

- Chrome: `ExtensionInstallForcelist` → `nngceckbapebfimnlniiiahkandclblb;https://clients2.google.com/service/update2/crx`
- Edge: `ExtensionInstallForcelist` → `jbkfoedolllekgbhcbcoahefnbanhhlh;https://edge.microsoft.com/extensionwebstorebase/v1/crx`

### Chrome / Edge via Jamf or a macOS MDM

Deliver a configuration profile for the browser preference domain
(`com.google.Chrome` / `com.microsoft.Edge`) containing the same
`3rdparty → extensions → <id> → policy` structure, plus
`ExtensionInstallForcelist`.

### Firefox

Firefox uses `policies.json` (or the equivalent Enterprise Policies profile),
placed in the Firefox installation's `distribution/` directory:

```json
{
  "policies": {
    "ExtensionSettings": {
      "{446900e4-71c2-419f-a6a7-df9c091e268b}": {
        "installation_mode": "force_installed",
        "install_url": "https://addons.mozilla.org/firefox/downloads/latest/bitwarden-password-manager/latest.xpi"
      }
    },
    "3rdparty": {
      "Extensions": {
        "{446900e4-71c2-419f-a6a7-df9c091e268b}": {
          "environment": { "base": "https://vault.example.com" }
        }
      }
    }
  }
}
```

---

## Mobile: iOS and Android via MDM

Bitwarden's mobile apps support **managed app configuration**, the standard
mechanism where an MDM hands the app a key/value payload at install time.

**Deploy the app through the MDM, not the public store** - the app must be
managed for AppConfig to apply. In Intune this means adding it as a managed
store app and assigning it; in Jamf, a managed App Store app with an App
Configuration payload; in Android Enterprise, a managed Google Play app with a
managed configuration.

The AppConfig payload sets the self-hosted base URL. Start from:

```xml
<dict>
  <key>baseEnvironmentUrl</key>
  <string>https://vault.example.com</string>
</dict>
```

Android Enterprise exposes the same as a managed configuration field, usually
surfaced in the MDM console as a form once the app is added - which is the
easiest way to discover the current key name without guessing.

**Discovery tip:** in Intune or Jamf, add the Bitwarden app and open its App
Configuration screen. Modern MDMs read the app's published configuration schema
and render the available keys for you. That is authoritative for the version you
are deploying and beats any documentation, including this file.

---

## Desktop

The desktop app has the weakest managed-configuration story of the four. Two
workable approaches:

**A. Packaged install plus a one-line instruction (recommended).** Distribute
via your normal channel (Intune/Winget/MSI, Jamf/Homebrew, or a `.deb`/`.rpm`)
and include the server URL in the install notification and your onboarding doc.
The user sets it once on the login screen.

**B. Seed the configuration file.** The desktop app persists its environment in
a per-user data file. You can pre-place that file during provisioning so the app
opens pre-pointed. This is version-fragile - the file location and schema are
not a supported management interface - so only do it if you are prepared to
re-verify it after client updates.

**Recommendation: use A.** The desktop app is a smaller share of daily use than
the extension, and B's maintenance cost outweighs saving one field of typing.
Spend the effort on the extension and mobile instead.

---

## CLI

Trivial, and worth doing in your standard developer image:

```bash
bw config server https://vault.example.com
```

Or set the equivalent environment variable in a shared shell profile or CI
image so no interactive step is needed at all.

---

## Manual fallback: per-app configuration

For unmanaged or BYO devices, and as the instruction you give anyone the
policy did not reach. The web vault needs nothing; every other client
follows the same pattern.

The web vault needs nothing. For every other client the pattern is the same:
open the environment/server setting on the **login or create-account screen**
(not after logging in), enter your server URL, save, then log in.

- **Web vault (any browser)** - Users simply visit `https://vault.example.com`
  and log in. Nothing to configure; this is served by Vaultwarden itself
  (requires `WEB_VAULT_ENABLED=true`, the default).

- **Browser extension (Chrome, Edge, Firefox, Safari, Opera, Brave)** - On the
  extension's login screen, open the **region / settings** control (a cog or a
  region dropdown near the top), choose **Self-hosted**, enter the **Server URL**
  (`https://vault.example.com`), **Save**, then log in. Leave the other
  per-service URL fields blank - a single base URL is enough for Vaultwarden.

- **Desktop app (Windows, macOS, Linux)** - On the login screen, open the
  **region / settings** control, choose **Self-hosted environment**, set the
  **Server URL**, **Save**, then log in. Same as the extension.

- **Mobile - iOS / iPadOS (App Store)** - On the login screen, tap the **region**
  selector (top of the screen, defaults to *US*/*EU*), choose **Self-hosted**,
  enter the **Server URL**, save, then log in.

- **Mobile - Android (Google Play or F-Droid)** - Same as iOS: tap the **region**
  selector on the login screen, choose **Self-hosted**, enter the **Server URL**,
  save, then log in.

- **CLI (`bw`)** - Point it once, then log in:

  ```bash
  bw config server https://vault.example.com
  bw login you@example.com
  ```

  Scripts and CI can also set `BW_CLIENTURL` / the equivalent env var instead of
  `bw config`.

**Notes that avoid support tickets:**
- Keep clients **reasonably up to date**. Older client versions may not speak to
  a current Vaultwarden; if login fails on an ancient build, update first.
- The server URL is set **once per install per device**. A user with the
  extension, the desktop app, and mobile configures all three separately.
- If a user logged into the public cloud by mistake, they must **log out**,
  change the environment to self-hosted, and log back in - the server can't be
  switched while logged in.

---

## What users still have to do

Zero-touch removes the *server URL* step. It does not remove these, and your
comms should say so plainly:

1. **Log in** with their work email (or via SSO if `SSO_ONLY` is set).
2. **Accept the organization invite** that SCIM triggered.
3. **Set a master password** on first login, if the account is new.

Step 3 is the one that surprises people. Under end-to-end encryption the master
password is what protects the vault key, and no amount of device management can
provision it - see [design.md](design.md) for why the server cannot do this on
their behalf.

There is also a fourth step that is **not** the user's: an administrator must
**confirm** each member in the web vault before they can access shared items.
SCIM deliberately cannot do this. Budget admin time for it in the rollout, and
see the "Verify and confirm members" part of [README.md](README.md).

---

## Suggested rollout sequence

1. **Pilot (week 0).** Two or three admins. Web vault plus one managed extension
   on one device. Prove invite → accept → confirm → unlock end to end, and
   validate the extension policy per [Step 0](#step-0-validate-on-one-device-first).
2. **Web vault to everyone (week 1).** Zero client configuration, so it works
   immediately and unblocks people who just need access. Users can accept their
   SCIM invites here.
3. **Extension policy to the fleet (week 1-2).** Highest-leverage zero-touch
   step. Force-install plus managed environment.
4. **Mobile via MDM (week 2-3).** Once the AppConfig key is confirmed on a test
   device.
5. **Desktop and CLI (ongoing).** Opt-in, documented.
6. **Communicate the deprovision reality to admins.** Offboarding must be driven
   from Entra, not by revoking in the vault - a vault-side revoke is silently
   reversed on the next sync if the IdP still shows the user active. This is in
   [README.md](README.md) under "Behaviour notes and deviations" and it is the
   single most important operational fact for your admins.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| App still shows bitwarden.com after policy push | Policy not applied, wrong extension ID, or app installed before the policy | Reinstall the client on a test device with the policy already in place; re-check the ID |
| Policy applies but the field is editable and empty | Key name or schema wrong for this client version | Read the app's published config schema in your MDM console; re-run Step 0 |
| User logged into the public cloud by mistake | Server cannot be changed while logged in | Log out, set the self-hosted environment, log back in |
| Login fails on an old client build | Client too old for current Vaultwarden | Update the client first |
| User logged in but sees no shared items | Not yet **confirmed** by an admin | Confirm them in the web vault; this is a manual step by design |
| Recreated Entra user cannot sign in | SSO binds to the IdP subject id, not the email | Admin panel → Users → **Delete SSO Association**, then re-login. Prefer disable/re-enable over delete/recreate in Entra |
