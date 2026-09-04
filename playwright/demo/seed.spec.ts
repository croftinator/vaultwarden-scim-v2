import { test, expect, type Page } from '@playwright/test';

// NOTE ON REUSING tests/setups/: the plan said lean on upstream's helpers, and
// that turned out to be only half right. They drive the same UI, but they
// assert on TOASTS - `checkNotification(page, 'Your new account has been
// created')` - and a toast is the most volatile thing in a web application. It
// is also the wrong assertion for a seeder: what matters is that the account
// exists and the vault opens, not that a message appeared for four seconds.
//
// So registration and org creation are local, and assert on OUTCOMES. Helpers
// that navigate rather than assert are still worth reusing.
// (no upstream helpers left in use here - see the note above)

// Registers the Owner and creates the organization. NOTHING ELSE.
//
// This file used to seed vault items too, and that was the wrong tool: the same
// six items take minutes here and 18 seconds through the Bitwarden CLI
// (tools/scim-demo-seed-items.sh). Both are real clients doing identical
// crypto, but only one has an interface that survives a web-vault release.
//
// What is left is what the CLI genuinely cannot do - `bw` has no register
// command, and account creation derives a master key in the client, so it
// cannot be faked server-side either.
//
// Seeds data that CANNOT be seeded any other way.
//
// Everything here needs client-side cryptography, which is exactly why it is a
// browser automation rather than a SQL script:
//
//   the Owner account   master key derived from the password, in the client
//   vault items         encrypted under the user's symmetric key
//   the organization    its symmetric key is generated and wrapped client-side
//
// tools/ci-seed-vaultwarden.sh writes an organization row and a SCIM key
// straight into PostgreSQL, and that is the right tool for those two things -
// neither involves a key the server cannot hold. Nothing in this file could be
// done that way. See "The constraint that shapes everything" in
// docs/scim/demo-plan.md.
//
// Idempotency: this is NOT idempotent, and deliberately so. Re-registering an
// existing account fails with a clear error rather than silently continuing
// against half-seeded state. Use `tools/scim-sandbox.sh --purge` for a clean
// slate; a --reset that rewinds to the seeded state is phase 6.

const OWNER = {
    email: process.env.DEMO_OWNER_MAIL!,
    name: process.env.DEMO_OWNER_NAME!,
    password: process.env.DEMO_OWNER_PASSWORD!,
};
const ORG = process.env.DEMO_ORG_NAME!;


test.describe.configure({ mode: 'serial' });

test('register the Owner and create the organization', async ({ page }) => {
    // NOT test.slow(): it TRIPLES the configured timeout, so `--timeout=170000`
    // silently became 510s and every diagnostic run overshot the budget I set
    // for it. The config's own timeout is already generous; set it there where
    // it is visible rather than multiplying it invisibly here.

    await test.step('register the Owner', async () => {
        await registerOwner(page, OWNER);
    });

    await test.step(`create the ${ORG} organization`, async () => {
        await createOrg(page, ORG);
    });


});

async function registerOwner(page: Page, user: { email: string, name: string, password: string }) {
    await page.context().clearCookies();
    await page.goto('/', { waitUntil: 'domcontentloaded' });

    await page.getByRole('link', { name: 'Create account' }).click();
    await page.getByLabel(/Email address/).fill(user.email);
    await page.getByLabel('Name').fill(user.name);
    await page.getByRole('button', { name: 'Continue' }).click();

    await expect(page.getByRole('heading', { name: 'Set a strong password' })).toBeVisible();
    await page.getByRole('textbox', { name: 'Master password * (required)', exact: true }).fill(user.password);
    await page.getByRole('textbox', { name: 'Confirm master password * (' }).fill(user.password);

    // Uncheck "Check known data breaches for this password".
    //
    // This is not cosmetic. It is a live request to a third-party breach API,
    // and it is checked by default, so the whole demo silently acquires a
    // dependency on outbound internet at the single least convenient moment -
    // registration. On a machine that cannot reach it, submission simply does
    // not proceed and the form sits there fully filled, which is exactly what
    // it looked like when this first failed. A local sandbox must work offline.
    const breachCheck = page.getByRole('checkbox', { name: /known data breaches/i });
    if (await breachCheck.isChecked()) {
        await breachCheck.uncheck();
    }

    await page.getByRole('button', { name: 'Create account' }).click();

    // Assert on the OUTCOME - the vault is open - not on a toast. Toasts vanish
    // on a timer, so an assertion on one is a race even when the text matches.
    await expect(page.getByTitle('All vaults', { exact: true })).toBeVisible();
}

async function createOrg(page: Page, name: string) {
    const pm = page.locator('a').filter({ hasText: 'Password Manager' });
    if (await pm.count() > 0) {
        await pm.first().click();
    }
    await expect(page.getByTitle('All vaults', { exact: true })).toBeVisible();

    await page.getByRole('link', { name: 'New organisation' }).click();
    await page.getByRole('textbox', { name: 'Organisation name * (required)', exact: true }).fill(name);
    await page.getByRole('button', { name: 'Submit' }).click();

    // Again the outcome: the org appears in the switcher, which is only true
    // once the client has generated its key pair and the server has stored it.
    await expect(page.locator('org-switcher').filter({ hasText: name })).toBeVisible();
}

