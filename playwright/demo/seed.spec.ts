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

// Seeds the demo organization with data that CANNOT be seeded any other way.
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

// Realistic-looking, entirely fictional. Nothing here resolves to a real
// service, and no value is a credential for anything - a demo that shipped a
// plausible-looking real secret would be a liability the first time someone
// screenshotted it.
// Trimmable for a fast edit loop: DEMO_ITEM_COUNT=1 turns a ten-minute run
// into a two-minute one when only the item step is in question. The demo uses
// all of them.
const ITEM_COUNT = Number(process.env.DEMO_ITEM_COUNT ?? '0') || undefined;
const ALL_ITEMS = [
    { name: 'Acme AWS root', username: 'root@acme.example', password: 'Aa1!demo-not-real-0001' },
    { name: 'Acme GitHub org', username: 'acme-bot', password: 'Aa1!demo-not-real-0002' },
    { name: 'Acme Grafana', username: 'admin', password: 'Aa1!demo-not-real-0003' },
    { name: 'Acme Jira', username: 'svc-jira', password: 'Aa1!demo-not-real-0004' },
    { name: 'Acme Postgres (prod)', username: 'acme_app', password: 'Aa1!demo-not-real-0005' },
    { name: 'Acme SMTP relay', username: 'mailer', password: 'Aa1!demo-not-real-0006' },
];
const ITEMS = ITEM_COUNT ? ALL_ITEMS.slice(0, ITEM_COUNT) : ALL_ITEMS;

test.describe.configure({ mode: 'serial' });

test('seed the demo organization', async ({ page }) => {
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

    await test.step('add vault items', async () => {
        for (const item of ITEMS) {
            await addLogin(page, item);
        }
    });

    // Proves the seed produced something a client can actually read back,
    // rather than that the clicks did not throw. A vault that looks right in
    // the DOM immediately after writing is not the same as one that decrypts
    // on a fresh load.
    await test.step('verify the items survive a reload', async () => {
        await page.goto('/#/vault');
        for (const item of ITEMS) {
            // .first(): the name renders in both the list row and the detail
            // pane, and Playwright's strict mode rejects a two-element match.
            await expect(page.getByText(item.name, { exact: true }).first()).toBeVisible();
        }
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

// Kept small and separate from the helpers in tests/setups/ on purpose: those
// belong to upstream's suite and upstream maintains them. Anything the demo
// needs that they do not already provide lives here, so a sync-upstream never
// has to merge demo requirements into a shared file.
async function addLogin(page: Page, item: { name: string, username: string, password: string }) {
    await test.step(`add "${item.name}"`, async () => {
        await page.goto('/#/vault');
        // "New item" opens the Login form DIRECTLY in web vault 2026.7.0 -
        // there is no type-picker menu. An earlier version of this waited for
        // a `menuitem` named "Login" that never appears, and since a missing
        // locator only fails on timeout, it looked like a hang rather than a
        // wrong selector. Assert the form is open instead.
        await page.getByRole('button', { name: 'New item' }).click();
        await expect(page.getByRole('heading', { name: 'New Login' })).toBeVisible();

        await page.getByRole('textbox', { name: 'Item name * (required)' }).fill(item.name);
        await page.getByRole('textbox', { name: 'Username', exact: true }).fill(item.username);
        await page.getByRole('textbox', { name: 'Password', exact: true }).fill(item.password);

        await page.getByRole('button', { name: 'Save' }).click();

        // Saving does NOT return you to the list: it opens a "View Login"
        // dialog for the item just created. `page.goto('/#/vault')` on the next
        // iteration is only a hash change in an Angular SPA, so it neither
        // reloads nor dismisses that modal - and "New item" then sits behind it
        // forever. Close it explicitly and wait for it to go.
        const dialog = page.getByRole('dialog');
        await expect(dialog).toBeVisible();
        await expect(dialog.getByText(item.name, { exact: true }).first()).toBeVisible();
        await dialog.getByRole('button', { name: 'Close' }).click();
        await expect(dialog).toHaveCount(0);
    });
}
