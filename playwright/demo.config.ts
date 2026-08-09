import { defineConfig } from '@playwright/test';
import dotenv from 'dotenv';
import dotenvExpand from 'dotenv-expand';

// Deliberately NOT playwright.config.ts, and deliberately not a project inside
// it either.
//
// That config exists to TEST Vaultwarden: its globalSetup starts a Vaultwarden
// in Docker on port 8003 with Keycloak beside it, each project resets a
// database, and teardown destroys everything. Every one of those behaviours is
// wrong for the demo seeder, which must attach to a sandbox that is already
// running and must never reset it - the whole point is that the data survives.
//
// Adding a project to the existing file would also mean the demo shares that
// file's globalSetup, so `npx playwright test` would try to start the test
// stack before seeding the sandbox. Two configs is the smaller lie.
//
// The upstream helpers under tests/setups/ ARE reused, because they drive the
// web vault through its UI and take `page` rather than reaching for any of the
// test harness's own state.
const myEnv = dotenv.config({ path: 'demo.env', quiet: true });
dotenvExpand.expand(myEnv);

export default defineConfig({
    testDir: './demo',
    fullyParallel: false,
    retries: 0,
    workers: 1,
    reporter: [['list']],

    // Generous: this drives a real browser through account creation, key
    // generation and a dozen vault writes. Argon2 alone is deliberately slow.
    timeout: 300 * 1000,
    actionTimeout: 40 * 1000,
    navigationTimeout: 40 * 1000,
    expect: { timeout: 40 * 1000 },

    use: {
        baseURL: process.env.DEMO_DOMAIN ?? 'https://localhost:8000',
        browserName: 'firefox',
        locale: 'en-GB',
        timezoneId: 'Europe/London',
        // The sandbox uses a mkcert certificate. It is trusted by the SYSTEM
        // once `mkcert -install` has run, but Firefox keeps its own trust
        // store and Playwright's bundled Firefox has neither, so this is
        // required regardless of how well the host is set up.
        ignoreHTTPSErrors: true,
        viewport: { width: 1280, height: 800 },
        // Traces and video only on failure: a successful seed is not something
        // anyone watches, and phase 7 records its clips deliberately rather
        // than scavenging them from here.
        trace: 'retain-on-failure',
        video: 'retain-on-failure',
    },
});
