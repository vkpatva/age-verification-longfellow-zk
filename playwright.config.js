// @ts-check
const { defineConfig, devices } = require('@playwright/test');

module.exports = defineConfig({
  testDir: './verifier/test',
  testMatch: '**/*.spec.mjs',
  timeout: 180_000,
  retries: 0,
  workers: 1,
  reporter: 'line',
  use: {
    headless: true,
    launchOptions: {
      args: ['--no-sandbox', '--disable-setuid-sandbox'],
    },
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
});
