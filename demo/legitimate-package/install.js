// NaijaPay payment SDK — synthetic legitimate package.
// This is demo code. It does NOT touch any real payment system.
'use strict';

const fs = require('fs');
const path = require('path');

// Normal install-time configuration: write a local config file inside the
// workspace only. No network, no secrets, no access outside the package dir.
const configPath = path.join(process.cwd(), 'naijapay.config.json');
const config = {
  apiBase: 'https://api.naijapay.example/v1',
  mode: 'sandbox',
  installedBy: 'airlock-demo',
};

if (!fs.existsSync(configPath)) {
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
  console.log('[naijapay] wrote local config (inside workspace only)');
}

console.log('[naijapay] payment-sdk@2.1.0 installed cleanly');