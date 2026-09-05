'use strict';

// Safe demo wrapper. Reads the canary via AIRLOCK_SANDBOX env presence.
const { runCanary } = require('./canary');

if (process.env.AIRLOCK_SANDBOX === '1') {
  runCanary(false); // benign: no network attempts
} else {
  console.log('canary-sdk installed outside AIRLOCK (no canary run)');
}