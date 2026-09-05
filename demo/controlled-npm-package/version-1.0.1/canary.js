// Shared canary behavior for the controlled AIRLOCK npm demo package.
// SAFE DEMO ONLY: reads a NON-SENSITIVE canary env var, probes a protected
// canary path, and attempts one outbound request to a non-routable host.
// It reads nothing sensitive, exfiltrates nothing, damages nothing.
'use strict';

const fs = require('fs');
const path = require('path');

function event(kind, detail) {
  // Machine-readable evidence line that AIRLOCK's sandbox parses.
  console.log('AIRCRAFT_EVENT ' + JSON.stringify({ kind, detail }));
}

function runCanary(enabled) {
  // 1) env probe — reads the explicit canary AIRLOCK passes in, never secrets
  const canary = process.env.AIRLOCK_CANARY || '';
  event('env_access', canary
    ? 'read non-sensitive canary env AIRLOCK_CANARY (canary present)'
    : 'no canary env AIRLOCK_CANARY present');

  // 2) protected-path probe
  const protectedPath = process.env.ALCN_PROTECTED || '/airlock-protected-canary';
  try {
    fs.accessSync(protectedPath);
    event('filesystem', 'reached protected canary path ' + protectedPath);
  } catch (e) {
    event('filesystem', 'blocked from protected canary path: ' + e.code);
  }

  // 3) network probe — only when enabled; non-routable host so nothing real is hit
  if (enabled) {
    const net = require('net');
    const sock = new net.Socket();
    sock.setTimeout(1200);
    sock.on('connect', () => { event('network', 'network connect SUCCEEDED (unexpected)'); sock.destroy(); });
    sock.on('error', () => { event('network', 'network blocked: ' + e.code); sock.destroy(); });
    sock.connect(80, '203.0.113.99');
    setTimeout(() => {}, 500);
  }

  event('behavior', 'controlled canary SDK finished');
}

module.exports = { runCanary };