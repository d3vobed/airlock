// Synthetic malicious package for the AIRLOCK demo.
//
// WARNING: This is NOT real malware. It is a safe, self-contained demonstration
// that ATTEMPTS restricted actions and records whether the sandbox blocked
// them. Everything it does is confined to reading environment metadata and
// attempting local socket connections to a non-existent host. Nothing is
// exfiltrated, no damage is done, and no real third-party system is touched.
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

function report(kind, blocked) {
  console.log(`[demo-malicious] ${kind}: ${blocked ? 'BLOCKED' : 'NOT BLOCKED'}`);
}

try {
  // ATTEMPT 1: read environment variables / secrets
  const envKeys = Object.keys(process.env);
  const secretish = envKeys.filter(k => /(TOKEN|SECRET|KEY|PASSWORD|MONO|DOJAH|PAYMENT)/i.test(k));
  report('env_access', secretish.length === 0);
  // No secret values are ever printed — only whether any look secret-like.
} catch (e) {
  report('env_access', true);
}

try {
  // ATTEMPT 2: look for ~/.ssh
  const sshPath = path.join(os.homedir(), '.ssh');
  fs.accessSync(sshPath);
  report('ssh_access', false);
} catch (e) {
  report('ssh_access', true);
}

try {
  // ATTEMPT 3: outbound network
  const net = require('net');
  const sock = new net.Socket();
  sock.setTimeout(1200);
  sock.on('connect', () => { report('network', false); sock.destroy(); });
  sock.on('error', () => { sock.destroy(); });
  sock.on('timeout', () => { sock.destroy(); });
  sock.connect(4500, '10.255.255.1');
  setTimeout(() => { }, 500);
} catch (e) {
  report('network', true);
}

try {
  // ATTEMPT 4: write outside the workspace
  fs.writeFileSync('/tmp/airlock-escape-test', 'demo');
  report('filesystem', false);
} catch (e) {
  report('filesystem', true);
}

console.log('[demo-malicious] demostration attempts complete');