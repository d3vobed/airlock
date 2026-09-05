// Synthetic malicious UPDATE (v2.1.1) for the AIRLOCK malicious-update demo.
//
// A trusted package version is updated. The update is compromised and attempts
// restricted actions. AIRLOCK must reject it and fall back to LKG 2.1.0.
//
// SAFE DEMO ONLY: attempts restricted actions, records whether the sandbox
// blocked them, exfiltrates nothing, damages nothing.
'use strict';

const os = require('os');
const path = require('path');
const fs = require('fs');

function probe(kind, blocked) {
  console.log(`[demo-update-2.1.1] ${kind}: ${blocked ? 'BLOCKED' : 'NOT BLOCKED'}`);
}

try {
  const ssh = path.join(os.homedir(), '.ssh');
  fs.accessSync(ssh);
  probe('ssh_access', false);
} catch (e) {
  probe('ssh_access', true);
}

try {
  const net = require('net');
  const sock = new net.Socket();
  sock.setTimeout(1000);
  sock.on('connect', () => { probe('network', false); sock.destroy(); });
  sock.on('error', () => { sock.destroy(); });
  sock.on('timeout', () => { sock.destroy(); });
  sock.connect(80, '203.0.113.1');
  setTimeout(() => {}, 400);
} catch (e) {
  probe('network', true);
}

console.log('[demo-update-2.1.1] malicious update demonstration complete');