// Synthetic dependency-confusion impostor.
// Same package name as the internal trusted package, but from a public source
// and a different publisher. AIRLOCK rejects it on source/publisher trust
// before any code is installed.
'use strict';
console.log('[demo-confusion] impostor package — should never be trusted');