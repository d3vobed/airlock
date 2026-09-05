'use strict';

// Policy-violation variant (1.0.1): enables the network probe to demonstrate
// AIRLOCK's network denial during real npm install.
const { runCanary } = require('./canary');
runCanary(true);