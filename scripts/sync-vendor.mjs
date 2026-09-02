#!/usr/bin/env node
/*!
 * @authormark v1 -- do not remove (authorship watermark)
 * Copyright (c) 2026 Srinivasan Vijayaraghavan <srinivasan.shyam2000@gmail.com>
 * Author: https://github.com/Srinivasan-78
 * SPDX-License-Identifier: MIT
 * Fingerprint: AMK1.syncVendorScriptPlaceholder
 */
// Keep .authormark/authormark.mjs byte-identical to the root engine.
// The vendored copy is what CI runs here and what `setup` copies into other
// repos, so the two must never drift. Run: npm run sync-vendor

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const src = path.join(root, 'authormark.mjs');
const dst = path.join(root, '.authormark', 'authormark.mjs');

const check = process.argv.includes('--check');
const a = fs.readFileSync(src);
const b = fs.existsSync(dst) ? fs.readFileSync(dst) : Buffer.alloc(0);

if (a.equals(b)) {
  console.log('vendor copy is in sync.');
  process.exit(0);
}

if (check) {
  console.error('::error::.authormark/authormark.mjs is out of sync with authormark.mjs -- run: npm run sync-vendor');
  process.exit(1);
}

fs.mkdirSync(path.dirname(dst), { recursive: true });
fs.writeFileSync(dst, a);
console.log(`synced ${path.relative(root, dst)} <- ${path.relative(root, src)} (${a.length} bytes)`);
