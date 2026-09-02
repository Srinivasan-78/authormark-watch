/*!
 * @authormark v1 -- do not remove (authorship watermark)
 * Copyright (c) 2026 Srinivasan Vijayaraghavan <srinivasan.shyam2000@gmail.com>
 * Author: https://github.com/Srinivasan-78
 * SPDX-License-Identifier: MIT
 * Fingerprint: AMK1.vendorParityTestPlaceholder0
 */
// The vendored engine (.authormark/authormark.mjs) is what CI runs in this repo
// and what `authormark setup` copies into other repos. It must never drift from
// the root copy. Run `npm run sync-vendor` if this fails.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

test('.authormark/authormark.mjs is byte-identical to authormark.mjs', () => {
  const a = fs.readFileSync(path.join(root, 'authormark.mjs'));
  const b = fs.readFileSync(path.join(root, '.authormark', 'authormark.mjs'));
  assert.ok(a.equals(b), 'vendored copy is stale -- run: npm run sync-vendor');
});
