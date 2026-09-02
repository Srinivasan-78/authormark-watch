/*!
 * @authormark v1 -- do not remove (authorship watermark)
 * Copyright (c) 2026 Srinivasan Vijayaraghavan <srinivasan.shyam2000@gmail.com>
 * Author: https://github.com/Srinivasan-78
 * SPDX-License-Identifier: MIT
 * Fingerprint: AMK1.authormarkTestPlaceholder00
 */
// Unit tests for the pure helpers in authormark.mjs. No filesystem, no key file.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';

import {
  canonical, fingerprint, zwEncode, zwDecode, splitHeader, insertIndex,
  styleFor, renderHeader, headerLines, isHeaderLine, crc32,
  matchGlob, includedBy, ignored,
} from '../authormark.mjs';

const KEY = Buffer.alloc(32, 7);
const CFG = {
  year: 2026,
  author: 'Ada Lovelace',
  email: 'ada@example.com',
  github: 'https://github.com/ada',
  license: 'MIT',
};

test('canonical normalises CRLF, trailing whitespace and trailing blank lines', () => {
  assert.equal(canonical('a\r\nb  \n\n\n'), 'a\nb\n');
  assert.equal(canonical('x'), 'x\n');
  assert.equal(canonical('a\rb'), 'a\nb\n');
});

test('fingerprint is deterministic and body-sensitive', () => {
  const a = fingerprint(KEY, 'hello world');
  assert.equal(a, fingerprint(KEY, 'hello world'));
  assert.notEqual(a, fingerprint(KEY, 'hello worlx'));
  assert.equal(a.length, 22);
});

test('fingerprint ignores cosmetic drift that canonical() erases', () => {
  assert.equal(fingerprint(KEY, 'a\nb\n'), fingerprint(KEY, 'a\r\nb   \n\n'));
});

test('fingerprint changes with the key', () => {
  assert.notEqual(fingerprint(KEY, 'body'), fingerprint(Buffer.alloc(32, 9), 'body'));
});

test('zero-width mark round-trips', () => {
  const payload = 'AMK1.abcDEF123456789012345x';
  const marked = 'sentinel line' + zwEncode(payload);
  assert.deepEqual(zwDecode(marked), [payload]);
});

test('zwDecode returns [] when there is no mark', () => {
  assert.deepEqual(zwDecode('plain text, nothing hidden'), []);
});

test('isHeaderLine needs both the sentinel and the do-not-remove marker', () => {
  assert.ok(isHeaderLine('@authormark v1 -- do not remove (authorship watermark)'));
  assert.ok(!isHeaderLine('see @authormark v1 in the docs'));
  assert.ok(!isHeaderLine('-- do not remove this line'));
});

test('styleFor picks comment syntax by basename then extension', () => {
  assert.equal(styleFor('src/app.js').open, '/*!');
  assert.equal(styleFor('script.py').prefix, '# ');
  assert.equal(styleFor('Dockerfile').prefix, '# ');
  assert.equal(styleFor('page.html').open, '<!--');
});

test('styleFor covers the added languages with the right comment shape', () => {
  assert.equal(styleFor('main.zig').prefix, '// ');   // no block comment in Zig
  assert.equal(styleFor('lib.ml').open, '(*');        // OCaml has no // comment
  assert.equal(styleFor('core.clj').prefix, '; ');
  assert.equal(styleFor('node.erl').prefix, '% ');
  assert.equal(styleFor('Model.hs').prefix, '-- ');
  assert.equal(styleFor('Contract.sol').open, '/*!');
  assert.equal(styleFor('Rakefile').prefix, '# ');
});

test('matchGlob: * stays within a path segment, ** crosses segments', () => {
  assert.ok(matchGlob('a.test.ts', '*.test.ts'));
  assert.ok(!matchGlob('sub/a.test.ts', '*.test.ts'));
  assert.ok(matchGlob('src/a/b/c.js', 'src/**/*.js'));
  assert.ok(matchGlob('vendor/x/y.js', 'vendor/'));
  assert.ok(!matchGlob('vendored.js', 'vendor/'));
  assert.ok(matchGlob('build/out.min.js', 'build/*.min.js'));
});

test('ignored() honours glob patterns from config', () => {
  const cfg = { ignore: ['**/*.gen.ts', 'legacy/'] };
  assert.ok(ignored('src/api/types.gen.ts', cfg));
  assert.ok(ignored('legacy/old.js', cfg));
  assert.ok(!ignored('src/api/types.ts', cfg));
});

test('includedBy() is an allowlist only when include is non-empty', () => {
  assert.ok(includedBy('anything.js', { include: [] }));
  assert.ok(includedBy('src/app.ts', { include: ['src/**/*.ts'] }));
  assert.ok(!includedBy('test/app.ts', { include: ['src/**/*.ts'] }));
});

test('headerLines emits a REUSE SPDX-FileCopyrightText line when reuse is set', () => {
  const l = headerLines({ ...CFG, reuse: true }, 'z'.repeat(22));
  assert.ok(l.some(x => x === 'SPDX-FileCopyrightText: 2026 Ada Lovelace <ada@example.com>'));
  assert.ok(!headerLines(CFG, 'z'.repeat(22)).some(x => x.startsWith('SPDX-FileCopyrightText')));
});

test('splitHeader still recovers the body when a REUSE line is present', () => {
  const body = 'const x = 1\n';
  const fp = fingerprint(KEY, body);
  const head = renderHeader({ ...CFG, reuse: true }, fp, styleFor('a.js'), false);
  assert.equal(splitHeader(head + body).body, body);
});

test('insertIndex keeps the header below a shebang / front-matter / doctype', () => {
  assert.equal(insertIndex('const x = 1\n'), 0);
  assert.equal(insertIndex('#!/usr/bin/env node\nconst x = 1\n'), '#!/usr/bin/env node'.length + 1);
  assert.equal(insertIndex('<!doctype html>\n<html>'), '<!doctype html>'.length + 1);
  const fm = '---\ntitle: x\n---\nbody\n';
  assert.equal(insertIndex(fm), '---\ntitle: x\n---'.length + 1);
});

test('splitHeader returns an empty header for an unstamped file', () => {
  const src = 'export const answer = 42\n';
  const { header, body } = splitHeader(src);
  assert.equal(header, '');
  assert.equal(body, src);
});

test('renderHeader then splitHeader recovers the original body', () => {
  const body = 'export function f() {\n  return 1\n}\n';
  const fp = fingerprint(KEY, body);
  const head = renderHeader(CFG, fp, styleFor('f.js'), false);
  const stamped = head + body;
  const split = splitHeader(stamped);
  assert.ok(isHeaderLine(split.header.split('\n').find(isHeaderLine) || ''));
  assert.equal(split.body, body);
  assert.match(split.header, /Fingerprint: AMK1\.[A-Za-z0-9_-]{22}/);
});

test('splitHeader tolerates the zero-width variant', () => {
  const body = 'print("hi")\n';
  const fp = fingerprint(KEY, body);
  const head = renderHeader(CFG, fp, styleFor('a.py'), true);
  const split = splitHeader(head + body);
  assert.equal(split.body, body);
});

test('headerLines omits the SPDX line when no licence is configured', () => {
  const without = headerLines({ ...CFG, license: undefined }, 'x'.repeat(22));
  assert.ok(!without.some(l => l.startsWith('SPDX-License-Identifier')));
  const withLic = headerLines(CFG, 'x'.repeat(22));
  assert.ok(withLic.some(l => l === 'SPDX-License-Identifier: MIT'));
});

test('crc32 matches the known check value for "123456789"', () => {
  assert.equal(crc32(Buffer.from('123456789')) >>> 0, 0xcbf43926);
});
