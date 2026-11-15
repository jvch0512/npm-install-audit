'use strict';
const fs = require('fs');
const path = require('path');

const RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const DEP_SECTIONS = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];
const LIFECYCLE = ['preinstall', 'install', 'postinstall', 'prepare'];
const LOCKFILES = ['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb', 'bun.lock'];

const RE_DANGEROUS = [
  /(curl|wget)[^|;&]*\|\s*(sudo\s+)?(ba|z|da)?sh\b/i,
  /\bnode\s+(-e|--eval|-p|--print)\b/,
  /\beval\b/,
  /\bbase64\s+(-d|--decode)\b/i,
  /\bpowershell(\.exe)?\b/i,
  /\bIEX\b|Invoke-Expression|Invoke-WebRequest/i,
  /\/dev\/tcp\//,
  /\bnc\s+(-[a-z]*e|.*\s-e\s)/i,
  /\b(bash|sh)\s+<\(\s*(curl|wget)/i,
];
const RE_PRIV = /\bsudo\b|--unsafe-perm\b/;

function finding(sev, rule, file, where, msg) {
  return { sev, rule, file, where: where ? `${file}#${where}` : file, msg };
}

function isObj(x) {
  return x !== null && typeof x === 'object' && !Array.isArray(x);
}

function classifySpec(v) {
  if (typeof v !== 'string') return 'other';
  const s = v.trim();
  if (s === '' || /^(\*|x|latest|>=?\s*0(\.0\.0)?)$/i.test(s)) return 'wildcard';
  if (/^http:\/\//i.test(s)) return 'http';
  if (/^(git\+|git:|git@|github:|gitlab:|bitbucket:|gist:|https:|ssh:)/i.test(s)) return 'git';
  if (/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(#.*)?$/.test(s)) return 'git';
  if (/^(file:|link:)/i.test(s)) return 'local';
  return 'registry';
}

function hasLockNext(dir) {
  for (const n of LOCKFILES) {
    try { if (fs.existsSync(path.join(dir, n))) return true; } catch (e) { /* ignore */ }
  }
  return false;
}

function auditManifest(doc, label, opts) {
  const out = [];
  const scripts = isObj(doc.scripts) ? doc.scripts : {};
  for (const name of LIFECYCLE) {
    const cmd = scripts[name];
    if (typeof cmd !== 'string') continue;
    out.push(finding(name === 'prepare' ? 'low' : 'medium', 'NPM002', label, `scripts.${name}`,
      `${name} runs on install: ${trunc(cmd)}`));
    if (RE_DANGEROUS.some((re) => re.test(cmd))) {
      out.push(finding('high', 'NPM001', label, `scripts.${name}`,
        `${name} downloads, evaluates or decodes code at install time: ${trunc(cmd)}`));
    }
    if (RE_PRIV.test(cmd)) {
      out.push(finding('medium', 'NPM007', label, `scripts.${name}`,
        `${name} uses sudo or --unsafe-perm: ${trunc(cmd)}`));
    }
  }
  let depCount = 0;
  for (const sec of DEP_SECTIONS) {
    const deps = doc[sec];
    if (!isObj(deps)) continue;
    for (const name of Object.keys(deps).sort()) {
      depCount++;
      const kind = classifySpec(deps[name]);
      const where = `${sec}.${name}`;
      if (kind === 'git') {
        out.push(finding('high', 'NPM003', label, where, `${name} comes from ${trunc(String(deps[name]))}, not the registry: the code can change without a version bump`));
      } else if (kind === 'http') {
        out.push(finding('high', 'NPM003', label, where, `${name} is fetched over plain HTTP from ${trunc(String(deps[name]))}`));
      } else if (kind === 'wildcard') {
        out.push(finding('medium', 'NPM004', label, where, `${name} accepts any version ("${String(deps[name])}")`));
      } else if (kind === 'local') {
        out.push(finding('low', 'NPM005', label, where, `${name} is a local path (${trunc(String(deps[name]))})`));
      }
    }
  }
  if (depCount > 0 && opts && opts.dir && !hasLockNext(opts.dir)) {
    out.push(finding('low', 'NPM008', label, '', 'no lockfile next to this manifest: installs can resolve to different versions each time'));
  }
  return out;
}

function auditLock(doc, label) {
  const out = [];
  const seen = new Set();
  function entry(name, e) {
    if (!isObj(e) || e.link === true) return;
    if (typeof e.resolved === 'string') {
      if (/^(git\+)?http:\/\//i.test(e.resolved)) {
        out.push(finding('high', 'NPM006', label, name, `resolved over plain HTTP: ${trunc(e.resolved)}`));
      }
      if (typeof e.integrity !== 'string' && !/^git/i.test(e.resolved)) {
        out.push(finding('low', 'NPM009', label, name, 'no integrity hash for the resolved tarball'));
      }
    }
  }
  if (isObj(doc.packages)) {
    for (const k of Object.keys(doc.packages).sort()) {
      if (k === '') continue;
      entry(k, doc.packages[k]);
      seen.add(k);
    }
  }
  function walk(deps, prefix, depth) {
    if (!isObj(deps) || depth > 50) return;
    for (const k of Object.keys(deps).sort()) {
      const e = deps[k];
      const name = `${prefix}${k}`;
      if (!seen.has('node_modules/' + name)) entry(name, e);
      if (isObj(e) && isObj(e.dependencies)) walk(e.dependencies, name + '>', depth + 1);
    }
  }
  if (!isObj(doc.packages)) walk(doc.dependencies, '', 0);
  return out;
}

function trunc(s) {
  const t = s.replace(/\s+/g, ' ').trim();
  return t.length > 80 ? t.slice(0, 77) + '...' : t;
}

function audit(text, label, opts) {
  opts = opts || {};
  let doc;
  try {
    doc = JSON.parse(text);
  } catch (e) {
    return [finding('info', 'NPM000', label, '', 'not valid JSON, ignored')];
  }
  if (!isObj(doc)) return [finding('info', 'NPM000', label, '', 'not a JSON object, ignored')];
  const base = path.basename(label);
  const kind = opts.kind || (base === 'package.json' ? 'manifest' : 'lock');
  return kind === 'manifest' ? auditManifest(doc, label, opts) : auditLock(doc, label);
}

function sortFindings(list) {
  return list.slice().sort((a, b) => {
    if (RANK[a.sev] !== RANK[b.sev]) return RANK[a.sev] - RANK[b.sev];
    if (a.file !== b.file) return a.file < b.file ? -1 : 1;
    if (a.rule !== b.rule) return a.rule < b.rule ? -1 : 1;
    return a.where < b.where ? -1 : a.where > b.where ? 1 : 0;
  });
}

function walkDir(dir, base, acc, depth) {
  if (depth > 30) return;
  let names;
  try { names = fs.readdirSync(dir).sort(); } catch (e) { return; }
  for (const n of names) {
    if (n === 'node_modules' || n === '.git') continue;
    const full = path.join(dir, n);
    let st;
    try { st = fs.lstatSync(full); } catch (e) { continue; }
    if (st.isSymbolicLink()) continue;
    if (st.isDirectory()) walkDir(full, base, acc, depth + 1);
    else if (['package.json', 'package-lock.json', 'npm-shrinkwrap.json'].includes(n)) {
      acc.push({ full, label: path.relative(base, full).split(path.sep).join('/') });
    }
  }
}

function auditPath(p) {
  const files = [];
  const st = fs.statSync(p);
  if (st.isDirectory()) walkDir(p, p, files, 0);
  else files.push({ full: p, label: path.basename(p) });
  let all = [];
  for (const f of files) {
    let text;
    try {
      if (fs.statSync(f.full).size > 20e6) continue;
      text = fs.readFileSync(f.full, 'utf8');
    } catch (e) { continue; }
    all = all.concat(audit(text, f.label, { dir: path.dirname(f.full) }));
  }
  return { files: files.length, findings: sortFindings(all) };
}

module.exports = { audit, auditPath, classifySpec, sortFindings, RANK };
