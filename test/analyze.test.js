'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { analyze } = require('../src/analyze');
const { toMarkdown, toHtml } = require('../src/report');
const { buildPE, W, X, R, CODE } = require('./helpers/build-pe');

const sample = () => buildPE({
  imports: {
    'wininet.dll': ['InternetOpenA', 'InternetReadFile'],
    'kernel32.dll': ['CreateFileA', 'ExitProcess'],
  },
  strings: ['http://example.test/a.bin', 'C:\\Temp\\out.dat', 'plain text here'],
});

test('every claim cites existing evidence', () => {
  const r = analyze(sample(), 'sample.exe');
  const ids = new Set(r.evidence.map((e) => e.id));
  assert.ok(r.claims.length > 5);
  for (const c of r.claims) {
    assert.ok(c.evidence.length > 0, c.text);
    for (const id of c.evidence) assert.ok(ids.has(id), `${c.id} cites ${id}`);
  }
});

test('http capability is inferred with hedged wording', () => {
  const r = analyze(sample(), 'sample.exe');
  const c = r.claims.find((x) => /HTTP/.test(x.text));
  assert.ok(c);
  assert.match(c.text, /may/);
  assert.strictEqual(c.certainty, 'moderate');
  const labels = c.evidence.map((id) => r.evidence.find((e) => e.id === id).label);
  assert.ok(labels.includes('import wininet.dll!InternetOpenA'));
});

test('single-evidence inference is labelled low', () => {
  const r = analyze(buildPE({ imports: { 'kernel32.dll': ['IsDebuggerPresent'] } }));
  const c = r.claims.find((x) => /debugger/.test(x.text));
  assert.strictEqual(c.certainty, 'low');
});

test('string evidence carries file offsets', () => {
  const buf = sample();
  const r = analyze(buf);
  const e = r.evidence.find((x) => x.kind === 'string' && /example\.test/.test(x.label));
  assert.ok(e);
  assert.strictEqual(buf.toString('latin1', e.offset, e.offset + 4), 'http');
});

test('no claim calls the file malicious', () => {
  const r = analyze(buildPE({ imports: { 'kernel32.dll': ['WriteProcessMemory', 'CreateRemoteThread', 'VirtualAllocEx'] } }));
  const all = r.claims.map((c) => c.text).join(' ');
  assert.doesNotMatch(all, /malware|malicious|virus|trojan/i);
  assert.match(all, /legitimately/);
});

test('flags high entropy and writable+executable sections', () => {
  let seed = 7;
  const noise = Buffer.alloc(0x400);
  for (let i = 0; i < noise.length; i++) noise[i] = (seed = (seed * 1103515245 + 12345) & 0x7fffffff) >> 16 & 0xff;
  const r = analyze(buildPE({ extraSections: [{ name: 'packed', data: noise, flags: CODE | R | W | X }] }));
  assert.ok(r.claims.some((c) => /high entropy/.test(c.text) && /packed/.test(c.text)));
  assert.ok(r.claims.some((c) => /writable and executable/.test(c.text)));
  assert.ok(r.unknowns.some((u) => /packed/.test(u)));
});

test('unknowns are always listed', () => {
  const r = analyze(sample());
  assert.ok(r.unknowns.some((u) => /executed/.test(u)));
});

test('hostile names are sanitized and HTML is escaped', () => {
  const r = analyze(buildPE({ extraSections: [{ name: '<b>x', data: Buffer.alloc(16), flags: R }] }), '<script>.exe');
  const html = toHtml(r);
  assert.ok(!html.includes('<script>'));
  assert.ok(!/<b>x/.test(html));
});

test('markdown and html reports contain claims, evidence and unknowns', () => {
  const r = analyze(sample(), 'sample.exe');
  const md = toMarkdown(r);
  assert.match(md, /^C1\. /m);
  assert.match(md, /## Unknowns/);
  assert.match(md, /- E\d+ \(import\)/);
  const html = toHtml(r);
  assert.match(html, /<a href="#E\d+">/);
  assert.match(html, /<h2>Unknowns<\/h2>/);
});

test('analysis survives a truncated file', () => {
  const buf = sample();
  const r = analyze(buf.subarray(0, 0x250), 'cut.exe');
  assert.ok(r.unknowns.some((u) => /Parser warning/.test(u)));
});
