'use strict';

const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const { analyze } = require('../src/analyze');
const { explainWithOllama, validateClaims } = require('../src/ollama');
const { toMarkdown } = require('../src/report');
const { buildPE } = require('./helpers/build-pe');

function fakeOllama(responseText) {
  const requests = [];
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (d) => (body += d));
    req.on('end', () => {
      requests.push({ url: req.url, body: JSON.parse(body) });
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ response: responseText }));
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve({ server, requests, url: `http://127.0.0.1:${server.address().port}` }));
  });
}

const result = () => analyze(buildPE({ imports: { 'wininet.dll': ['InternetOpenA'] } }), 'x.exe');

test('validateClaims keeps only claims with real evidence IDs', () => {
  const ids = new Set(['E1', 'E2']);
  const { claims, dropped } = validateClaims({
    claims: [
      { text: 'ok one', evidence: ['E1'] },
      { text: 'no evidence', evidence: [] },
      { text: 'missing field' },
      { text: 'bad id', evidence: ['E1', 'E99'] },
      { text: 'This is malicious software.', evidence: ['E2'] },
      { text: '', evidence: ['E1'] },
      { text: 'ok two', evidence: ['E2', 'E2'] },
    ],
  }, ids, 10);
  assert.deepStrictEqual(claims.map((c) => c.text), ['ok one', 'ok two']);
  assert.deepStrictEqual(claims.map((c) => c.id), ['C10', 'C11']);
  assert.deepStrictEqual(claims[1].evidence, ['E2']);
  assert.strictEqual(dropped.length, 5);
});

test('validateClaims handles junk responses', () => {
  assert.strictEqual(validateClaims('not json', new Set()).claims.length, 0);
  assert.strictEqual(validateClaims('{"claims":5}', new Set()).claims.length, 0);
  assert.strictEqual(validateClaims(null, new Set()).claims.length, 0);
});

test('adapter talks to an Ollama-style server and filters the reply', async () => {
  const r = result();
  const id = r.evidence.find((e) => e.kind === 'import').id;
  const reply = JSON.stringify({
    claims: [
      { text: 'It may open internet sessions.', evidence: [id] },
      { text: 'It steals passwords.', evidence: [] },
    ],
  });
  const f = await fakeOllama(reply);
  try {
    const out = await explainWithOllama(r, { url: f.url, model: 'test-model' });
    assert.strictEqual(f.requests[0].url, '/api/generate');
    assert.strictEqual(f.requests[0].body.model, 'test-model');
    assert.strictEqual(f.requests[0].body.stream, false);
    assert.match(f.requests[0].body.prompt, /import wininet\.dll!InternetOpenA/);
    assert.strictEqual(out.claims.length, 1);
    assert.strictEqual(out.claims[0].source, 'ollama');
    assert.strictEqual(out.dropped.length, 1);

    r.claims.push(...out.claims);
    const md = toMarkdown(r, { dropped: out.dropped });
    assert.match(md, /It may open internet sessions\. \[model\]/);
    assert.doesNotMatch(md, /steals passwords/);
    assert.match(md, /Dropped model statements/);
  } finally {
    f.server.close();
  }
});

test('adapter rejects on HTTP error', async () => {
  const server = http.createServer((req, res) => { res.statusCode = 500; res.end(); });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    await assert.rejects(
      explainWithOllama(result(), { url: `http://127.0.0.1:${server.address().port}`, model: 'm' }),
      /HTTP 500/,
    );
  } finally {
    server.close();
  }
});

test('validateClaims rejects safe/benign verdicts', () => {
  const ids = new Set(['E1']);
  const raw = { claims: [{ text: 'This looks benign.', evidence: ['E1'] }, { text: 'It is safe to run.', evidence: ['E1'] }] };
  assert.strictEqual(validateClaims(raw, ids).claims.length, 0);
});

test('non-loopback ollama url is refused unless allowed', async () => {
  await assert.rejects(explainWithOllama(result(), { url: 'http://example.com:11434', model: 'm' }), /non-local/);
});
