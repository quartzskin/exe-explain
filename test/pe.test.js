'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { parsePE, entropy } = require('../src/pe');
const { buildPE } = require('./helpers/build-pe');

test('parses headers of a PE32 file', () => {
  const pe = parsePE(buildPE());
  assert.strictEqual(pe.header.machine, 'i386');
  assert.strictEqual(pe.header.is64, false);
  assert.strictEqual(pe.header.subsystem, 'Windows console');
  assert.strictEqual(pe.header.entryPoint, 0x1000);
  assert.strictEqual(pe.entrySection, '.text');
  assert.deepStrictEqual(pe.sections.map((s) => s.name), ['.text', '.idata']);
  assert.deepStrictEqual(pe.warnings, []);
});

test('parses PE32+ imports including ordinals', () => {
  const pe = parsePE(buildPE({ is64: true, imports: { 'ws2_32.dll': ['socket', 115], 'kernel32.dll': ['ExitProcess'] } }));
  assert.strictEqual(pe.header.machine, 'x64');
  assert.deepStrictEqual(pe.imports, [
    { dll: 'ws2_32.dll', functions: ['socket', '#115'] },
    { dll: 'kernel32.dll', functions: ['ExitProcess'] },
  ]);
});

test('parses exports and DLL flag', () => {
  const pe = parsePE(buildPE({ dll: true, exports: { dll: 'demo.dll', names: ['Alpha', 'Beta'] } }));
  assert.strictEqual(pe.header.isDll, true);
  assert.strictEqual(pe.exports.name, 'demo.dll');
  assert.deepStrictEqual(pe.exports.names, ['Alpha', 'Beta']);
});

test('parses resources', () => {
  const pe = parsePE(buildPE({ resource: { type: 10, payload: Buffer.from('hello') } }));
  assert.strictEqual(pe.resources.length, 1);
  assert.strictEqual(pe.resources[0].typeName, 'RCDATA');
  assert.strictEqual(pe.resources[0].size, 5);
});

test('reports overlay', () => {
  const buf = buildPE({ overlay: Buffer.from('trailing') });
  assert.strictEqual(parsePE(buf).overlay.size, 8);
});

test('entropy of constant and uniform data', () => {
  assert.strictEqual(entropy(Buffer.alloc(100)), 0);
  const all = Buffer.from(Array.from({ length: 256 }, (_, i) => i));
  assert.strictEqual(entropy(all), 8);
});

test('rejects non-PE input', () => {
  assert.throws(() => parsePE(Buffer.from('hello')), /MZ/);
  const noPe = Buffer.alloc(128);
  noPe.write('MZ');
  noPe.writeUInt32LE(0x7fffffff, 0x3c);
  assert.throws(() => parsePE(noPe), /PE signature/);
});

test('every truncation of a valid file either parses or throws cleanly', () => {
  const full = buildPE({
    imports: { 'wininet.dll': ['InternetOpenA'] },
    exports: { names: ['Alpha'] },
    resource: { type: 3, payload: Buffer.alloc(16) },
  });
  for (let n = 0; n < full.length; n += 7) {
    try {
      parsePE(full.subarray(0, n));
    } catch (e) {
      assert.ok(e instanceof Error && !(e instanceof TypeError), `unexpected ${e.constructor.name} at ${n}: ${e.message}`);
    }
  }
});

test('random corruption never crashes the parser', () => {
  const base = buildPE({
    imports: { 'wininet.dll': ['InternetOpenA'], 'kernel32.dll': ['ExitProcess'] },
    exports: { names: ['Alpha'] },
    resource: { type: 3, payload: Buffer.alloc(16) },
  });
  let seed = 12345;
  const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff);
  for (let i = 0; i < 3000; i++) {
    const buf = Buffer.from(base);
    for (let k = 0; k < 6; k++) buf[rnd() % 0x400] = rnd() & 0xff;
    try {
      parsePE(buf);
    } catch (e) {
      assert.ok(!(e instanceof TypeError || e instanceof RangeError), `${e.constructor.name}: ${e.message}`);
    }
  }
});

test('self-referencing import table does not loop forever', () => {
  const buf = buildPE({ imports: { 'a.dll': ['X'] } });
  const pe0 = parsePE(buf);
  assert.ok(pe0.imports.length === 1);
  const idata = pe0.sections.find((s) => s.name === '.idata');
  buf.fill(0x41, idata.rawOffset + 40, idata.rawOffset + 200);
  const pe = parsePE(buf);
  assert.ok(pe.imports.length <= 512);
});
