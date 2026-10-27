'use strict';

const FILE_ALIGN = 0x200;
const SECT_ALIGN = 0x1000;
const R = 0x40000000;
const W = 0x80000000;
const X = 0x20000000;
const CODE = 0x20;
const IDATA = 0x40;

const align = (n, a) => Math.ceil(n / a) * a;

function importSection(va, imports, is64) {
  const size = is64 ? 8 : 4;
  const dlls = Object.entries(imports);
  const buf = Buffer.alloc(4096);
  let cur = (dlls.length + 1) * 20;
  dlls.forEach(([dll, funcs], i) => {
    const ilt = cur;
    cur += (funcs.length + 1) * size;
    const nameAt = cur;
    buf.write(dll + '\0', nameAt, 'latin1');
    cur += dll.length + 1;
    funcs.forEach((fn, k) => {
      let v;
      if (typeof fn === 'number') {
        v = is64 ? 2n ** 63n + BigInt(fn) : 0x80000000 + fn;
      } else {
        cur += cur % 2;
        buf.write(fn + '\0', cur + 2, 'latin1');
        v = va + cur;
        cur += 2 + fn.length + 1;
      }
      if (is64) buf.writeBigUInt64LE(BigInt(v), ilt + k * 8);
      else buf.writeUInt32LE(v, ilt + k * 4);
    });
    buf.writeUInt32LE(va + ilt, i * 20);
    buf.writeUInt32LE(va + nameAt, i * 20 + 12);
    buf.writeUInt32LE(va + ilt, i * 20 + 16);
  });
  return buf.subarray(0, cur);
}

function exportSection(va, dllName, names) {
  const buf = Buffer.alloc(2048);
  const n = names.length;
  const funcs = 40;
  const namePtrs = funcs + n * 4;
  const ords = namePtrs + n * 4;
  let cur = ords + n * 2;
  const dllAt = cur;
  buf.write(dllName + '\0', cur, 'latin1');
  cur += dllName.length + 1;
  names.forEach((nm, i) => {
    buf.writeUInt32LE(0x1000, funcs + i * 4);
    buf.writeUInt32LE(va + cur, namePtrs + i * 4);
    buf.writeUInt16LE(i, ords + i * 2);
    buf.write(nm + '\0', cur, 'latin1');
    cur += nm.length + 1;
  });
  buf.writeUInt32LE(va + dllAt, 12);
  buf.writeUInt32LE(1, 16);
  buf.writeUInt32LE(n, 20);
  buf.writeUInt32LE(n, 24);
  buf.writeUInt32LE(va + funcs, 28);
  buf.writeUInt32LE(va + namePtrs, 32);
  buf.writeUInt32LE(va + ords, 36);
  return buf.subarray(0, cur);
}

// root -> type -> id -> language -> data entry
function resourceSection(va, type, payload) {
  const buf = Buffer.alloc(16 * 3 + 8 * 3 + 16 + payload.length);
  const dirs = [0, 24, 48];
  dirs.forEach((d, i) => {
    buf.writeUInt16LE(1, d + 14);
    buf.writeUInt32LE(i === 0 ? type : i === 1 ? 1 : 1033, d + 16);
  });
  buf.writeUInt32LE(((0x80000000 | 24) >>> 0), 20);
  buf.writeUInt32LE(((0x80000000 | 48) >>> 0), 44);
  buf.writeUInt32LE(72, 68);
  const dataAt = 72 + 16;
  buf.writeUInt32LE(va + dataAt, 72);
  buf.writeUInt32LE(payload.length, 76);
  payload.copy(buf, dataAt);
  return buf;
}

function buildPE({
  is64 = false,
  dll = false,
  imports = { 'kernel32.dll': ['ExitProcess'] },
  exports = null,
  strings = [],
  resource = null,
  extraSections = [],
  overlay = null,
} = {}) {
  const text = Buffer.alloc(0x100, 0x90);
  const secs = [{ name: '.text', data: text, flags: CODE | X | R }];

  if (strings.length) {
    secs.push({ name: '.rdata', data: Buffer.from(strings.join('\0') + '\0', 'latin1'), flags: IDATA | R });
  }
  const dirs = {};
  const add = (name, build, flags, dirIndex) => {
    const va = SECT_ALIGN * (secs.length + 1);
    const data = build(va);
    if (dirIndex !== undefined) dirs[dirIndex] = [va, data.length];
    secs.push({ name, data, flags });
  };
  if (imports) add('.idata', (va) => importSection(va, imports, is64), IDATA | R | W, 1);
  if (exports) add('.edata', (va) => exportSection(va, exports.dll || 'synthetic.dll', exports.names), IDATA | R, 0);
  if (resource) add('.rsrc', (va) => resourceSection(va, resource.type, resource.payload), IDATA | R, 2);
  for (const s of extraSections) secs.push(s);

  const optSize = is64 ? 240 : 224;
  const hdrEnd = 0x58 + optSize + secs.length * 40;
  if (hdrEnd > FILE_ALIGN) throw new Error('too many sections for the fixed header size');

  let rawCur = FILE_ALIGN;
  const placed = secs.map((s, i) => {
    const rawSize = align(s.data.length, FILE_ALIGN);
    const p = { ...s, va: SECT_ALIGN * (i + 1), rawOffset: rawCur, rawSize };
    rawCur += rawSize;
    return p;
  });

  const out = Buffer.alloc(rawCur + (overlay ? overlay.length : 0));
  out.write('MZ', 0, 'latin1');
  out.writeUInt32LE(0x40, 0x3c);
  out.write('PE\0\0', 0x40, 'latin1');
  const coff = 0x44;
  out.writeUInt16LE(is64 ? 0x8664 : 0x14c, coff);
  out.writeUInt16LE(placed.length, coff + 2);
  out.writeUInt32LE(1700000000, coff + 4);
  out.writeUInt16LE(optSize, coff + 16);
  out.writeUInt16LE(0x0002 | (dll ? 0x2000 : 0) | (is64 ? 0x0020 : 0x0100), coff + 18);

  const opt = 0x58;
  out.writeUInt16LE(is64 ? 0x20b : 0x10b, opt);
  out.writeUInt32LE(0x1000, opt + 16);
  if (is64) out.writeBigUInt64LE(0x140000000n, opt + 24);
  else out.writeUInt32LE(0x400000, opt + 28);
  out.writeUInt32LE(SECT_ALIGN, opt + 32);
  out.writeUInt32LE(FILE_ALIGN, opt + 36);
  out.writeUInt32LE(SECT_ALIGN * (placed.length + 1), opt + 56);
  out.writeUInt32LE(FILE_ALIGN, opt + 60);
  out.writeUInt16LE(3, opt + 68);
  const ddBase = opt + (is64 ? 112 : 96);
  out.writeUInt32LE(16, ddBase - 4);

  for (const [i, [rva, size]] of Object.entries(dirs)) {
    const idx = Number(i);
    const sec = placed.find((p) => p.va === rva);
    out.writeUInt32LE(sec.va, ddBase + idx * 8);
    out.writeUInt32LE(size, ddBase + idx * 8 + 4);
  }

  placed.forEach((p, i) => {
    const o = opt + optSize + i * 40;
    out.write(p.name, o, 'latin1');
    out.writeUInt32LE(p.data.length, o + 8);
    out.writeUInt32LE(p.va, o + 12);
    out.writeUInt32LE(p.rawSize, o + 16);
    out.writeUInt32LE(p.rawOffset, o + 20);
    out.writeUInt32LE(p.flags >>> 0, o + 36);
    p.data.copy(out, p.rawOffset);
  });
  if (overlay) overlay.copy(out, rawCur);
  return out;
}

module.exports = { buildPE, R, W, X, CODE, IDATA };
