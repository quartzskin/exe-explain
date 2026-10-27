'use strict';

const MAX_IMPORT_DLLS = 512;
const MAX_IMPORT_FUNCS = 8192;
const MAX_EXPORTS = 16384;
const MAX_RES_LEAVES = 512;

const MACHINES = {
  0x14c: 'i386',
  0x1c4: 'ARMv7',
  0x8664: 'x64',
  0xaa64: 'ARM64',
  0x200: 'IA-64',
};

const SUBSYSTEMS = {
  1: 'native',
  2: 'Windows GUI',
  3: 'Windows console',
  5: 'OS/2 console',
  7: 'POSIX console',
  9: 'Windows CE GUI',
  10: 'EFI application',
};

const RES_TYPES = {
  1: 'CURSOR', 2: 'BITMAP', 3: 'ICON', 4: 'MENU', 5: 'DIALOG', 6: 'STRING',
  9: 'ACCELERATOR', 10: 'RCDATA', 11: 'MESSAGETABLE', 12: 'GROUP_CURSOR',
  14: 'GROUP_ICON', 16: 'VERSION', 24: 'MANIFEST',
};

class Reader {
  constructor(buf) {
    this.buf = buf;
  }

  check(off, n) {
    if (!Number.isInteger(off) || off < 0 || off + n > this.buf.length) {
      throw new RangeError(`read of ${n} bytes at 0x${off.toString(16)} is outside the file`);
    }
  }

  u8(off) { this.check(off, 1); return this.buf[off]; }
  u16(off) { this.check(off, 2); return this.buf.readUInt16LE(off); }
  u32(off) { this.check(off, 4); return this.buf.readUInt32LE(off); }
  u64(off) { this.check(off, 8); return Number(this.buf.readBigUInt64LE(off)); }

  cstr(off, max = 256) {
    this.check(off, 1);
    const end = Math.min(this.buf.length, off + max);
    let i = off;
    while (i < end && this.buf[i] !== 0) i++;
    return this.buf.toString('latin1', off, i);
  }
}

function entropy(data) {
  if (data.length === 0) return 0;
  const counts = new Array(256).fill(0);
  for (const b of data) counts[b]++;
  let h = 0;
  for (const c of counts) {
    if (c) {
      const p = c / data.length;
      h -= p * Math.log2(p);
    }
  }
  return h;
}

function parsePE(buf) {
  const r = new Reader(buf);
  const warnings = [];
  const warn = (msg) => warnings.push(msg);

  if (buf.length < 64 || r.u16(0) !== 0x5a4d) {
    throw new Error('not a PE file: missing MZ signature');
  }
  const peOff = r.u32(0x3c);
  if (peOff > buf.length - 24 || r.u32(peOff) !== 0x4550) {
    throw new Error('not a PE file: missing PE signature');
  }

  const coff = peOff + 4;
  const machine = r.u16(coff);
  const numSections = r.u16(coff + 2);
  const timestamp = r.u32(coff + 4);
  const optSize = r.u16(coff + 16);
  const characteristics = r.u16(coff + 18);

  const opt = coff + 20;
  const magic = r.u16(opt);
  if (magic !== 0x10b && magic !== 0x20b) {
    throw new Error(`unsupported optional header magic 0x${magic.toString(16)}`);
  }
  const is64 = magic === 0x20b;
  const header = {
    machine: MACHINES[machine] || `0x${machine.toString(16)}`,
    is64,
    isDll: !!(characteristics & 0x2000),
    characteristics,
    timestamp,
    entryPoint: r.u32(opt + 16),
    imageBase: is64 ? r.u64(opt + 24) : r.u32(opt + 28),
    sizeOfImage: r.u32(opt + 56),
    subsystem: SUBSYSTEMS[r.u16(opt + 68)] || `unknown (${r.u16(opt + 68)})`,
    dllCharacteristics: r.u16(opt + 70),
  };

  const ddBase = opt + (is64 ? 112 : 96);
  const ddCount = Math.min(r.u32(ddBase - 4), 16);
  const dir = (i) => {
    if (i >= ddCount || ddBase + i * 8 + 8 > opt + optSize) return { rva: 0, size: 0 };
    return { rva: r.u32(ddBase + i * 8), size: r.u32(ddBase + i * 8 + 4) };
  };

  const sections = [];
  const secTable = opt + optSize;
  for (let i = 0; i < numSections; i++) {
    const o = secTable + i * 40;
    try {
      const s = {
        name: r.buf.toString('latin1', o, o + 8).replace(/\0.*$/, ''),
        virtualSize: r.u32(o + 8),
        virtualAddress: r.u32(o + 12),
        rawSize: r.u32(o + 16),
        rawOffset: r.u32(o + 20),
        flags: r.u32(o + 36),
      };
      const start = Math.min(s.rawOffset, buf.length);
      const end = Math.min(s.rawOffset + s.rawSize, buf.length);
      if (end - start < s.rawSize) warn(`section ${s.name || i} raw data is truncated or outside the file`);
      s.entropy = entropy(buf.subarray(start, end));
      s.executable = !!(s.flags & 0x20000000);
      s.writable = !!(s.flags & 0x80000000);
      s.readable = !!(s.flags & 0x40000000);
      sections.push(s);
    } catch (e) {
      warn(`section header ${i}: ${e.message}`);
      break;
    }
  }

  const rvaToOffset = (rva) => {
    for (const s of sections) {
      const span = Math.max(s.virtualSize, s.rawSize);
      if (rva >= s.virtualAddress && rva < s.virtualAddress + span) {
        const off = s.rawOffset + (rva - s.virtualAddress);
        return off < buf.length ? off : null;
      }
    }
    return null;
  };
  const at = (rva) => {
    const off = rvaToOffset(rva);
    if (off === null) throw new RangeError(`RVA 0x${rva.toString(16)} is not mapped to file data`);
    return off;
  };

  const imports = [];
  try {
    const d = dir(1);
    if (d.rva) {
      let desc = at(d.rva);
      for (let n = 0; n < MAX_IMPORT_DLLS; n++, desc += 20) {
        const oft = r.u32(desc);
        const nameRva = r.u32(desc + 12);
        const ft = r.u32(desc + 16);
        if (!oft && !nameRva && !ft) break;
        const dll = r.cstr(at(nameRva), 128).toLowerCase();
        const entry = { dll, functions: [] };
        imports.push(entry);
        try {
          const size = is64 ? 8 : 4;
          let t = at(oft || ft);
          for (let k = 0; k < MAX_IMPORT_FUNCS; k++, t += size) {
            r.check(t, size);
            const v = is64 ? buf.readBigUInt64LE(t) : BigInt(buf.readUInt32LE(t));
            if (v === 0n) break;
            if (v >> BigInt(size * 8 - 1)) entry.functions.push(`#${Number(v & 0xffffn)}`);
            else entry.functions.push(r.cstr(at(Number(v)) + 2, 256));
          }
        } catch (e) {
          warn(`imports of ${dll}: ${e.message}`);
        }
      }
    }
  } catch (e) {
    warn(`import table: ${e.message}`);
  }

  const exports = { name: null, names: [], count: 0 };
  try {
    const d = dir(0);
    if (d.rva) {
      const e = at(d.rva);
      exports.name = r.cstr(at(r.u32(e + 12)), 128);
      exports.count = r.u32(e + 20);
      const nNames = Math.min(r.u32(e + 24), MAX_EXPORTS);
      const names = at(r.u32(e + 32));
      for (let i = 0; i < nNames; i++) {
        exports.names.push(r.cstr(at(r.u32(names + i * 4)), 256));
      }
    }
  } catch (e) {
    warn(`export table: ${e.message}`);
  }

  const resources = [];
  try {
    const d = dir(2);
    if (d.rva) {
      const base = at(d.rva);
      const seen = new Set();
      const walk = (off, depth, path) => {
        if (depth > 2 || seen.has(off) || resources.length >= MAX_RES_LEAVES) return;
        seen.add(off);
        const count = r.u16(base + off + 12) + r.u16(base + off + 14);
        for (let i = 0; i < count && resources.length < MAX_RES_LEAVES; i++) {
          const eo = base + off + 16 + i * 8;
          const id = r.u32(eo);
          const target = r.u32(eo + 4);
          const key = id & 0x80000000 ? 'named' : id;
          if (target & 0x80000000) {
            walk(target & 0x7fffffff, depth + 1, [...path, key]);
          } else {
            const de = base + target;
            resources.push({
              type: path[0] === undefined ? key : path[0],
              typeName: RES_TYPES[path[0] === undefined ? key : path[0]] || null,
              id: path[1] === undefined ? key : path[1],
              rva: r.u32(de),
              size: r.u32(de + 4),
            });
          }
        }
      };
      walk(0, 0, []);
    }
  } catch (e) {
    warn(`resources: ${e.message}`);
  }

  let entrySection = null;
  for (const s of sections) {
    const span = Math.max(s.virtualSize, s.rawSize);
    if (header.entryPoint >= s.virtualAddress && header.entryPoint < s.virtualAddress + span) {
      entrySection = s.name;
    }
  }

  const lastEnd = sections.reduce((m, s) => Math.max(m, s.rawOffset + s.rawSize), 0);
  const overlay = lastEnd > 0 && lastEnd < buf.length ? { offset: lastEnd, size: buf.length - lastEnd } : null;

  return {
    header, sections, imports, exports, resources, entrySection, overlay, warnings,
    fileEntropy: entropy(buf),
  };
}

module.exports = { parsePE, entropy, Reader };
