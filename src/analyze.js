'use strict';

const crypto = require('node:crypto');
const { parsePE } = require('./pe');
const { extractStrings, classify } = require('./strings');
const { IMPORT_RULES, STRING_RULES } = require('./rules');

const HIGH_ENTROPY = 7.0;
const MAX_STRING_EVIDENCE_PER_KIND = 5;

const clean = (s) => String(s).replace(/[^\x20-\x7e]/g, '?');
const hex = (n) => `0x${n.toString(16)}`;

function analyze(buf, name = 'input') {
  const pe = parsePE(buf);
  const evidence = [];
  const ev = (kind, label, offset) => {
    const e = { id: `E${evidence.length + 1}`, kind, label };
    if (offset !== undefined) e.offset = offset;
    evidence.push(e);
    return e.id;
  };

  const claims = [];
  const claim = (text, certainty, ids) => {
    claims.push({ id: `C${claims.length + 1}`, text, certainty, evidence: ids, source: 'rule' });
  };

  const hashes = {
    md5: crypto.createHash('md5').update(buf).digest('hex'),
    sha1: crypto.createHash('sha1').update(buf).digest('hex'),
    sha256: crypto.createHash('sha256').update(buf).digest('hex'),
  };

  const h = pe.header;
  const evFile = ev('file', `${clean(name)}: ${buf.length} bytes, sha256 ${hashes.sha256}, whole-file entropy ${pe.fileEntropy.toFixed(2)}`);
  const evHdr = ev('header', `PE header: machine ${h.machine}, ${h.is64 ? 'PE32+' : 'PE32'}, subsystem ${h.subsystem}, characteristics ${hex(h.characteristics)}`, 0);

  const kind = h.isDll ? 'a DLL' : 'an executable image';
  claim(`The file is ${kind} for ${h.machine} (${h.is64 ? 'PE32+' : 'PE32'}) with subsystem "${h.subsystem}".`, 'observed', [evHdr]);

  const evTs = ev('header', `COFF time/date stamp ${h.timestamp} (${new Date(h.timestamp * 1000).toISOString()})`);
  claim(`The header records a build timestamp of ${new Date(h.timestamp * 1000).toISOString()}; this field is easily set to any value, so it may not reflect the real build time.`, 'observed', [evTs]);

  const secIds = pe.sections.map((s) => ev(
    'section',
    `section ${clean(s.name)}: raw ${s.rawSize} bytes at ${hex(s.rawOffset)}, entropy ${s.entropy.toFixed(2)}, flags ${s.readable ? 'r' : '-'}${s.writable ? 'w' : '-'}${s.executable ? 'x' : '-'}`,
    s.rawOffset,
  ));
  if (pe.sections.length) {
    claim(`The file has ${pe.sections.length} section(s): ${pe.sections.map((s) => clean(s.name) || '(unnamed)').join(', ')}.`, 'observed', secIds);
  }

  pe.sections.forEach((s, i) => {
    if (s.rawSize > 0 && s.entropy >= HIGH_ENTROPY) {
      claim(`Section ${clean(s.name)} has high entropy (${s.entropy.toFixed(2)} of 8), which suggests its contents may be compressed or encrypted; this is also common for embedded images and other compressed data.`, 'low', [secIds[i]]);
    }
    if (s.writable && s.executable) {
      claim(`Section ${clean(s.name)} is both writable and executable, which may indicate code that modifies itself or is unpacked at run time.`, 'low', [secIds[i]]);
    }
  });

  const evEntry = ev('header', `entry point RVA ${hex(h.entryPoint)}${pe.entrySection === null ? ' (not inside any section)' : ` in section ${clean(pe.entrySection)}`}`);
  if (pe.entrySection === null && h.entryPoint !== 0) {
    claim('The entry point does not fall inside any section, which suggests the section table is unusual or the file is damaged.', 'low', [evEntry]);
  } else if (pe.entrySection !== null) {
    claim(`Execution would begin in section ${clean(pe.entrySection)}.`, 'observed', [evEntry]);
  }

  if (pe.overlay) {
    const evOv = ev('overlay', `${pe.overlay.size} bytes after the last section`, pe.overlay.offset);
    claim(`${pe.overlay.size} bytes follow the last section (overlay). Installers, signatures and appended data all look like this; the content was not examined.`, 'observed', [evOv]);
  }

  const importEv = new Map();
  let importCount = 0;
  for (const imp of pe.imports) {
    for (const fn of imp.functions) {
      importCount++;
      importEv.set(`${imp.dll}!${fn}`, { dll: imp.dll, fn, id: ev('import', `import ${clean(imp.dll)}!${clean(fn)}`) });
    }
  }
  if (pe.imports.length) {
    const ids = pe.imports.map((imp) => imp.functions.length ? importEv.get(`${imp.dll}!${imp.functions[0]}`).id : null).filter(Boolean);
    claim(`The import table lists ${importCount} function(s) from ${pe.imports.length} DLL(s): ${pe.imports.map((i) => clean(i.dll)).join(', ')}.`, 'observed', ids);
  }

  for (const rule of IMPORT_RULES) {
    const hits = [...importEv.values()].filter((x) => (rule.funcs && rule.funcs.test(x.fn)) || (rule.dlls && rule.dlls.test(x.dll)));
    if (!hits.length) continue;
    const ids = hits.slice(0, 8).map((x) => x.id);
    claim(`The program ${rule.text}.`, hits.length >= 2 ? 'moderate' : 'low', ids);
  }

  if (pe.exports.count) {
    const ids = [ev('export', `export table${pe.exports.name ? ` of ${clean(pe.exports.name)}` : ''}: ${pe.exports.count} entries, ${pe.exports.names.length} named`)];
    for (const n of pe.exports.names.slice(0, 5)) ids.push(ev('export', `export ${clean(n)}`));
    claim(`The file exports ${pe.exports.count} function(s)${pe.exports.names.length ? `, including ${pe.exports.names.slice(0, 5).map(clean).join(', ')}` : ''}.`, 'observed', ids);
  }

  if (pe.resources.length) {
    const byType = new Map();
    for (const rs of pe.resources) {
      const k = rs.typeName || `type ${rs.type}`;
      byType.set(k, (byType.get(k) || 0) + 1);
    }
    const ids = pe.resources.slice(0, 8).map((rs) => ev('resource', `resource ${rs.typeName || `type ${rs.type}`} id ${rs.id}: ${rs.size} bytes at RVA ${hex(rs.rva)}`));
    claim(`The file embeds ${pe.resources.length} resource(s): ${[...byType].map(([k, n]) => `${k} x${n}`).join(', ')}.`, 'observed', ids);
  }

  const strings = extractStrings(buf);
  const byKind = new Map();
  for (const s of strings) {
    const c = classify(s);
    if (!c) continue;
    const list = byKind.get(c.kind) || { total: 0, ids: [] };
    list.total++;
    if (list.ids.length < MAX_STRING_EVIDENCE_PER_KIND) {
      list.ids.push(ev('string', `${s.encoding} string at ${hex(s.offset)}: ${clean(c.match)}`, s.offset));
    }
    byKind.set(c.kind, list);
  }
  for (const rule of STRING_RULES) {
    const hit = byKind.get(rule.kind);
    if (!hit) continue;
    claim(`The file ${rule.text} (${hit.total} matching string(s)).`, hit.total >= 2 ? 'moderate' : 'low', hit.ids);
  }

  claim(`Hashes: MD5 ${hashes.md5}, SHA-1 ${hashes.sha1}, SHA-256 ${hashes.sha256}.`, 'observed', [evFile]);

  const unknowns = [
    'Nothing was executed, so actual run-time behavior is unknown.',
    'Imported functions may never be called; an import shows capability, not use.',
    'Digital signature validity was not checked.',
    'Contents of resources, overlay data and section code were not disassembled.',
  ];
  if (pe.imports.length === 0) unknowns.push('No imports were found; the table may be absent, damaged, or the program may resolve everything dynamically.');
  if (importEv.size && [...importEv.values()].some((x) => /^(GetProcAddress|LoadLibrary)/.test(x.fn))) {
    unknowns.push('Functions resolved with GetProcAddress/LoadLibrary at run time are not visible in the import table.');
  }
  for (const s of pe.sections) {
    if (s.rawSize > 0 && s.entropy >= HIGH_ENTROPY) unknowns.push(`What section ${clean(s.name)} actually contains (high entropy) is unknown.`);
  }
  if (strings.length >= 20000) unknowns.push('String extraction stopped at its limit; later strings were not examined.');
  for (const w of pe.warnings) unknowns.push(`Parser warning: ${clean(w)}`);

  return { file: clean(name), size: buf.length, hashes, pe, evidence, claims, unknowns };
}

module.exports = { analyze };
