'use strict';

const PATTERNS = [
  ['url', /\bhttps?:\/\/[^\s"'<>]{4,}/i],
  ['ipv4', /\b(?:\d{1,3}\.){3}\d{1,3}\b/],
  ['registry', /\b(?:HKEY_[A-Z_]+|SOFTWARE\\[A-Za-z0-9_\\ .-]+|CurrentVersion\\Run)/],
  ['path', /\b[A-Za-z]:\\[^\s"<>|*?]{3,}/],
  ['command', /\b(?:cmd\.exe|powershell(?:\.exe)?|wscript|cscript|rundll32|regsvr32)\b/i],
];

function extractStrings(buf, minLen = 5, limit = 20000) {
  const out = [];
  const printable = (b) => b >= 0x20 && b < 0x7f;

  let start = -1;
  for (let i = 0; i <= buf.length && out.length < limit; i++) {
    if (i < buf.length && printable(buf[i])) {
      if (start < 0) start = i;
    } else if (start >= 0) {
      if (i - start >= minLen) out.push({ offset: start, encoding: 'ascii', value: buf.toString('latin1', start, i) });
      start = -1;
    }
  }

  start = -1;
  for (let i = 0; i + 1 <= buf.length && out.length < limit; i += 2) {
    const ok = i + 1 < buf.length && printable(buf[i]) && buf[i + 1] === 0;
    if (ok) {
      if (start < 0) start = i;
    } else if (start >= 0) {
      if ((i - start) / 2 >= minLen) {
        out.push({ offset: start, encoding: 'utf16le', value: buf.toString('utf16le', start, i) });
      }
      start = -1;
    }
  }
  return out;
}

function classify(str) {
  for (const [kind, re] of PATTERNS) {
    const m = re.exec(str.value);
    if (m) return { kind, match: m[0].slice(0, 200) };
  }
  return null;
}

module.exports = { extractStrings, classify };
