'use strict';

const LEGEND = {
  observed: 'read directly from the file',
  moderate: 'inferred by a rule from two or more pieces of evidence',
  low: 'inferred by a rule from a single piece of evidence',
  model: 'written by a language model; only checked for citing real evidence',
};

function usedEvidence(result) {
  const used = new Set(result.claims.flatMap((c) => c.evidence));
  return result.evidence.filter((e) => used.has(e.id));
}

function toMarkdown(result, { dropped = [] } = {}) {
  const out = [];
  out.push(`# Static analysis: ${result.file}`, '');
  out.push('Static analysis only. The file was not executed. Statements describe what the file may do, not what it does.', '');
  out.push('## Claims', '');
  for (const c of result.claims) {
    out.push(`${c.id}. ${c.text} [${c.certainty}] (evidence: ${c.evidence.join(', ')})`);
  }
  out.push('', '## Evidence', '');
  for (const e of usedEvidence(result)) {
    out.push(`- ${e.id} (${e.kind}): ${e.label}`);
  }
  out.push('', '## Unknowns', '');
  for (const u of result.unknowns) out.push(`- ${u}`);
  if (dropped.length) {
    out.push('', '## Dropped model statements', '');
    out.push(`${dropped.length} statement(s) from the model were discarded:`, '');
    for (const d of dropped) out.push(`- ${d.reason}`);
  }
  out.push('', '## Certainty labels', '');
  for (const [k, v] of Object.entries(LEGEND)) out.push(`- ${k}: ${v}`);
  return out.join('\n') + '\n';
}

const esc = (s) => String(s).replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]);

function toHtml(result, { dropped = [] } = {}) {
  const claims = result.claims.map((c) => {
    const links = c.evidence.map((id) => `<a href="#${esc(id)}">${esc(id)}</a>`).join(', ');
    return `<li id="${esc(c.id)}">[${esc(c.certainty)}] ${esc(c.text)} (evidence: ${links})</li>`;
  });
  const evidence = usedEvidence(result).map((e) => `<li id="${esc(e.id)}"><b>${esc(e.id)}</b> (${esc(e.kind)}): ${esc(e.label)}</li>`);
  const unknowns = result.unknowns.map((u) => `<li>${esc(u)}</li>`);
  const drop = dropped.map((d) => `<li>${esc(d.reason)}</li>`);
  const legend = Object.entries(LEGEND).map(([k, v]) => `<li>${esc(k)}: ${esc(v)}</li>`);
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Static analysis: ${esc(result.file)}</title>
<style>
body{font-family:system-ui,sans-serif;max-width:60rem;margin:1rem auto;padding:0 1rem}
li{margin:.3rem 0}
</style></head><body>
<h1>Static analysis: ${esc(result.file)}</h1>
<p>Static analysis only. The file was not executed. Statements describe what the file may do, not what it does.</p>
<h2>Claims</h2><ol>${claims.join('\n')}</ol>
<h2>Evidence</h2><ul>${evidence.join('\n')}</ul>
<h2>Unknowns</h2><ul>${unknowns.join('\n')}</ul>
${drop.length ? `<h2>Dropped model statements</h2><ul>${drop.join('\n')}</ul>` : ''}
<h2>Certainty labels</h2><ul>${legend.join('')}</ul>
</body></html>
`;
}

module.exports = { toMarkdown, toHtml };
