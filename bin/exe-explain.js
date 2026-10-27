#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { analyze } = require('../src/analyze');
const { explainWithOllama, checkEndpoint } = require('../src/ollama');
const { toMarkdown, toHtml } = require('../src/report');

const MAX_SIZE = 512 * 1024 * 1024;

function usage() {
  console.error('usage: exe-explain <file> [--format md|html|json] [-o out] [--ollama model] [--ollama-url url] [--allow-remote]');
  process.exit(2);
}

function parseArgs(argv) {
  const opts = { format: 'md' };
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--format') opts.format = argv[++i];
    else if (a === '-o') opts.out = argv[++i];
    else if (a === '--ollama') opts.model = argv[++i];
    else if (a === '--ollama-url') opts.url = argv[++i];
    else if (a === '--allow-remote') opts.allowRemote = true;
    else if (a.startsWith('-')) usage();
    else rest.push(a);
  }
  if (rest.length !== 1 || !['md', 'html', 'json'].includes(opts.format)) usage();
  opts.file = rest[0];
  if (opts.model) {
    try {
      checkEndpoint(opts.url || 'http://127.0.0.1:11434', opts.allowRemote);
    } catch (e) {
      console.error(`exe-explain: ${e.message}`);
      process.exit(2);
    }
  }
  return opts;
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const size = fs.statSync(opts.file).size;
  if (size > MAX_SIZE) throw new Error(`file is larger than ${MAX_SIZE} bytes`);

  const result = analyze(fs.readFileSync(opts.file), path.basename(opts.file));
  let dropped = [];
  if (opts.model) {
    try {
      const extra = await explainWithOllama(result, { model: opts.model, url: opts.url, allowRemote: opts.allowRemote });
      result.claims.push(...extra.claims);
      dropped = extra.dropped;
    } catch (e) {
      result.unknowns.push(`The Ollama request failed (${e.message}); no model statements are included.`);
    }
  }

  let text;
  if (opts.format === 'json') text = JSON.stringify({ ...result, dropped }, null, 2) + '\n';
  else if (opts.format === 'html') text = toHtml(result, { dropped });
  else text = toMarkdown(result, { dropped });

  if (opts.out) fs.writeFileSync(opts.out, text);
  else process.stdout.write(text);
}

main().catch((e) => {
  console.error(`exe-explain: ${e.message}`);
  process.exit(1);
});
