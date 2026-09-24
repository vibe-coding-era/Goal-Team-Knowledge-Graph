import {readFileSync, writeFileSync} from 'node:fs';

const [input, output] = process.argv.slice(2);
if (!input || !output) throw new Error('usage: prepare-stream.mjs <stream.jsonl> <stream.js>');
const bytes = readFileSync(input);
writeFileSync(output, `globalThis.__GTKG_A2UI_STREAM_HEX__ = "${bytes.toString('hex')}";\n`);
