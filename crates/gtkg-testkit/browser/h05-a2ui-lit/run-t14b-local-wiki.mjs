// T14B browser evidence: a real local browser reads a static Wiki projection.
// The server binds only 127.0.0.1 and this harness never contacts a Provider,
// target repository, or external renderer endpoint.

import {createHash} from 'node:crypto';
import {mkdirSync, readFileSync, renameSync, rmSync, writeFileSync} from 'node:fs';
import {createServer} from 'node:http';
import {extname, resolve, sep} from 'node:path';
import {chromium} from 'playwright';

const [siteArg, receiptArg, evidenceArg] = process.argv.slice(2);
if (!siteArg || !receiptArg || !evidenceArg) {
  throw new Error('usage: run-t14b-local-wiki.mjs <site-root> <fixture-receipt.json> <evidence.json>');
}
const site = resolve(siteArg);
const receiptPath = resolve(receiptArg);
const evidencePath = resolve(evidenceArg);
const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const contentTypes = new Map([
  ['.html', 'text/html; charset=utf-8'],
  ['.js', 'text/javascript; charset=utf-8'],
  ['.json', 'application/json; charset=utf-8'],
]);
const fixtureReceipt = JSON.parse(readFileSync(receiptPath, 'utf8'));
const identity = (root) => {
  const index = JSON.parse(readFileSync(resolve(root, 'index.json'), 'utf8'));
  return {
    site: root,
    projection_sha256: index.projection?.projection_sha256,
    structural_graph_sha256: index.projection?.structural_graph_sha256,
    knowledge_overlay_sha256: index.projection?.knowledge_overlay_sha256,
    lifecycle_identity_sha256: index.projection?.lifecycle_identity_sha256,
    query_receipt_sha256: index.projection?.query_receipt_sha256,
    evidence_state: index.projection?.evidence_state,
    site_index_sha256: sha256(readFileSync(resolve(root, 'index.json'))),
    site_stream_sha256: sha256(readFileSync(resolve(root, 'a2ui/stream.jsonl'))),
    site_manifest_sha256: sha256(readFileSync(resolve(root, 'manifest.json'))),
  };
};
const identityMatchesReceipt = (observed) =>
  fixtureReceipt.schema_version === 'gtkg.t14b-browser-fixture/v2' &&
  resolve(fixtureReceipt.site) === site &&
  Object.entries(observed).every(([key, value]) => key === 'site' || fixtureReceipt[key] === value);
const initialIdentity = identity(site);
if (!identityMatchesReceipt(initialIdentity)) throw new Error(`fixture receipt identity mismatch: ${JSON.stringify({fixtureReceipt, initialIdentity})}`);
const server = createServer((request, response) => {
  try {
    const pathname = decodeURIComponent(new URL(request.url ?? '/', 'http://127.0.0.1').pathname);
    const path = resolve(site, `.${pathname === '/' ? '/index.html' : pathname}`);
    if (!(path === site || path.startsWith(`${site}${sep}`))) throw new Error('path escape');
    const bytes = readFileSync(path);
    response.writeHead(200, {'content-type': contentTypes.get(extname(path)) ?? 'application/octet-stream'});
    response.end(bytes);
  } catch {
    response.writeHead(404);
    response.end('not found');
  }
});
await new Promise((resolveListen, reject) => {
  server.once('error', reject);
  server.listen(0, '127.0.0.1', resolveListen);
});
const address = server.address();
if (!address || typeof address === 'string') throw new Error('loopback server failed to bind');
const origin = `http://127.0.0.1:${address.port}`;
const requests = [];
const consoleErrors = [];
const pageErrors = [];
const browser = await chromium.launch({headless: true});
try {
  const page = await browser.newPage({viewport: {width: 1280, height: 720}});
  page.on('request', (request) => requests.push(request.url()));
  page.on('console', (message) => {
    if (message.type() === 'error') consoleErrors.push(message.text());
  });
  page.on('pageerror', (error) => pageErrors.push(String(error)));
  await page.goto(`${origin}/index.html`, {waitUntil: 'domcontentloaded'});
  await page.waitForFunction(
    () => document.querySelectorAll('#index button').length > 0 && document.querySelector('#title').textContent,
    null,
    {timeout: 10_000},
  );
  const initial = await page.evaluate(() => ({
    title: document.querySelector('#title').textContent,
    body: document.querySelector('#body').textContent,
    evidence: document.querySelector('#evidence').textContent,
    scripts: document.querySelectorAll('script').length,
    dangerous: document.querySelectorAll('script:not([src]),iframe,object,embed,img,svg').length,
  }));
  if (!initial.title || !initial.body || !initial.evidence.includes('a2ui_generatable') || initial.scripts !== 1 || initial.dangerous !== 0) {
    throw new Error(`initial local Wiki projection did not render safely: ${JSON.stringify(initial)}`);
  }
  const buttonCount = await page.locator('#index button').count();
  if (buttonCount > 1) {
    await page.locator('#index button').last().click();
    await page.waitForTimeout(50);
  }
  const remoteRequests = requests.filter((url) => !url.startsWith(origin));
  if (remoteRequests.length || consoleErrors.length || pageErrors.length) {
    throw new Error(`local browser boundary failed: ${JSON.stringify({remoteRequests, consoleErrors, pageErrors})}`);
  }
  const localPaths = requests.map((url) => new URL(url).pathname);
  const pageReads = localPaths.filter((path) => path.startsWith('/pages/')).length;
  if (pageReads < 1 || pageReads > (buttonCount > 1 ? 2 : 1) || !localPaths.includes('/index.json')) {
    throw new Error(`progressive page reads drifted: ${JSON.stringify({buttonCount, localPaths})}`);
  }
  const anchoredSite = `${site}.identity-anchor`;
  let siteReplacementRejected = false;
  renameSync(site, anchoredSite);
  try {
    mkdirSync(site);
    writeFileSync(resolve(site, 'index.json'), '{"projection":{}}\n');
    try {
      const replacementIdentity = identity(site);
      siteReplacementRejected = !identityMatchesReceipt(replacementIdentity);
    } catch {
      siteReplacementRejected = true;
    }
    if (!siteReplacementRejected) throw new Error('site replacement unexpectedly satisfied fixture identity');
  } finally {
    rmSync(site, {recursive: true, force: true});
    renameSync(anchoredSite, site);
  }
  mkdirSync(resolve(evidencePath, '..'), {recursive: true});
  const evidence = {
    schema_version: 'gtkg.t14b-local-browser-evidence/v2',
    browser_execution: 'local_loopback_only',
    evidence_state: 'a2ui_generatable',
    renderer_replicable: 'not_claimed',
    provider_calls: 0,
    target_execution_count: 0,
    fixture_receipt_verified: true,
    site_replacement_rejected: siteReplacementRejected,
    local_request_paths: localPaths,
    local_page_reads: pageReads,
    initial,
    ...identity(site),
  };
  writeFileSync(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`);
} finally {
  await browser.close();
  await new Promise((resolveClose) => server.close(resolveClose));
}
