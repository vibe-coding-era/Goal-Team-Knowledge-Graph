import {createHash} from 'node:crypto';
import {mkdirSync, readFileSync, readdirSync, statSync, writeFileSync} from 'node:fs';
import {createServer} from 'node:http';
import {extname, join, relative, resolve} from 'node:path';
import {chromium} from 'playwright';

const [
  siteArg,
  projectionArg,
  generationArg,
  evidenceArg,
  artifactArg,
  packageLockArg,
  clientSchemaArg,
  rendererLockArg,
  harnessRootArg,
] =
  process.argv.slice(2);
if (![siteArg, projectionArg, generationArg, evidenceArg, artifactArg, packageLockArg, clientSchemaArg, rendererLockArg, harnessRootArg].every(Boolean)) {
  throw new Error('usage: run-browser.mjs <site> <projection> <generation.json> <evidence.json> <artifacts> <package-lock.json> <client-schema.json> <renderer-lock.json> <harness-root>');
}

const site = resolve(siteArg);
const projection = resolve(projectionArg);
const generationPath = resolve(generationArg);
const evidencePath = resolve(evidenceArg);
const artifacts = resolve(artifactArg);
const packageLockPath = resolve(packageLockArg);
const clientSchemaPath = resolve(clientSchemaArg);
const rendererLockPath = resolve(rendererLockArg);
const harnessRoot = resolve(harnessRootArg);
mkdirSync(artifacts, {recursive: true});

const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const shaFile = (path) => sha256(readFileSync(path));
const collectFiles = (root, directory = root, result = []) => {
  for (const name of readdirSync(directory).sort()) {
    const path = join(directory, name);
    if (statSync(path).isDirectory()) collectFiles(root, path, result);
    else result.push({path: relative(root, path).replaceAll('\\', '/'), sha256: shaFile(path)});
  }
  return result;
};

const generation = JSON.parse(readFileSync(generationPath, 'utf8'));
const streamPath = join(projection, 'a2ui/stream.jsonl');
const streamText = readFileSync(streamPath, 'utf8');
const streamMessageCount = streamText.split(/\r?\n/).filter(Boolean).length;
const packageLock = JSON.parse(readFileSync(packageLockPath, 'utf8'));
const rendererLock = JSON.parse(readFileSync(rendererLockPath, 'utf8'));
if (shaFile(packageLockPath) !== rendererLock.package_lock_sha256) {
  throw new Error('package lock drifted from the trusted renderer lock');
}
const harnessFiles = rendererLock.harness_files.map((artifact) => {
  const path = resolve(harnessRoot, artifact.path);
  if (!(path === harnessRoot || path.startsWith(`${harnessRoot}/`))) throw new Error('harness path escape');
  const observed = shaFile(path);
  if (observed !== artifact.sha256) throw new Error(`trusted harness artifact drifted: ${artifact.path}`);
  return {path: artifact.path, sha256: observed};
});
const packageInfo = (name) => {
  const entry = packageLock.packages[`node_modules/${name}`];
  if (!entry) throw new Error(`package lock is missing ${name}`);
  return {name, version: entry.version, integrity: entry.integrity ?? null};
};

const consoleErrors = [];
const pageErrors = [];
const requests = [];
const dialogs = [];
const popups = [];
const downloads = [];
const workers = [];
const contentTypes = new Map([
  ['.html', 'text/html; charset=utf-8'],
  ['.js', 'text/javascript; charset=utf-8'],
  ['.css', 'text/css; charset=utf-8'],
  ['.json', 'application/json; charset=utf-8'],
]);
const server = createServer((request, response) => {
  try {
    const requested = decodeURIComponent(new URL(request.url ?? '/', 'http://127.0.0.1').pathname);
    const path = resolve(site, `.${requested === '/' ? '/index.html' : requested}`);
    if (!(path === site || path.startsWith(`${site}/`))) throw new Error('path escape');
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
if (!address || typeof address === 'string') throw new Error('loopback server address unavailable');
const browser = await chromium.launch({headless: true});
const page = await browser.newPage({viewport: {width: 1440, height: 900}});
page.on('console', (message) => {
  if (message.type() === 'error') consoleErrors.push(message.text());
});
page.on('pageerror', (error) => pageErrors.push(error.stack ?? String(error)));
page.on('request', (request) => requests.push(request.url()));
page.on('dialog', async (dialog) => {
  dialogs.push({type: dialog.type(), message: dialog.message()});
  await dialog.dismiss();
});
page.on('popup', (popup) => popups.push(popup.url()));
page.on('download', (download) => downloads.push(download.suggestedFilename()));
page.on('worker', (worker) => workers.push(worker.url()));
await page.addInitScript(() => {
  globalThis.__GTKG_XSS_SENTINEL__ = false;
  globalThis.__GTKG_CSP_VIOLATIONS__ = [];
  globalThis.__GTKG_WINDOW_OPEN_COUNT__ = 0;
  globalThis.open = () => {
    globalThis.__GTKG_WINDOW_OPEN_COUNT__ += 1;
    return null;
  };
  globalThis.addEventListener('securitypolicyviolation', (event) => {
    globalThis.__GTKG_CSP_VIOLATIONS__.push(event.violatedDirective);
  });
});
await page.goto(`http://127.0.0.1:${address.port}/index.html`);
try {
  await page.waitForFunction(
    () => globalThis.__GTKG_H05__?.ready || globalThis.__GTKG_H05__?.errors?.length,
    null,
    {timeout: 30_000},
  );
} catch (error) {
  const diagnostic = await page.evaluate(() => ({
    evidence: globalThis.__GTKG_H05__,
    body: document.body?.innerText,
  }));
  console.error(JSON.stringify({diagnostic, consoleErrors, pageErrors, requests}, null, 2));
  throw error;
}

const composedText = async () => page.evaluate(() => {
  const parts = [];
  const visit = (node) => {
    if (node.nodeType === Node.TEXT_NODE) {
      const text = node.textContent?.trim();
      if (text) parts.push(text);
      return;
    }
    if (node.shadowRoot) visit(node.shadowRoot);
    for (const child of node.childNodes ?? []) visit(child);
  };
  visit(document.body);
  return parts.join(' ');
});

const initialEvidence = await page.evaluate(() => structuredClone(globalThis.__GTKG_H05__));
if (initialEvidence.errors.length) throw new Error(initialEvidence.errors.join('\n'));
if (initialEvidence.catalogId !== generation.a2ui_lock.catalog_id) throw new Error('basicCatalog identity mismatch');
if (initialEvidence.messageCount !== streamMessageCount) throw new Error('processed message count mismatch');
if (initialEvidence.surfaceId !== 'gtkg-main') throw new Error('surface id mismatch');
for (const required of ['root', 'index-pane', 'index-list', 'index-button', 'content-pane', 'doc-title', 'doc-body', 'doc-provenance']) {
  if (!initialEvidence.componentIds.includes(required)) throw new Error(`missing rendered component ${required}`);
}
if (initialEvidence.indexCount < 2) throw new Error('renderer index did not materialize');
let text = await composedText();
if (!text.includes('Knowledge Index') || !text.includes(initialEvidence.initialTitle)) {
  throw new Error(`left index or right title is not visible: ${text.slice(0, 500)}`);
}
if (!text.includes(initialEvidence.initialBody.trim().slice(0, 40))) {
  throw new Error('selected document body is not visible');
}

const initialScreenshot = join(artifacts, 'initial.png');
await page.screenshot({path: initialScreenshot, fullPage: true});
const buttons = page.locator('a2ui-basic-button');
if (await buttons.count() !== initialEvidence.indexCount) throw new Error('dynamic index button count mismatch');
await buttons.last().locator('button').click();
try {
  await page.waitForFunction(() => globalThis.__GTKG_H05__.actions.length > 0, null, {timeout: 10_000});
} catch (error) {
  const buttonDiagnostic = await buttons.last().evaluate((element) => ({
    props: element.controller?.props,
    html: element.shadowRoot?.innerHTML,
    contextPath: element.context?.path,
    componentId: element.context?.componentModel?.id,
    rawAction: element.context?.componentModel?.properties?.action,
    dataContextPath: element.context?.dataContext?.path,
    evidence: globalThis.__GTKG_H05__,
  }));
  console.error(JSON.stringify({buttonDiagnostic, consoleErrors, pageErrors}, null, 2));
  throw error;
}
const actionEvidence = await page.evaluate(() => structuredClone(globalThis.__GTKG_H05__));
const action = actionEvidence.actions.at(-1);
const clientMessage = {version: 'v0.9', action};
if (!actionEvidence.actionSchemaValid || action.name !== 'gtkg.select_document') throw new Error('official client action validation failed');
if (!action.context?.documentId || !action.context?.documentPath || !action.sourceComponentId) throw new Error('action context/source binding is incomplete');

const updatedTitle = 'H05 Updated Document';
const updatedBody = 'H05 safe text <img src=x onerror=globalThis.__GTKG_XSS_SENTINEL__=true> <script>globalThis.__GTKG_XSS_SENTINEL__=true</script> https://example.invalid';
await page.evaluate(async ({title, body}) => globalThis.__GTKG_APPLY_DOCUMENT__(title, body), {title: updatedTitle, body: updatedBody});
await page.waitForFunction((title) => globalThis.__GTKG_H05__.updatedTitle === title, updatedTitle);
text = await composedText();
if (!text.includes(updatedTitle) || !text.includes('H05 safe text')) throw new Error('reactive document update is not visible');
const xssSentinel = await page.evaluate(() => globalThis.__GTKG_XSS_SENTINEL__);
const cspViolations = await page.evaluate(() => structuredClone(globalThis.__GTKG_CSP_VIOLATIONS__));
const windowOpenCount = await page.evaluate(() => globalThis.__GTKG_WINDOW_OPEN_COUNT__);
const dangerousContentNodeCount = await page.locator('#surface').evaluate((root) => {
  let count = 0;
  const visit = (node) => {
    if (node.nodeType === Node.ELEMENT_NODE && node.matches('script,img,iframe,object,embed,svg,foreignObject')) count += 1;
    if (node.shadowRoot) visit(node.shadowRoot);
    for (const child of node.childNodes ?? []) visit(child);
  };
  visit(root);
  return count;
});
if (xssSentinel) throw new Error('untrusted document text executed');

const updatedScreenshot = join(artifacts, 'updated.png');
await page.screenshot({path: updatedScreenshot, fullPage: true});
const browserVersion = browser.version();
const executablePath = chromium.executablePath();
await browser.close();
await new Promise((resolveClose, reject) => server.close((error) => (error ? reject(error) : resolveClose())));

const remoteRequests = requests.filter((url) => {
  if (!/^https?:\/\//i.test(url)) return false;
  const host = new URL(url).hostname;
  return host !== '127.0.0.1' && host !== 'localhost';
});
if (remoteRequests.length || consoleErrors.length || pageErrors.length || cspViolations.length) {
  throw new Error(JSON.stringify({remoteRequests, consoleErrors, pageErrors, cspViolations}));
}

const finalEvidence = {
  schema_version: 'gtkg.a2ui-renderer-smoke/v2',
  projection_tree_sha256: generation.projection_tree_sha256,
  stream_sha256: shaFile(streamPath),
  stream_message_count: streamMessageCount,
  catalog_id: generation.a2ui_lock.catalog_id,
  catalog_version: generation.a2ui_lock.catalog_version,
  catalog_sha256: generation.a2ui_lock.catalog_sha256,
  server_schema_sha256: generation.a2ui_lock.schema_sha256,
  common_types_sha256: generation.a2ui_lock.common_types_sha256,
  client_schema_sha256: shaFile(clientSchemaPath),
  renderer: {
    package_lock_path: packageLockPath,
    package_lock_sha256: shaFile(packageLockPath),
    harness_root: harnessRoot,
    harness_files: harnessFiles,
    site_root: site,
    site_files: collectFiles(site),
    packages: [packageInfo('@a2ui/lit'), packageInfo('@a2ui/web_core'), packageInfo('lit'), packageInfo('playwright'), packageInfo('vite')],
  },
  browser: {
    engine: 'chromium',
    version: browserVersion,
    executable_path: executablePath,
    executable_sha256: shaFile(executablePath),
  },
  observations: {
    surface_id: initialEvidence.surfaceId,
    catalog_id: initialEvidence.catalogId,
    message_count: initialEvidence.messageCount,
    component_ids: initialEvidence.componentIds,
    index_count: initialEvidence.indexCount,
    initial_title: initialEvidence.initialTitle,
    initial_body_sha256: sha256(Buffer.from(initialEvidence.initialBody)),
    action_schema_valid: actionEvidence.actionSchemaValid,
    client_message: clientMessage,
    action_name: action.name,
    action_context_id: action.context.documentId,
    action_context_path: action.context.documentPath,
    action_source_component_id: action.sourceComponentId,
    updated_title: updatedTitle,
    updated_body_sha256: sha256(Buffer.from(updatedBody)),
    remote_request_count: remoteRequests.length,
    console_error_count: consoleErrors.length + pageErrors.length,
    csp_violation_count: cspViolations.length,
    dialog_count: dialogs.length,
    popup_count: popups.length,
    download_count: downloads.length,
    worker_count: workers.length,
    window_open_count: windowOpenCount,
    dangerous_content_node_count: dangerousContentNodeCount,
    xss_sentinel_tripped: xssSentinel,
  },
  artifacts: [
    {path: initialScreenshot, sha256: shaFile(initialScreenshot)},
    {path: updatedScreenshot, sha256: shaFile(updatedScreenshot)},
  ],
};
writeFileSync(evidencePath, `${JSON.stringify(finalEvidence, null, 2)}\n`);
console.log(JSON.stringify({evidencePath, streamMessageCount, browserVersion, action: action.name}));
