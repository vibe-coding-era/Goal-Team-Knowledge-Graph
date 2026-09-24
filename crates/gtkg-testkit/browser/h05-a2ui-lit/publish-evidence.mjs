import {createHash} from 'node:crypto';
import {cpSync, existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync} from 'node:fs';
import {basename, dirname, join, relative, resolve} from 'node:path';

const [runArg, destinationArg] = process.argv.slice(2);
if (!runArg || !destinationArg) throw new Error('usage: publish-evidence.mjs <H05 run root> <destination>');
const run = resolve(runArg);
const destination = resolve(destinationArg);
if (existsSync(destination)) throw new Error(`destination already exists: ${destination}`);
mkdirSync(destination, {recursive: true});

const sha256 = (path) => `sha256:${createHash('sha256').update(readFileSync(path)).digest('hex')}`;
const fixturePath = join(run, 'emitter/h05-current-source-receipt.json');
const fixture = JSON.parse(readFileSync(fixturePath, 'utf8'));
const workspace = fixture.workspace;
const smokePath = join(workspace, '.gtkg/a2ui/browser-evidence/smoke-h05-v2.json');
const smoke = JSON.parse(readFileSync(smokePath, 'utf8'));
const validationPath = join(run, 'h05-validation.json');
const validation = JSON.parse(readFileSync(validationPath, 'utf8'));
const generation = JSON.parse(readFileSync(fixture.generation_receipt_path, 'utf8'));
const sourceManifestPath = fixture.source_snapshot.current_source_manifest_path;
const sources = [
  [fixturePath, 'current-source-receipt.json'],
  [sourceManifestPath, 'current-source-manifest.json'],
  [validationPath, 'validation.json'],
  [smokePath, 'renderer-smoke-v2.json'],
  [fixture.generation_receipt_path, 'receipts/generation.json'],
  [join(run, 'emitter', fixture.source_inspection_ref.path), 'receipts/source-inspection.json'],
  [join(workspace, generation.resolution_ref.path), 'receipts/resolution.json'],
  [join(workspace, validation.validation.validation_ref.path), 'receipts/a2ui-validation.json'],
];
for (const artifact of smoke.artifacts) {
  sources.push([artifact.path, `screenshots/${basename(artifact.path)}`]);
}
for (const artifact of smoke.renderer.harness_files) {
  sources.push([join(smoke.renderer.harness_root, artifact.path), `renderer/harness/${artifact.path}`]);
}
for (const [source, relativePath] of sources) {
  const target = join(destination, relativePath);
  mkdirSync(dirname(target), {recursive: true});
  cpSync(source, target);
}
cpSync(fixture.bundle_path, join(destination, 'bundle'), {recursive: true});
cpSync(fixture.projection_path, join(destination, 'projection'), {recursive: true});
cpSync(smoke.renderer.site_root, join(destination, 'renderer/site'), {recursive: true});

const files = [];
const collect = (directory) => {
  for (const name of readdirSync(directory).sort()) {
    const path = join(directory, name);
    if (statSync(path).isDirectory()) collect(path);
    else if (basename(path) !== 'evidence-manifest.json' && basename(path) !== 'summary.json') {
      files.push({
        path: relative(destination, path).replaceAll('\\', '/'),
        bytes: statSync(path).size,
        sha256: sha256(path),
      });
    }
  }
};
collect(destination);
writeFileSync(
  join(destination, 'summary.json'),
  `${JSON.stringify(
    {
      schema_version: 'gtkg.h05-evidence-summary/v1',
      result: 'passed_current_development',
      source_snapshot: fixture.source_snapshot,
      source_file_count: fixture.source_file_count,
      admitted_source_count: fixture.admitted_source_count,
      omission_count: fixture.omission_count,
      bundle_tree_sha256: fixture.bundle_tree_sha256,
      projection_tree_sha256: fixture.projection_tree_sha256,
      stream_sha256: fixture.stream_sha256,
      stream_message_count: fixture.stream_message_count,
      renderer_smoke_schema: smoke.schema_version,
      renderer_packages: smoke.renderer.packages,
      browser: smoke.browser,
      observations: smoke.observations,
      validation: 'renderer_replicable',
      screenshot_artifacts: validation.validation.checks.screenshot_artifacts,
      visual_threshold: validation.validation.checks.visual_threshold,
      verified_replica: 'not_run_fail_closed',
      evidence_portability: 'the current-source exact manifest, canonical bundle, full projection/Wiki, trusted harness, receipts, renderer site, and screenshots are copied and digest-manifested; raw receipts retain original absolute execution paths',
    },
    null,
    2,
  )}\n`,
);
files.push({
  path: 'summary.json',
  bytes: statSync(join(destination, 'summary.json')).size,
  sha256: sha256(join(destination, 'summary.json')),
});
files.sort((left, right) => left.path.localeCompare(right.path));
writeFileSync(
  join(destination, 'evidence-manifest.json'),
  `${JSON.stringify({schema_version: 'gtkg.evidence-manifest/v1', files}, null, 2)}\n`,
);
console.log(JSON.stringify({destination, fileCount: files.length}));
