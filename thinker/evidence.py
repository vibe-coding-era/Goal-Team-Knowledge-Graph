"""Read-only evidence adapters. Source text is data, never executable input.

Only administrator-pinned executables/handoffs reach GTKGAdapter. Source readers
accept a registry binding, never a command, repository location or index override.
All hashes are SHA-256 of bytes; character offsets only belong to knowledge pages.
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import time


MAX_BLOB = 8 * 1024 * 1024
MAX_SNIPPET = 64 * 1024
OID = re.compile(r'^(?:[a-f0-9]{40}|[a-f0-9]{64})$')
SHA = re.compile(r'^sha256:[a-f0-9]{64}$')


def digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def _matches_hash(claimed, raw):
    actual = digest(raw)
    # GTKG source chunks use bare hex; artifact refs use the algorithm prefix.
    return claimed in (actual, actual[7:])


def file_digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return 'sha256:' + h.hexdigest()


def git(location, *args, allowed=(0,)):
    """Fixed Git plumbing only; no hooks, replacement objects, helpers or fetch."""
    env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
               GIT_NO_REPLACE_OBJECTS='1', GIT_OPTIONAL_LOCKS='0',
               GIT_TERMINAL_PROMPT='0', GIT_PAGER='cat', GIT_NO_LAZY_FETCH='1')
    try:
        result = subprocess.run(
            ['/usr/bin/git', '--no-optional-locks', '-c', 'core.hooksPath=' + os.devnull,
             '-c', 'protocol.allow=never', '-c', 'credential.helper=',
             '-C', str(location), *args], env=env, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError('git_unavailable') from exc
    if result.returncode not in allowed:
        # Do not expose arbitrary local config, credentials or source in errors.
        raise ValueError('git_read_failed')
    return result


def repository_identity(location):
    root = Path(location)
    if not root.is_absolute() or not root.is_dir():
        raise ValueError('repository_location_unavailable')
    root = root.resolve(strict=True)
    common = git(str(root), 'rev-parse', '--git-common-dir').stdout.decode().strip()
    common = (root / common).resolve(strict=True)
    if not common.is_dir():
        raise ValueError('repository_common_dir_unavailable')
    return str(root), str(common)


def source_path(value):
    if not isinstance(value, str) or not value or len(value) > 2048 or '\x00' in value:
        raise ValueError('invalid_source_path')
    path = PurePosixPath(value)
    if path.is_absolute() or '\\' in value or any(p in ('', '.', '..') for p in value.split('/')):
        raise ValueError('invalid_source_path')
    return value


def git_blob(location, revision, path):
    source_path(path)
    if not isinstance(revision, str) or not OID.fullmatch(revision):
        raise ValueError('full_commit_oid_required')
    actual = git(location, 'rev-parse', '--verify', revision + '^{commit}').stdout.decode().strip()
    if actual != revision:
        raise ValueError('commit_identity_mismatch')
    tree = git(location, 'ls-tree', '-z', revision, '--', path).stdout
    entries = [entry for entry in tree.split(b'\x00') if entry]
    if len(entries) != 1:
        raise ValueError('source_path_missing_or_ambiguous')
    metadata, found_path = entries[0].split(b'\t', 1)
    mode, kind, object_id = metadata.split()
    if found_path.decode('utf-8') != path or mode not in (b'100644', b'100755') or kind != b'blob':
        raise ValueError('source_must_be_regular_blob_not_symlink_or_submodule')
    size = int(git(location, 'cat-file', '-s', object_id.decode()).stdout)
    if size > MAX_BLOB:
        raise ValueError('source_blob_over_budget')
    raw = git(location, 'cat-file', 'blob', object_id.decode()).stdout
    if len(raw) != size:
        raise ValueError('source_blob_size_changed')
    return raw


def _slice(raw, start, end):
    if type(start) is not int or type(end) is not int or not 0 <= start < end <= len(raw):
        raise ValueError('invalid_source_byte_range')
    if end - start > MAX_SNIPPET:
        raise ValueError('source_range_over_budget')
    try:
        raw[:start].decode('utf-8')
        text = raw[start:end].decode('utf-8')
    except UnicodeError as exc:
        raise ValueError('non_utf8_or_split_character') from exc
    return text, raw[:start].count(b'\n') + 1, raw[:end - 1].count(b'\n') + 1


def _record(binding, kind, locator, raw, text, **extra):
    required = ('scope', 'repo', 'ref', 'source_revision', 'config_revision', 'ref_generation')
    if any(key not in binding for key in required):
        raise ValueError('registry_binding_required')
    identity = {key: binding[key] for key in required}
    identity.update(source_kind=kind, locator=locator, content_hash=digest(raw))
    encoded = json.dumps(identity, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()
    now = time.time()
    return dict(identity, id='ev-' + hashlib.sha256(encoded).hexdigest(), text=text,
                state='active', transition_seq=binding.get('transition_seq', 0),
                source_uri='git:' + binding['repo'] + '@' + binding['source_revision'],
                occurred_at=now, recorded_at=now, **extra)


def read_source(location, binding, path, start=0, end=None):
    raw = git_blob(location, binding['source_revision'], path)
    end = len(raw) if end is None else end
    text, line_start, line_end = _slice(raw, start, end)
    locator = {'path': path, 'byte_start': start, 'byte_end': end,
               'line_start': line_start, 'line_end': line_end,
               'commit': binding['source_revision'], 'repo': binding['repo']}
    return _record(binding, 'git_source', locator, raw[start:end], text,
                   file_hash=digest(raw), source_span_verified=True,
                   verification_method='git_cat_file_blob',
                   read_policy='whole_file' if start == 0 and end == len(raw) else 'byte_range')


def validate_source_hit(location, binding, hit):
    if hit.get('source_commit') != binding['source_revision']:
        raise ValueError('source_revision_mismatch')
    raw = git_blob(location, binding['source_revision'], hit.get('path'))
    if not _matches_hash(hit.get('file_sha', hit.get('file_hash')), raw):
        raise ValueError('source_file_hash_mismatch')
    start, end = hit.get('byte_start'), hit.get('byte_end')
    text, first, last = _slice(raw, start, end)
    if hit.get('text') != text or hit.get('line_start') != first or hit.get('line_end') != last:
        raise ValueError('source_span_or_text_mismatch')
    if hit.get('content_hash') is not None and not _matches_hash(hit['content_hash'], raw[start:end]):
        raise ValueError('source_slice_hash_mismatch')
    if hit.get('source_tree') is not None:
        tree = git(location, 'rev-parse', binding['source_revision'] + '^{tree}').stdout.decode().strip()
        if hit['source_tree'] != tree:
            raise ValueError('source_tree_mismatch')
    locator = {'path': hit['path'], 'byte_start': start, 'byte_end': end,
               'line_start': first, 'line_end': last,
               'commit': binding['source_revision'], 'repo': binding['repo']}
    return _record(binding, 'gtkg_source', locator, raw[start:end], text,
                   file_hash=digest(raw), source_span_verified=True,
                   verification_method='git_cat_file_blob', read_policy='byte_range')


def _contained_file(root, relative):
    source_path(relative)
    base = Path(root).resolve(strict=True)
    path = (base / relative).resolve(strict=True)
    if base not in path.parents or not path.is_file():
        raise ValueError('artifact_outside_authorized_root')
    if path.stat().st_size > MAX_BLOB:
        raise ValueError('artifact_over_budget')
    return path


def bind_knowledge_page(root, bundle_digest, binding, hit, location=None):
    """Legacy page citations stay page-local; a source hash alone is not a locator."""
    if not SHA.fullmatch(bundle_digest or ''):
        raise ValueError('bundle_digest_required')
    meta = hit.get('evidence', {})
    path = meta.get('knowledge_path')
    if hit.get('knowledge_path') != path:
        raise ValueError('page_locator_mismatch')
    try:
        raw = _contained_file(root, path).read_bytes()
    except (OSError, TypeError) as exc:
        raise ValueError('knowledge_page_unavailable') from exc
    if not _matches_hash(meta.get('knowledge_sha256'), raw):
        raise ValueError('knowledge_page_hash_mismatch')
    text = raw.decode('utf-8')
    start, end = meta.get('snippet_char_start'), meta.get('snippet_char_end')
    if type(start) is not int or type(end) is not int or not 0 <= start < end <= len(text):
        raise ValueError('invalid_page_character_range')
    snippet = text[start:end]
    if snippet != hit.get('snippet') or len(snippet.encode()) > MAX_SNIPPET:
        raise ValueError('knowledge_page_snippet_mismatch')
    sources = []
    for source in meta.get('source_bindings', []):
        if location is None:
            raise ValueError('source_binding_requires_registered_repository')
        sources.append(validate_source_hit(location, binding, source))
    return _record(binding, 'knowledge_page', {
        'page_path': path, 'bundle_digest': bundle_digest,
        'page_hash': digest(raw), 'char_start': start, 'char_end': end,
        'byte_start': len(text[:start].encode()), 'byte_end': len(text[:end].encode())},
        snippet.encode(), snippet, source_bindings=sources,
        binding_status='source_bound' if sources else 'partial', independent_evidence=False)


def _validated_result(location, binding, response, limit):
    result = response.get('result', response)
    valid, partial = [], []
    rows = result.get('evidence', [])
    if not isinstance(rows, list):
        return {'status': 'partial', 'evidence': [], 'partial_sources': ['invalid_adapter_response']}
    for hit in rows[:limit]:
        try:
            valid.append(validate_source_hit(location, binding, hit))
        except (ValueError, KeyError, TypeError, UnicodeError):
            partial.append('source_binding_failed')
    if result.get('status') not in ('complete', 'fresh') or result.get('truncation', {}).get('budget'):
        partial.append('query_incomplete')
    if result.get('truncation', {}).get('pagination'):
        partial.append('more_matches_not_returned')
    return {'status': 'partial' if partial else 'fresh', 'evidence': valid,
            'partial_sources': sorted(set(partial)),
            'index_revision': binding['source_revision'],
            'ranking_complete': result.get('ranking_complete', result.get('status') == 'complete')}


class MockAdapter:
    """Deterministic fixture adapter, never treated as independent provider proof."""
    def __init__(self, response):
        self.response = response

    def search(self, location, binding, query, limit=5):
        result = _validated_result(location, binding, self.response, limit)
        for item in result['evidence']:
            item['adapter_kind'] = 'mock'
            item['execution_assurance'] = 'fixture_only'
        return result


class GTKGAdapter:
    """Only graph.search; immutable handoff, index and executable identities."""
    def __init__(self, config):
        self.config = dict(config)
        try:
            path = Path(config['handoff'])
            binary = Path(config['binary'])
            if not path.is_absolute() or not binary.is_absolute():
                raise ValueError('absolute_adapter_paths_required')
            path = path.resolve(strict=True)
            binary = binary.resolve(strict=True)
            if not path.is_file() or path.stat().st_size > 1024 * 1024:
                raise ValueError('invalid_handoff')
            # An administrator may pin a native GTKG build, not a shell wrapper.
            with binary.open('rb') as stream:
                magic = stream.read(4)
            if binary.name != 'gtkg' or magic not in (
                    b'\x7fELF', b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf',
                    b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xce', b'\xca\xfe\xba\xbe',
                    b'\xca\xfe\xba\xbf') or not os.access(str(binary), os.X_OK):
                raise ValueError('native_gtkg_binary_required')
            handoff_raw = path.read_bytes()
            handoff_sha, binary_sha = digest(handoff_raw), file_digest(binary)
            for key, value in (('handoff_sha256', handoff_sha), ('binary_sha256', binary_sha)):
                if config.get(key) is not None and config[key] != value:
                    raise ValueError('adapter_pin_changed')
                self.config[key] = value
            self.handoff = json.loads(handoff_raw)
            self.root = path.parent
            if self.handoff.get('workspace_root') and Path(self.handoff['workspace_root']).resolve() != self.root:
                raise ValueError('handoff_workspace_mismatch')
            self.revision = self.handoff['source_commit']
            if not OID.fullmatch(self.revision):
                raise ValueError('handoff_commit_required')
            ref = self.handoff['index_ref']
            manifest = _contained_file(self.root, ref['path']).read_bytes()
            if digest(manifest) != ref['sha256']:
                raise ValueError('index_manifest_hash_mismatch')
            self.index = json.loads(manifest)
            if self.index.get('source_commit') != self.revision:
                raise ValueError('index_commit_mismatch')
            self.config.update(kind='gtkg', handoff=str(path), binary=str(binary))
        except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
            raise ValueError('gtkg_handoff_unavailable') from exc

    def search(self, location, binding, query, limit=5):
        if binding['source_revision'] != self.revision:
            return {'status': 'stale', 'evidence': [], 'partial_sources': ['gtkg_index_behind'],
                    'index_revision': self.revision}
        try:
            if self.handoff.get('source_root'):
                if repository_identity(location)[1] != repository_identity(self.handoff['source_root'])[1]:
                    raise ValueError('handoff_repository_mismatch')
            tree = git(location, 'rev-parse', self.revision + '^{tree}').stdout.decode().strip()
            if self.handoff.get('source_tree') != tree or self.index.get('source_tree') != tree:
                raise ValueError('handoff_tree_mismatch')
            request = {'protocol_version': 'gtkg.protocol/v2', 'operation_id': 'graph.search',
                       'request_id': 'thinker-read-only', 'payload': {
                           'payload_revision': 'gtkg.knowledge-quality/v0.4-r1',
                           'workspace_root': str(self.root), 'index_ref': self.handoff['index_ref'],
                           'query_policy': self.handoff.get('source_query_policy', 'gtkg.qk.query/v2'),
                           'query': query, 'max_results': limit, 'max_tokens': 8000}}
            result = subprocess.run(
                [self.config['binary'], '--strict-exit', 'v2-op', 'graph.search',
                 '--profile', 'graph', '--request', '-', '--output', 'json'],
                input=json.dumps(request).encode(), cwd=str(self.root), stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=15, check=False)
            if result.returncode or len(result.stdout) > 4 * 1024 * 1024:
                raise ValueError('gtkg_query_failed')
            response = json.loads(result.stdout)
            identity = response['result']['source_identity']
            if identity.get('source_commit') != self.revision or identity.get('source_tree') != tree:
                raise ValueError('gtkg_response_identity_mismatch')
            validated = _validated_result(location, binding, response, limit)
            validated['adapter'] = {'kind': 'gtkg', 'binary_sha256': self.config['binary_sha256'],
                                    'handoff_sha256': self.config['handoff_sha256'],
                                    'index_ref': self.handoff['index_ref']}
            for item in validated['evidence']:
                item['adapter_kind'] = 'gtkg'
                item['execution_assurance'] = 'local_gtkg_graph_search'
                item['adapter_identity'] = validated['adapter']
            return validated
        except (ValueError, OSError, KeyError, TypeError, subprocess.TimeoutExpired):
            return {'status': 'partial', 'evidence': [], 'partial_sources': ['gtkg_or_source_unavailable'],
                    'index_revision': self.revision}
