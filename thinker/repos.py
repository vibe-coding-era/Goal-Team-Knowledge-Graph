"""Scope-isolated local Git registry and bounded reconciliation.

The service authenticates actors and serializes transactions; this module never
commits, authorizes by actor display name, starts a daemon, fetches or runs hooks.
Registry configuration is administrator-only. Registration authorizes regular
committed blobs on the explicit refs. `paths` only seeds Git lexical search; it
is not a subtree ACL. Reader operations cannot supply
adapter, path-root, binary, index or scope overrides. `search_context` is pure read.
"""
import hashlib
import json
import re
import time

from . import evidence


def init_db(db):
    statements = [
        '''CREATE TABLE IF NOT EXISTS tk_repos (
            scope TEXT NOT NULL, repo TEXT NOT NULL, location TEXT NOT NULL,
            common_dir TEXT NOT NULL, config TEXT NOT NULL, config_revision INTEGER NOT NULL,
            enabled INTEGER NOT NULL, removed INTEGER NOT NULL, health TEXT NOT NULL,
            last_polled REAL NOT NULL DEFAULT 0, last_success REAL NOT NULL DEFAULT 0,
            polls INTEGER NOT NULL DEFAULT 0, failures INTEGER NOT NULL DEFAULT 0,
            duplicates INTEGER NOT NULL DEFAULT 0, transitions INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(scope,repo))''',
        '''CREATE TABLE IF NOT EXISTS tk_refs (
            scope TEXT NOT NULL, repo TEXT NOT NULL, ref TEXT NOT NULL,
            observed_oid TEXT, indexed_oid TEXT, ref_generation INTEGER NOT NULL,
            transition_seq INTEGER NOT NULL, state TEXT NOT NULL,
            observed_at REAL NOT NULL, indexed_at REAL NOT NULL DEFAULT 0,
            pending_previous TEXT, PRIMARY KEY(scope,repo,ref))''',
        '''CREATE TABLE IF NOT EXISTS tk_repo_events (
            event_id TEXT PRIMARY KEY, scope TEXT NOT NULL, repo TEXT NOT NULL,
            ref TEXT NOT NULL, transition_seq INTEGER NOT NULL, payload TEXT NOT NULL,
            UNIQUE(scope,repo,ref,transition_seq))''',
        '''CREATE TABLE IF NOT EXISTS tk_source_evidence (
            scope TEXT NOT NULL, id TEXT NOT NULL, repo TEXT NOT NULL, ref TEXT NOT NULL,
            payload TEXT NOT NULL, PRIMARY KEY(scope,id))''',
    ]
    for statement in statements:
        db.execute(statement)


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def _repo_id(args):
    value = args.get('repo', args.get('repo_id'))
    if args.get('repo') is not None and args.get('repo_id') not in (None, value):
        raise ValueError('conflicting_repo_identity')
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', value):
        raise ValueError('invalid_repo_identity')
    return value


def _load(db, scope, repo, removed=False):
    row = db.execute('SELECT * FROM tk_repos WHERE scope=? AND repo=?', (scope, repo)).fetchone()
    if row is None or (row['removed'] and not removed):
        raise ValueError('repository_not_available_in_scope')
    return row


def _validate_ref(ref):
    if (not isinstance(ref, str) or len(ref) > 512
            or not ref.startswith(('refs/heads/', 'refs/tags/', 'refs/remotes/'))
            or any(c in ref for c in ('..', '@{', '\\', ' ', '~', '^', ':', '?', '*', '[', '\x00'))
            or any(ord(c) < 32 or ord(c) == 127 for c in ref)
            or ref.endswith(('/', '.', '.lock'))
            or any(not part or part.startswith('.') or part.endswith('.lock') for part in ref.split('/'))):
        raise ValueError('explicit_committed_ref_required')
    return ref


def _tips(row, config):
    location, common = evidence.repository_identity(row['location'])
    if location != row['location'] or common != row['common_dir']:
        raise ValueError('repository_identity_changed')
    raw = evidence.git(location, 'for-each-ref', '--format=%(refname)', *config['refs']).stdout
    present = set(raw.decode('utf-8').splitlines())
    tips = {}
    for ref in config['refs']:
        if ref in present:
            oid = evidence.git(location, 'rev-parse', '--verify', ref + '^{commit}').stdout.decode().strip()
            if not evidence.OID.fullmatch(oid):
                raise ValueError('invalid_ref_commit')
            tips[ref] = oid
        else:
            # Only a successful explicit enumeration establishes deletion.
            tips[ref] = None
    return tips


def _configuration(args, location):
    refs = args.get('refs', args.get('ref_rules'))
    if not isinstance(refs, list) or not 1 <= len(refs) <= 32 or len(set(refs)) != len(refs):
        raise ValueError('one_to_32_explicit_unique_refs_required')
    refs = sorted(_validate_ref(ref) for ref in refs)
    paths = args.get('paths', [])
    if not isinstance(paths, list) or len(paths) > 128:
        raise ValueError('invalid_search_seed_paths')
    paths = sorted(set(evidence.source_path(path) for path in paths))
    interval = args.get('poll_interval', 5)
    if type(interval) not in (int, float) or not 0 <= interval <= 86400:
        raise ValueError('invalid_poll_interval')
    adapter = args.get('adapter', {'kind': 'git'})
    if not isinstance(adapter, dict) or adapter.get('kind') not in ('git', 'gtkg', 'mock'):
        raise ValueError('invalid_adapter')
    adapter = dict(adapter)
    if adapter['kind'] == 'gtkg':
        reader = evidence.GTKGAdapter(adapter)
        source_root = reader.handoff.get('source_root')
        if source_root and evidence.repository_identity(source_root)[1] != evidence.repository_identity(location)[1]:
            raise ValueError('handoff_repository_mismatch')
        adapter = reader.config
    elif adapter['kind'] == 'mock':
        if not isinstance(adapter.get('response'), dict):
            raise ValueError('mock_response_required')
        if len(_json(adapter).encode()) > 1024 * 1024:
            raise ValueError('mock_fixture_over_budget')
    elif set(adapter) != {'kind'}:
        raise ValueError('git_adapter_does_not_accept_commands')
    return {'refs': refs, 'paths': paths, 'poll_interval': interval, 'adapter': adapter}


def _public_repo(db, row):
    now = time.time()
    config = json.loads(row['config'])
    refs = []
    for state in db.execute('SELECT * FROM tk_refs WHERE scope=? AND repo=? ORDER BY ref',
                            (row['scope'], row['repo'])):
        if state['ref'] not in config['refs']:
            continue
        refs.append({key: state[key] for key in ('ref', 'observed_oid', 'indexed_oid',
                     'ref_generation', 'transition_seq', 'state', 'observed_at', 'indexed_at')})
        refs[-1].update(index_behind=state['observed_oid'] != state['indexed_oid'],
                        indexing_lag_seconds=(max(0, now - state['observed_at'])
                                              if state['observed_oid'] != state['indexed_oid'] else 0))
    return {'repo': row['repo'], 'repo_id': row['repo'], 'location': row['location'],
            'common_dir': row['common_dir'], 'config_revision': row['config_revision'],
            'enabled': bool(row['enabled']), 'removed': bool(row['removed']), 'health': row['health'],
            'adapter_kind': config['adapter']['kind'], 'refs': refs,
            'last_polled': row['last_polled'], 'last_success': row['last_success'],
            'observation_lag_seconds': max(0, now - row['last_success']) if row['last_success'] else None,
            'counters': {key: row[key] for key in ('polls', 'failures', 'duplicates', 'transitions')},
            'failure_rate': row['failures'] / row['polls'] if row['polls'] else 0,
            'freshness_scope': 'last_successful_ref_observation; index_progress_separate'}


def current_binding(db, scope, repo, ref, source_revision=None):
    """Pure read; stamp only an enabled, currently observed and live Git revision."""
    row = _load(db, scope, repo)
    config = json.loads(row['config'])
    if not row['enabled'] or row['health'] != 'healthy' or ref not in config['refs']:
        raise ValueError('repository_paused_degraded_or_ref_not_allowed')
    state = db.execute('SELECT * FROM tk_refs WHERE scope=? AND repo=? AND ref=?',
                       (scope, repo, ref)).fetchone()
    if state is None or state['state'] != 'present' or not state['observed_oid']:
        raise ValueError('source_ref_unavailable')
    if source_revision is not None and source_revision != state['observed_oid']:
        raise ValueError('requested_revision_is_stale')
    if _tips(row, config)[ref] != state['observed_oid']:
        raise ValueError('source_changed_since_observation')
    return {'scope': scope, 'repo': repo, 'ref': ref, 'source_revision': state['observed_oid'],
            'observed_oid': state['observed_oid'], 'indexed_oid': state['indexed_oid'],
            'config_revision': row['config_revision'], 'ref_generation': state['ref_generation'],
            'transition_seq': state['transition_seq'], 'status': 'fresh',
            'index_status': 'fresh' if state['indexed_oid'] == state['observed_oid'] else 'pending'}


def validate_current(db, scope, item):
    try:
        if item.get('scope', scope) != scope or item.get('state', 'active') != 'active':
            return False
        binding = current_binding(db, scope, item['repo'], item['ref'], item['source_revision'])
        return all(type(item.get(key)) is int and item[key] == binding[key]
                   for key in ('config_revision', 'ref_generation'))
    except (ValueError, KeyError, TypeError, OSError):
        return False


def _remember(db, scope, items):
    for item in items:
        db.execute('INSERT OR IGNORE INTO tk_source_evidence(scope,id,repo,ref,payload) VALUES(?,?,?,?,?)',
                   (scope, item['id'], item['repo'], item['ref'], _json(item)))


def _refresh(db, scope, row, ref, old, binding):
    """New immutable Git evidence; never relabel old GTKG output as reindexed."""
    items = db.execute('SELECT payload FROM tk_source_evidence WHERE scope=? AND repo=? AND ref=? ORDER BY rowid DESC LIMIT 128',
                       (scope, row['repo'], ref)).fetchall()
    result, seen = [], set()
    for stored in items:
        item = json.loads(stored['payload'])
        if (item['source_revision'] != old or item.get('source_kind') not in ('git_source', 'gtkg_source')
                or item.get('config_revision') != binding['config_revision']):
            continue
        locator = item['locator']
        whole = item.get('read_policy') == 'whole_file'
        key = (locator['path'], 0 if whole else locator['byte_start'], None if whole else locator['byte_end'])
        if key in seen:
            continue
        seen.add(key)
        try:
            updated = evidence.read_source(row['location'], binding, *key)
            updated['refresh_origin'] = item['id']
            updated['refresh_reason'] = 'git_blob_revalidated_not_gtkg_reindexed'
            result.append(updated)
        except ValueError:
            # Disappeared/truncated paths do not manufacture replacement evidence.
            continue
    _remember(db, scope, result)
    return result


def _event(db, scope, row, ref, old, new, generation, sequence, kind):
    value = {'schema_version': 1, 'scope': scope, 'repo': row['repo'], 'repo_id': row['repo'],
             'ref': ref, 'previous_oid': old, 'observed_oid': new,
             'ref_generation': generation, 'config_revision': row['config_revision'],
             'transition_seq': sequence, 'kind': kind, 'recorded_at': time.time(),
             'history_gap': kind in ('force_push', 'history_unknown')}
    identity = [scope, row['repo'], ref, sequence, generation, row['config_revision'], old, new, kind]
    value['event_id'] = 'git-' + hashlib.sha256(_json(identity).encode()).hexdigest()
    db.execute('INSERT OR IGNORE INTO tk_repo_events(event_id,scope,repo,ref,transition_seq,payload) VALUES(?,?,?,?,?,?)',
               (value['event_id'], scope, row['repo'], ref, sequence, _json(value)))
    return value


def _poll(db, scope, repo, baseline=False):
    row = _load(db, scope, repo)
    if not row['enabled']:
        return {'status': 'stale', 'events': [], 'refreshed_evidence': [], 'partial_sources': ['paused']}
    config = json.loads(row['config'])
    now = time.time()
    db.execute('UPDATE tk_repos SET polls=polls+1,last_polled=? WHERE scope=? AND repo=?', (now, scope, repo))
    try:
        tips = _tips(row, config)
    except (ValueError, OSError, UnicodeError):
        db.execute("UPDATE tk_repos SET health='degraded',failures=failures+1 WHERE scope=? AND repo=?", (scope, repo))
        return {'status': 'partial', 'events': [], 'refreshed_evidence': [], 'partial_sources': ['repository_unavailable']}
    indexed = None
    partial = []
    if config['adapter']['kind'] == 'gtkg':
        try:
            indexed = evidence.GTKGAdapter(config['adapter']).revision
        except ValueError:
            partial.append('gtkg_handoff_unavailable')
    events, refreshed = [], []
    db.execute("UPDATE tk_repos SET health='healthy',last_success=? WHERE scope=? AND repo=?", (now, scope, repo))
    for ref, tip in tips.items():
        state = db.execute('SELECT * FROM tk_refs WHERE scope=? AND repo=? AND ref=?', (scope, repo, ref)).fetchone()
        if state is None:
            db.execute('INSERT INTO tk_refs(scope,repo,ref,observed_oid,indexed_oid,ref_generation,transition_seq,state,observed_at,indexed_at) VALUES(?,?,?,?,?,1,0,?,?,?)',
                       (scope, repo, ref, tip, indexed if indexed == tip else None,
                        'present' if tip else 'deleted', now, now if indexed == tip and tip else 0))
            continue
        old = state['observed_oid']
        generation, sequence = state['ref_generation'], state['transition_seq']
        if old == tip and not state['pending_previous']:
            db.execute('UPDATE tk_repos SET duplicates=duplicates+1 WHERE scope=? AND repo=?', (scope, repo))
            if indexed == tip and tip:
                db.execute('UPDATE tk_refs SET indexed_oid=?,indexed_at=? WHERE scope=? AND repo=? AND ref=?',
                           (tip, now, scope, repo, ref))
            continue
        prior = state['pending_previous'] or old
        pending = None
        if tip is None:
            kind, generation = 'deleted', generation + 1
        elif prior is None:
            kind, generation = 'created', generation + 1
        else:
            try:
                ancestry = evidence.git(row['location'], 'merge-base', '--is-ancestor', prior, tip, allowed=(0, 1))
                shallow = evidence.git(row['location'], 'rev-parse', '--is-shallow-repository').stdout.strip() == b'true'
                if ancestry.returncode == 0:
                    kind = 'fast_forward'
                elif shallow:
                    kind, pending = 'history_unknown', prior
                else:
                    kind, generation = 'force_push', generation + 1
            except ValueError:
                kind, pending = 'history_unknown', prior
        if pending:
            partial.append('history_incomplete')
            # Repeat unresolved ancestry checks without creating duplicate events.
            if state['pending_previous'] == pending and old == tip:
                continue
        sequence += 1
        index_value = tip if indexed == tip else state['indexed_oid']
        db.execute('UPDATE tk_refs SET observed_oid=?,indexed_oid=?,ref_generation=?,transition_seq=?,state=?,observed_at=?,indexed_at=?,pending_previous=? WHERE scope=? AND repo=? AND ref=?',
                   (tip, index_value, generation, sequence,
                    'pending' if pending else ('present' if tip else 'deleted'), now,
                    now if indexed == tip and tip else state['indexed_at'], pending, scope, repo, ref))
        event = _event(db, scope, row, ref, prior, tip, generation, sequence, kind)
        events.append(event)
        db.execute('UPDATE tk_repos SET transitions=transitions+1 WHERE scope=? AND repo=?', (scope, repo))
        if kind == 'fast_forward':
            binding = dict(scope=scope, repo=repo, ref=ref, source_revision=tip,
                           config_revision=row['config_revision'], ref_generation=generation,
                           transition_seq=sequence)
            refreshed.extend(_refresh(db, scope, row, ref, prior, binding))
    if baseline:
        # Registration establishes a baseline, then schedules the first watcher
        # observation immediately. Later ticks obey the configured interval.
        db.execute('UPDATE tk_repos SET last_polled=0 WHERE scope=? AND repo=?', (scope, repo))
    return {'status': 'partial' if partial else 'fresh', 'events': events,
            'refreshed_evidence': refreshed, 'partial_sources': sorted(set(partial))}


def _reader_args(args, allowed):
    if not isinstance(args, dict) or set(args) - set(allowed):
        raise ValueError('unsupported_reader_argument')


def search_context(db, scope, args):
    """No SQLite writes; the same local result can feed CLI or read-only MCP."""
    _reader_args(args, ('repo', 'repo_id', 'ref', 'source_revision', 'query', 'limit'))
    repo = _repo_id(args)
    row = _load(db, scope, repo)
    binding = current_binding(db, scope, repo, args.get('ref'), args.get('source_revision'))
    query, limit = args.get('query', ''), args.get('limit', 5)
    if not isinstance(query, str) or not query.strip() or len(query.encode()) > 4096:
        raise ValueError('bounded_nonempty_query_required')
    if type(limit) is not int or not 1 <= limit <= 20:
        raise ValueError('search_limit_out_of_bounds')
    config = json.loads(row['config'])
    adapter = config['adapter']
    if adapter['kind'] == 'gtkg':
        try:
            result = evidence.GTKGAdapter(adapter).search(row['location'], binding, query, limit)
        except ValueError:
            result = {'status': 'partial', 'evidence': [], 'partial_sources': ['gtkg_handoff_unavailable']}
    elif adapter['kind'] == 'mock':
        result = evidence.MockAdapter(adapter['response']).search(row['location'], binding, query, limit)
        result['adapter'] = {'kind': 'mock', 'execution_assurance': 'fixture_only'}
    else:
        found, omissions = [], []
        for path in config['paths']:
            try:
                raw = evidence.git_blob(row['location'], binding['source_revision'], path)
                text = raw.decode('utf-8')
                at = text.lower().find(query.lower())
                if at < 0:
                    continue
                first = max(0, at - 128)
                last = min(len(text), at + len(query) + 384)
                item = evidence.read_source(row['location'], binding, path,
                                            len(text[:first].encode()), len(text[:last].encode()))
                found.append(item)
                if len(found) == limit:
                    break
            except (ValueError, UnicodeError):
                omissions.append('source_unavailable_or_over_budget')
        result = {'status': 'partial' if omissions else 'fresh', 'evidence': found,
                  'partial_sources': sorted(set(omissions)),
                  'adapter': {'kind': 'git', 'scope': 'administrator_declared_paths_only'}}
    # Even an empty response must not claim freshness for a ref which moved while
    # the adapter was running. Revalidate the binding, not just returned rows.
    try:
        latest = current_binding(db, scope, repo, binding['ref'], binding['source_revision'])
        still_current = all(latest[key] == binding[key] for key in ('config_revision', 'ref_generation'))
    except ValueError:
        still_current = False
    if not still_current or any(not validate_current(db, scope, item) for item in result['evidence']):
        result.update(status='stale', evidence=[], partial_sources=['source_changed_during_read'])
    result.update(observed_oid=binding['observed_oid'], indexed_oid=binding['indexed_oid'],
                  ref_generation=binding['ref_generation'], config_revision=binding['config_revision'])
    return result


def tick(db):
    """One due repository per call. Caller provides its own connection/transaction."""
    now = time.time()
    rows = db.execute('SELECT * FROM tk_repos WHERE enabled=1 AND removed=0 ORDER BY last_polled,scope,repo').fetchall()
    for row in rows:
        if now - row['last_polled'] >= json.loads(row['config'])['poll_interval']:
            return {'processed': 1, 'scope': row['scope'], 'repo': row['repo'],
                    'result': _poll(db, row['scope'], row['repo'])}
    return {'processed': 0}


def dispatch(db, scope, actor, op, args):
    """`scope` and `actor` come only from authenticated service state, not args."""
    if not isinstance(scope, str) or not scope or not isinstance(actor, str) or not isinstance(args, dict):
        raise ValueError('invalid_dispatch_binding')
    if any(key in args for key in ('scope', 'actor', 'tenant_id', 'project_id', 'credential_ref')):
        raise ValueError('service_binding_override_forbidden')
    if op in ('repos.list', 'watch.status'):
        _reader_args(args, ('repo', 'repo_id'))
        rows = db.execute('SELECT * FROM tk_repos WHERE scope=? ORDER BY repo', (scope,)).fetchall()
        if args:
            repo = _repo_id(args)
            rows = [row for row in rows if row['repo'] == repo]
        result = {'repos': [_public_repo(db, row) for row in rows]}
        if op == 'watch.status':
            events = db.execute('SELECT payload FROM tk_repo_events WHERE scope=? ORDER BY rowid DESC LIMIT 100', (scope,)).fetchall()
            result['events'] = [json.loads(item['payload']) for item in reversed(events)
                                if not args or json.loads(item['payload'])['repo'] == repo]
        return result
    if op == 'repos.add':
        allowed = {'repo', 'repo_id', 'location', 'refs', 'ref_rules', 'paths', 'adapter', 'poll_interval'}
        if set(args) - allowed:
            raise ValueError('unsupported_repository_configuration')
        repo = _repo_id(args)
        location, common = evidence.repository_identity(args.get('location', ''))
        config = _configuration(args, location)
        old = db.execute('SELECT * FROM tk_repos WHERE scope=? AND repo=?', (scope, repo)).fetchone()
        revision = old['config_revision'] + 1 if old else 1
        if old:
            db.execute('UPDATE tk_repos SET location=?,common_dir=?,config=?,config_revision=?,enabled=1,removed=0,health=? WHERE scope=? AND repo=?',
                       (location, common, _json(config), revision, 'pending', scope, repo))
        else:
            count = db.execute('SELECT count(*) FROM tk_repos WHERE scope=? AND removed=0', (scope,)).fetchone()[0]
            if count >= 32:
                raise ValueError('repository_scope_quota_exceeded')
            db.execute('INSERT INTO tk_repos(scope,repo,location,common_dir,config,config_revision,enabled,removed,health) VALUES(?,?,?,?,?,?,1,0,?)',
                       (scope, repo, location, common, _json(config), revision, 'pending'))
        result = _poll(db, scope, repo, baseline=True)
        result['repo'] = _public_repo(db, _load(db, scope, repo))
        return result
    if op in ('repos.pause', 'repos.resume', 'repos.remove'):
        _reader_args(args, ('repo', 'repo_id'))
        repo = _repo_id(args)
        _load(db, scope, repo)
        enabled = op == 'repos.resume'
        removed = op == 'repos.remove'
        health = 'pending' if enabled else ('removed' if removed else 'paused')
        db.execute('UPDATE tk_repos SET enabled=?,removed=?,health=?,config_revision=config_revision+1,last_polled=0 WHERE scope=? AND repo=?',
                   (int(enabled), int(removed), health, scope, repo))
        return {'repo': _public_repo(db, _load(db, scope, repo, removed=True))}
    if op == 'watch.reconcile':
        _reader_args(args, ('repo', 'repo_id'))
        if args:
            return _poll(db, scope, _repo_id(args))
        rows = db.execute('SELECT repo FROM tk_repos WHERE scope=? AND removed=0 ORDER BY last_polled LIMIT 8', (scope,)).fetchall()
        results = [_poll(db, scope, row['repo']) for row in rows]
        return {'status': 'partial' if any(r['status'] != 'fresh' for r in results) else 'fresh',
                'events': [e for r in results for e in r['events']],
                'refreshed_evidence': [e for r in results for e in r['refreshed_evidence']],
                'partial_sources': sorted(set(p for r in results for p in r['partial_sources']))}
    if op == 'source.search':
        result = search_context(db, scope, args)
        _remember(db, scope, result['evidence'])
        return result
    if op == 'source.read':
        _reader_args(args, ('id', 'repo', 'repo_id', 'ref', 'source_revision', 'path', 'byte_start', 'byte_end'))
        if 'id' in args:
            if set(args) != {'id'}:
                raise ValueError('evidence_id_cannot_override_source_binding')
            stored = db.execute('SELECT payload FROM tk_source_evidence WHERE scope=? AND id=?', (scope, args['id'])).fetchone()
            if stored is None:
                raise ValueError('evidence_not_available_in_scope')
            item = json.loads(stored['payload'])
            if not validate_current(db, scope, item):
                raise ValueError('evidence_is_stale')
            return {'status': 'fresh', 'evidence': [item], 'partial_sources': []}
        repo = _repo_id(args)
        row = _load(db, scope, repo)
        binding = current_binding(db, scope, repo, args.get('ref'), args.get('source_revision'))
        item = evidence.read_source(row['location'], binding, args.get('path'),
                                    args.get('byte_start', 0), args.get('byte_end'))
        if not validate_current(db, scope, item):
            raise ValueError('source_changed_during_read')
        _remember(db, scope, [item])
        return {'status': 'fresh', 'evidence': [item], 'partial_sources': [],
                'observed_oid': binding['observed_oid'], 'indexed_oid': binding['indexed_oid']}
    raise ValueError('unsupported_repository_operation')
