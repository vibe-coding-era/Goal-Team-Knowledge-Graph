"""Replaceable, scoped memory projections. Never a source of authority.

The service owns authentication, admin permission checks and SQLite transactions.
No function commits the authority connection. Retain/forget and their outbox jobs
commit atomically together. Model reservations commit in a separate runtime ledger
before upstream I/O, including when the authority transaction later rolls back.
Hindsight HTTP contract: vectorize-io/hindsight v1.2.3 static/openapi.json.
"""

import hashlib
import contextlib
from datetime import datetime, timezone
import json
import math
import os
import re
import sqlite3
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


KINDS = {'world', 'experience', 'observation', 'mental_model'}
MAX_ATTEMPTS = 3
MAX_RECORDS = 1000
HINDSIGHT_VERSION = '1.2.3'
MODEL_LIMITS = {'weekly_model_operations': (1000, 0, 100000),
                'max_concurrent_model_operations': (2, 1, 16)}


class ModelBudgetUnavailable(ValueError):
    """No upstream request was authorized by the runtime operation gate."""


class AsyncOperationPending(ValueError):
    """A durable remote operation is not yet confirmed; polling is not failure."""


class SyncOperationUncertain(ValueError):
    """A synchronous write may still commit; neither retry nor deletion is safe."""


def _model_limits(config):
    result = {}
    for name, (default, minimum, maximum) in MODEL_LIMITS.items():
        value = config.get(name, default)
        if type(value) is not int or not minimum <= value <= maximum:
            raise ValueError('invalid model operation limit')
        result[name] = value
    return result


def _backend_identity(config):
    result = {key: value for key, value in config.items() if key not in MODEL_LIMITS}
    if result.get('backend') == 'hindsight':
        result.setdefault('retain_mode', 'sync')  # Persisted legacy configurations.
    return result


def _utc_week():
    year, week, _ = datetime.fromtimestamp(time.time(), timezone.utc).isocalendar()
    return '%04d-W%02d' % (year, week)


def _authority_path(db):
    path = next((row[2] for row in db.execute('PRAGMA database_list') if row[1] == 'main'), '') if db else ''
    if not path:
        raise ModelBudgetUnavailable('durable model ledger requires a file-backed authority database')
    return path


def _runtime_connect(path):
    # The service already owns a private directory. Never follow a substituted
    # ledger symlink or widen its access permissions; store no prompts or secrets.
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        mode = os.fstat(fd)
        if not stat.S_ISREG(mode.st_mode) or mode.st_mode & 0o077 or mode.st_uid != os.getuid():
            raise ModelBudgetUnavailable('model ledger must be a private regular file')
    finally:
        os.close(fd)
    ledger = sqlite3.connect(path, timeout=.25, isolation_level=None)
    try:
        ledger.execute('CREATE TABLE IF NOT EXISTS model_weeks(scope TEXT NOT NULL,utc_week TEXT NOT NULL,reserved_operations INTEGER NOT NULL,PRIMARY KEY(scope,utc_week))')
        ledger.execute('CREATE TABLE IF NOT EXISTS model_runs(id TEXT PRIMARY KEY,scope TEXT NOT NULL,utc_week TEXT NOT NULL,operation TEXT NOT NULL,owner_pid INTEGER NOT NULL,state TEXT NOT NULL,reserved_at REAL NOT NULL,finished_at REAL)')
        ledger.execute('CREATE INDEX IF NOT EXISTS model_active ON model_runs(scope,state)')
        ledger.execute('CREATE TABLE IF NOT EXISTS async_retains(scope TEXT NOT NULL,document_id TEXT NOT NULL,operation_id TEXT NOT NULL,payload_hash TEXT NOT NULL,state TEXT NOT NULL,PRIMARY KEY(scope,document_id))')
        ledger.execute('CREATE TABLE IF NOT EXISTS sync_retains(scope TEXT NOT NULL,document_id TEXT NOT NULL,payload_hash TEXT NOT NULL,state TEXT NOT NULL,PRIMARY KEY(scope,document_id))')
        return ledger
    except Exception:
        ledger.close()
        raise


def _owner_exited(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        pass
    return False


def _model_in_flight(ledger, scope, retry_operation=None):
    table = ledger.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='async_retains'").fetchone()
    pending = {row[0] for row in ledger.execute('SELECT operation_id FROM async_retains WHERE scope=? AND state="submitted"', (scope,))} if table else set()
    sync_table = ledger.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='sync_retains'").fetchone()
    uncertain = {row[0] for row in ledger.execute('SELECT document_id FROM sync_retains WHERE scope=? AND state="sending"', (scope,))} if sync_table else set()
    # A submitted async job outlives its submitting process/HTTP request. Count
    # it once, not once for the durable job and again for the current POST.
    represented = {'async-retain:' + operation for operation in pending} | {'sync-retain:' + document for document in uncertain}
    active = sum(1 for row in ledger.execute('SELECT operation FROM model_runs WHERE scope=? AND state="active"', (scope,))
                 if row[0] not in represented)
    return active + len(pending - {retry_operation}) + len(uncertain)


@contextlib.contextmanager
def _model_operation(db, scope, config, operation, async_operation=None, sync_document=None):
    """Reserve one potential model operation, never a currency/token estimate.

    A short independent SQLite transaction serializes all processes/threads.
    There is deliberately no time-only lease expiry: a slow live request must
    keep its slot. Dead owners are reclaimed; weekly reservations never refund.
    """
    ledger = None
    ticket = uuid.uuid4().hex
    try:
        authority = _authority_path(db)
        ledger = _runtime_connect(authority + '.model-usage.sqlite')
        ledger.execute('BEGIN IMMEDIATE')
        # Read committed policy independently of a possibly old caller snapshot.
        # This never writes/commits the caller's authority transaction.
        uri = 'file:' + urllib.parse.quote(authority, safe='/') + '?mode=ro'
        with contextlib.closing(sqlite3.connect(uri, uri=True, timeout=.25)) as current:
            row = current.execute('SELECT data FROM memory_config WHERE scope=?', (scope,)).fetchone()
        latest = json.loads(row[0]) if row else {'backend': 'local'}
        if latest.get('backend') != 'hindsight' or _backend_identity(latest) != _backend_identity(config):
            raise ModelBudgetUnavailable('model backend configuration changed')
        limits = _model_limits(latest)
        now, week = time.time(), _utc_week()
        for pid, in ledger.execute('SELECT DISTINCT owner_pid FROM model_runs WHERE scope=? AND state="active"', (scope,)).fetchall():
            if _owner_exited(pid):
                ledger.execute('UPDATE model_runs SET state="abandoned",finished_at=? WHERE scope=? AND owner_pid=? AND state="active"', (now, scope, pid))
        row = ledger.execute('SELECT reserved_operations FROM model_weeks WHERE scope=? AND utc_week=?', (scope, week)).fetchone()
        used = row[0] if row else 0
        active = _model_in_flight(ledger, scope, async_operation)
        if used >= limits['weekly_model_operations']:
            ledger.commit()  # Persist dead-owner cleanup even when admission fails.
            raise ModelBudgetUnavailable('weekly model operation limit reached')
        if active >= limits['max_concurrent_model_operations']:
            ledger.commit()
            raise ModelBudgetUnavailable('concurrent model operation limit reached')
        ledger.execute('INSERT INTO model_weeks VALUES(?,?,1) ON CONFLICT(scope,utc_week) DO UPDATE SET reserved_operations=reserved_operations+1', (scope, week))
        ledger.execute('INSERT INTO model_runs VALUES(?,?,?,?,?,?,?,NULL)',
                       (ticket, scope, week, ('async-retain:' + async_operation if async_operation else
                                             'sync-retain:' + sync_document if sync_document else operation),
                        os.getpid(), 'active', now))
        ledger.commit()
    except (OSError, sqlite3.Error, ValueError) as error:
        if ledger is not None:
            ledger.close()  # Any uncommitted reservation is rolled back.
        if isinstance(error, ModelBudgetUnavailable):
            raise
        raise ModelBudgetUnavailable('model operation ledger unavailable') from None
    try:
        yield
    finally:
        try:
            ledger.execute('UPDATE model_runs SET state="finished",finished_at=? WHERE id=?', (time.time(), ticket))
        except sqlite3.Error:
            # Keeping an uncertain slot occupied is safer than permitting excess
            # requests. A subsequent confirmed process exit permits recovery.
            raise ModelBudgetUnavailable('model operation completion unconfirmed') from None
        finally:
            ledger.close()


def _model_usage(db, scope):
    row = db.execute('SELECT data FROM memory_config WHERE scope=?', (scope,)).fetchone()
    config = json.loads(row[0]) if row else {'backend': 'local'}
    result = dict(_model_limits(config), unit='reserved_model_operations', utc_week=_utc_week(),
                  reserved_operations=0, in_flight=0, monetary_cost='not_observed')
    try:
        authority = _authority_path(db)
        path = authority + '.model-usage.sqlite'
        if not os.path.exists(path):
            return result
        uri = 'file:' + urllib.parse.quote(path, safe='/') + '?mode=ro'
        with contextlib.closing(sqlite3.connect(uri, uri=True, timeout=.25)) as ledger:
            row = ledger.execute('SELECT reserved_operations FROM model_weeks WHERE scope=? AND utc_week=?', (scope, result['utc_week'])).fetchone()
            result['reserved_operations'] = row[0] if row else 0
            result['in_flight'] = _model_in_flight(ledger, scope)
    except ModelBudgetUnavailable:
        if config['backend'] != 'local':
            result['available'] = False
    except sqlite3.Error:
        result['available'] = False
    return result


def init_db(db):
    for statement in (
        'CREATE TABLE IF NOT EXISTS memory_config(scope TEXT PRIMARY KEY,data TEXT NOT NULL)',
        'CREATE TABLE IF NOT EXISTS memory_refs(scope TEXT NOT NULL,id TEXT NOT NULL,data TEXT NOT NULL,lifecycle TEXT NOT NULL,backend_status TEXT NOT NULL,document_id TEXT NOT NULL,PRIMARY KEY(scope,id))',
        'CREATE TABLE IF NOT EXISTS memory_jobs(scope TEXT NOT NULL,id TEXT NOT NULL,kind TEXT NOT NULL,status TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,error TEXT,PRIMARY KEY(scope,id,kind))',
        'CREATE TABLE IF NOT EXISTS memory_local(scope TEXT NOT NULL,document_id TEXT NOT NULL,content TEXT NOT NULL,metadata TEXT NOT NULL,PRIMARY KEY(scope,document_id))',
        'CREATE TABLE IF NOT EXISTS memory_candidates(scope TEXT NOT NULL,id TEXT NOT NULL,data TEXT NOT NULL,PRIMARY KEY(scope,id))',
        'CREATE TABLE IF NOT EXISTS memory_schedule(scope TEXT PRIMARY KEY,last_run REAL NOT NULL DEFAULT 0,next_run REAL NOT NULL DEFAULT 0)',
        'CREATE TABLE IF NOT EXISTS timeline_reads(scope TEXT NOT NULL,actor TEXT NOT NULL,task TEXT NOT NULL,repo TEXT NOT NULL,ref TEXT NOT NULL,read_cursor INTEGER NOT NULL,updated_at REAL NOT NULL,PRIMARY KEY(scope,actor,task,repo,ref))',
    ):
        db.execute(statement)


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _id(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,159}', value):
        raise ValueError('invalid memory identifier')
    return value


def _text(value, maximum=20000):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValueError('invalid memory text')
    return value


def contains_secret(text):
    """Pure conservative quarantine shared by model and memory boundaries."""
    return bool(re.search(r'(?i)(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:api[_-]?key|password|secret|token)[\"\x27]?\s*[:=]\s*[\"\x27]?\S+|\bsk-[A-Za-z0-9_-]{16,})', text))


def _record(db, scope, memory_id):
    row = db.execute('SELECT data,lifecycle,backend_status,document_id FROM memory_refs WHERE scope=? AND id=?',
                     (scope, _id(memory_id))).fetchone()
    if not row:
        raise ValueError('memory unavailable')
    data = json.loads(row[0])
    data.update(lifecycle=row[1], backend_status=row[2], document_id=row[3])
    return data


def _materialize(db, scope, record):
    """Read canonical content only after the core's live revision and source gates."""
    from . import core
    if record.get('review_after', float('inf')) <= time.time():
        raise ValueError('memory review expired')
    evidence_ids = record.get('evidence_ids', [])
    if record.get('judgment_revision'):
        judgment = core.get_live_judgment(db, scope, record['judgment_revision'])
        if not set(evidence_ids).issubset(set(judgment['supports'] + judgment['contradicts'])):
            raise ValueError('memory evidence mismatch')
        evidence_ids = judgment['supports'] + judgment['contradicts']
        content = judgment['claim']
    else:
        if not evidence_ids:
            raise ValueError('independent evidence required')
        evidence = [core.get_evidence(db, scope, eid) for eid in evidence_ids]
        content = '\n'.join(item['text'] for item in evidence)
    # Validate explicitly bound references even when a judgment is available.
    for eid in evidence_ids:
        core.get_evidence(db, scope, eid)
    if len(content) > 20000:
        raise ValueError('projection content exceeds budget')
    # Deliberately conservative quarantine, including common credential formats.
    if contains_secret(content):
        raise ValueError('projection quarantined by secret filter')
    return {'content': content, 'evidence_ids': evidence_ids,
            'judgment_revision': record.get('judgment_revision')}


class LocalBackend:
    """Deterministic local test/production fallback; no language model calls."""

    def __init__(self, db, scope):
        self.db, self.scope = db, scope

    def setup(self):
        return None

    def retain(self, document_id, content, metadata):
        self.db.execute('INSERT INTO memory_local VALUES(?,?,?,?) ON CONFLICT(scope,document_id) DO UPDATE SET content=excluded.content,metadata=excluded.metadata',
                        (self.scope, document_id, content, _json(metadata)))

    def recall(self, query):
        terms = query.lower().split()
        rows = self.db.execute('SELECT document_id,content FROM memory_local WHERE scope=? ORDER BY document_id', (self.scope,)).fetchall()
        return [{'document_id': row[0], 'text': row[1]} for row in rows
                if not terms or any(term in row[1].lower() for term in terms)]

    def reflect(self, query):
        return '候选：请人工核对已绑定的项目证据，再决定是否提出新判断。'

    def forget(self, document_id):
        self.db.execute('DELETE FROM memory_local WHERE scope=? AND document_id=?', (self.scope, document_id))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise ValueError('memory backend redirect denied')


class HindsightBackend:
    """Explicit fixed-version HTTP adapter. Logical Banks do not replace auth."""

    def __init__(self, config, scope, db=None):
        self.config = dict(config)
        self.db, self.scope = db, scope
        _model_limits(config)
        self.retain_mode = config.get('retain_mode', 'sync')
        if self.retain_mode not in ('sync', 'async'):
            raise ValueError('invalid retain mode')
        if config.get('version') != HINDSIGHT_VERSION or config.get('processing_opt_in') is not True:
            raise ValueError('Hindsight 1.2.3 and explicit processing opt-in required')
        url = config.get('url', '')
        parsed = urllib.parse.urlsplit(url)
        local = parsed.hostname in ('localhost', '127.0.0.1', '::1')
        if (parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username
                or parsed.password or parsed.query or parsed.fragment or parsed.path not in ('', '/')):
            raise ValueError('invalid backend endpoint')
        if not local and (parsed.scheme != 'https' or config.get('remote_opt_in') is not True):
            raise ValueError('remote backend requires HTTPS and explicit remote opt-in')
        key_env = config.get('api_key_env', '')
        if key_env and not re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}', key_env):
            raise ValueError('use a credential environment reference')
        if not local and not key_env:
            raise ValueError('remote backend authentication reference required')
        self.url = url.rstrip('/')
        self.bank = 'thinker-' + hashlib.sha256(scope.encode()).hexdigest()
        self.path = '/v1/default/banks/' + self.bank
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())

    def _request(self, method, path, payload=None, allow_missing=False):
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
        key_env = self.config.get('api_key_env')
        if key_env:
            key = os.environ.get(key_env)
            if not key:
                raise ValueError('memory backend credential is unavailable')
            headers['Authorization'] = 'Bearer ' + key
        body = _json(payload).encode() if payload is not None else None
        request = urllib.request.Request(self.url + path, data=body, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=60 if path.endswith('/reflect') else 2) as response:
                raw = response.read(2 * 1024 * 1024 + 1)
                if len(raw) > 2 * 1024 * 1024:
                    raise ValueError('memory response exceeds budget')
                result = json.loads(raw) if raw else {}
                if not isinstance(result, dict):
                    raise ValueError('invalid memory response')
                return result
        except urllib.error.HTTPError as error:
            if allow_missing and error.code == 404:
                return None
            raise OSError('memory backend HTTP failure') from None
        except (urllib.error.URLError, TimeoutError, UnicodeError, json.JSONDecodeError):
            raise OSError('memory backend unavailable') from None

    def setup(self):
        document = self._request('GET', '/openapi.json')
        if document.get('info', {}).get('version') != HINDSIGHT_VERSION:
            raise ValueError('memory backend version mismatch')
        self._request('PUT', self.path, {})

    def _model_request(self, operation, path, payload):
        with _model_operation(self.db, self.scope, self.config, operation):
            return self._request('POST', path, payload)

    def _operation_id(self, document_id):
        return str(uuid.uuid5(uuid.NAMESPACE_URL, _json(['thinker-retain-v1', self.scope, document_id])))

    def _sync_record(self, document_id, state=None, payload_hash=None):
        try:
            with contextlib.closing(_runtime_connect(_authority_path(self.db) + '.model-usage.sqlite')) as ledger:
                ledger.execute('BEGIN IMMEDIATE')
                row = ledger.execute('SELECT payload_hash,state FROM sync_retains WHERE scope=? AND document_id=?',
                                     (self.scope, document_id)).fetchone()
                if row and payload_hash is not None and row[0] != payload_hash:
                    raise ValueError('sync retain payload mismatch')
                if state is not None:
                    if row and row[1] == 'deleted' and state != 'deleted':
                        raise ValueError('sync retain was deleted')
                    if row:
                        ledger.execute('UPDATE sync_retains SET state=? WHERE scope=? AND document_id=?',
                                       (state, self.scope, document_id))
                    elif payload_hash is not None:
                        ledger.execute('INSERT INTO sync_retains VALUES(?,?,?,?)',
                                       (self.scope, document_id, payload_hash, state))
                    else:
                        raise ValueError('sync retain intent unavailable')
                ledger.commit()
                return {'payload_hash': row[0], 'state': row[1]} if row else None
        except (OSError, sqlite3.Error):
            raise SyncOperationUncertain('sync retain ledger unavailable') from None

    def _async_record(self, document_id, state=None, payload_hash=None):
        """Survives authority rollback and lost HTTP acknowledgements.

        The durable intent precedes POST. Otherwise a timeout followed by forget
        could delete before a late request reaches the server and recreates data.
        """
        try:
            with contextlib.closing(_runtime_connect(_authority_path(self.db) + '.model-usage.sqlite')) as ledger:
                ledger.execute('BEGIN IMMEDIATE')
                row = ledger.execute('SELECT operation_id,payload_hash,state FROM async_retains WHERE scope=? AND document_id=?',
                                     (self.scope, document_id)).fetchone()
                if row and (row[0] != self._operation_id(document_id) or (payload_hash is not None and row[1] != payload_hash)):
                    raise ValueError('async retain identity or payload mismatch')
                if state is not None:
                    if row and row[2] == 'deleted' and state != 'deleted':
                        raise ValueError('async retain was deleted')
                    if row:
                        ledger.execute('UPDATE async_retains SET state=? WHERE scope=? AND document_id=?',
                                       (state, self.scope, document_id))
                    elif payload_hash is not None:
                        ledger.execute('INSERT INTO async_retains VALUES(?,?,?,?,?)',
                                       (self.scope, document_id, self._operation_id(document_id), payload_hash, state))
                    else:
                        raise ValueError('async retain intent unavailable')
                ledger.commit()
                return {'operation_id': row[0], 'payload_hash': row[1], 'state': row[2]} if row else None
        except (OSError, sqlite3.Error):
            raise ValueError('async retain ledger unavailable') from None

    def _operation_status(self, document_id):
        operation_id = self._operation_id(document_id)
        result = self._request('GET', self.path + '/operations/' + operation_id, allow_missing=True)
        if result is None:
            return 'not_found'
        if (result.get('operation_id') != operation_id or result.get('id', operation_id) not in (None, operation_id)):
            raise ValueError('async operation identity mismatch')
        status = result.get('status')
        if status == 'not_found':
            return status
        operation_type = result.get('operation_type')
        if operation_type not in ('retain', 'batch_retain') or result.get('task_type', operation_type) not in (None, operation_type):
            raise ValueError('async operation is not retain')
        if status in ('pending', 'processing', 'cancelled'):
            # v1.2.3 cancellation is cooperative: cancelled can still be writing
            # a batch. It is not proof that a compensating delete is safe yet.
            raise AsyncOperationPending('async retain not quiescent')
        if status not in ('completed', 'failed') or result.get('next_retry_at'):
            raise AsyncOperationPending('async retain completion unknown')
        try:
            completed = datetime.fromisoformat(result['completed_at'].replace('Z', '+00:00'))
            if completed.tzinfo is None:
                raise ValueError('missing timezone')
        except (KeyError, TypeError, ValueError, AttributeError):
            raise AsyncOperationPending('async retain completion timestamp unavailable') from None
        children = result.get('child_operations') or []
        if not isinstance(children, list) or any(not isinstance(child, dict) or
                child.get('status') not in (('completed',) if status == 'completed' else ('completed', 'failed'))
                for child in children):
            raise AsyncOperationPending('async child operations not completed')
        return status

    def retain(self, document_id, content, metadata):
        payload = {'async': self.retain_mode == 'async', 'items': [{'content': content,
                   'document_id': document_id, 'update_mode': 'replace',
                   'metadata': {key: str(value) for key, value in metadata.items()}, 'tags': [self.bank]}]}
        if self.retain_mode == 'async':
            payload['operation_id'] = self._operation_id(document_id)
            fingerprint = hashlib.sha256(_json(payload).encode()).hexdigest()
            record = self._async_record(document_id, payload_hash=fingerprint)
            if record and record['state'] == 'deleted':
                raise ValueError('async retain was deleted')
            status = self._operation_status(document_id)
            if status == 'completed':
                if not record:
                    raise ValueError('async completion has no local submission intent')
                self._async_record(document_id, 'completed')
                return
            if status == 'failed':
                if record:
                    self._async_record(document_id, 'failed')
                raise ValueError('async retain failed')
            if record and record['state'] == 'completed':
                raise AsyncOperationPending('previous async completion no longer queryable')
            # A retry after 404/not_found reuses the exact caller UUID and payload.
            # The official endpoint returns the original operation, never new work.
            with _model_operation(self.db, self.scope, self.config, 'retain', payload['operation_id']):
                self._async_record(document_id, 'submitted', fingerprint)
                try:
                    result = self._request('POST', self.path + '/memories', payload)
                except OSError:
                    raise AsyncOperationPending('async retain submission acknowledgement unknown') from None
            if (result.get('success') is not True or result.get('async') is not True
                    or result.get('operation_id') != payload['operation_id']
                    or result.get('bank_id') != self.bank or result.get('items_count') != 1
                    or result.get('operation_ids') not in (None, [payload['operation_id']])):
                raise ValueError('async retain acknowledgement mismatch')
            raise AsyncOperationPending('async retain submitted; awaiting completion')
        fingerprint = hashlib.sha256(_json(payload).encode()).hexdigest()
        record = self._sync_record(document_id, payload_hash=fingerprint)
        if record:
            if record['state'] == 'confirmed':
                return
            if record['state'] == 'deleted':
                raise ValueError('sync retain was deleted')
            raise SyncOperationUncertain('previous sync retain outcome unknown; manual bank isolation required')
        with _model_operation(self.db, self.scope, self.config, 'retain', sync_document=document_id):
            # A denied reservation creates no delivery intent. Once admitted,
            # intent commits before I/O and survives an authority rollback.
            self._sync_record(document_id, 'sending', fingerprint)
            try:
                result = self._request('POST', self.path + '/memories', payload)
            except (OSError, ValueError):
                raise SyncOperationUncertain('sync retain acknowledgement unavailable') from None
            if result.get('success') is not True or result.get('async') is not False:
                raise SyncOperationUncertain('memory retain not synchronously confirmed')
            self._sync_record(document_id, 'confirmed')

    def recall(self, query):
        result = self._model_request('recall', self.path + '/memories/recall',
                               {'query': query or 'project knowledge', 'budget': 'low', 'max_tokens': 2048,
                                'types': ['world', 'experience'], 'tags': [self.bank], 'tags_match': 'all_strict'})
        rows = result.get('results')
        if not isinstance(rows, list):
            raise ValueError('invalid recall results')
        return rows

    def reflect(self, query):
        result = self._model_request('reflect', self.path + '/reflect',
                               {'query': query, 'budget': 'low', 'max_tokens': 1024,
                                'include': {'facts': {}}, 'tags': [self.bank], 'tags_match': 'all_strict',
                                'exclude_mental_models': True})
        return _text(result.get('text'), 20000)

    def forget(self, document_id):
        async_record = None
        sync_record = None
        if self.retain_mode == 'sync':
            sync_record = self._sync_record(document_id)
            if sync_record and sync_record['state'] == 'sending':
                raise SyncOperationUncertain('sync write may still arrive; remote deletion not confirmed')
        if self.retain_mode == 'async':
            async_record = self._async_record(document_id)
            status = self._operation_status(document_id)
            if status == 'not_found' and async_record and async_record['state'] != 'deleted':
                raise AsyncOperationPending('submitted async retain is not yet observable')
            if async_record and status in ('completed', 'failed') and async_record['state'] != 'deleted':
                self._async_record(document_id, status)
        path = self.path + '/documents/' + urllib.parse.quote(document_id, safe='')
        result = self._request('DELETE', path, allow_missing=True)
        if result and result.get('success') is not True:
            raise ValueError('memory deletion not confirmed')
        # HTTP success alone is insufficient, including asynchronous/lying adapters.
        remaining = self._request('GET', path, allow_missing=True)
        if remaining is not None:
            raise ValueError('memory deletion readback still contains source')
        if async_record:
            self._async_record(document_id, 'deleted')
        if sync_record:
            self._sync_record(document_id, 'deleted')


def _backend(db, scope):
    row = db.execute('SELECT data FROM memory_config WHERE scope=?', (scope,)).fetchone()
    config = json.loads(row[0]) if row else {'backend': 'local'}
    if config['backend'] == 'local':
        return LocalBackend(db, scope)
    return HindsightBackend(config, scope, db)


def _setup(db, scope, args):
    name = args.get('backend')
    if name not in ('local', 'hindsight'):
        raise ValueError('unsupported memory backend')
    allowed = {'backend', 'url', 'version', 'processing_opt_in', 'remote_opt_in', 'api_key_env', 'retain_mode'} | set(MODEL_LIMITS)
    if set(args) - allowed:
        raise ValueError('unsupported backend configuration')
    config = {key: value for key, value in args.items() if key in allowed}
    previous = db.execute('SELECT data FROM memory_config WHERE scope=?', (scope,)).fetchone()
    old_config = json.loads(previous[0]) if previous else {}
    if name == 'hindsight' and 'retain_mode' not in config:
        config['retain_mode'] = old_config.get('retain_mode', 'sync') if old_config.get('backend') == 'hindsight' else 'async'
    limits = _model_limits(config)
    if db.execute('SELECT 1 FROM memory_refs WHERE scope=? LIMIT 1', (scope,)).fetchone():
        old = db.execute('SELECT data FROM memory_config WHERE scope=?', (scope,)).fetchone()
        if _backend_identity(config) != _backend_identity(json.loads(old[0]) if old else {'backend': 'local'}):
            raise ValueError('backend change requires a separate migration; existing projections retained')
    backend = LocalBackend(db, scope) if name == 'local' else HindsightBackend(config, scope, db)
    backend.setup()
    db.execute('INSERT INTO memory_config VALUES(?,?) ON CONFLICT(scope) DO UPDATE SET data=excluded.data',
               (scope, _json(config)))
    return {'backend': name, 'version': HINDSIGHT_VERSION if name == 'hindsight' else 'deterministic-1',
            'ready': True, 'authoritative': False, 'model_limits': limits}


def _retain(db, scope, actor, args):
    if args.get('consent') is not True or args.get('data_class') not in ('public', 'internal'):
        raise ValueError('explicit consent and permitted data classification required')
    memory_id = _id(args.get('id'))
    if args.get('kind') not in KINDS:
        raise ValueError('invalid memory kind')
    evidence_ids = args.get('evidence_ids', [])
    if not isinstance(evidence_ids, list) or len(evidence_ids) > 64:
        raise ValueError('invalid memory evidence')
    evidence_ids = [_id(eid) for eid in evidence_ids]
    if len(evidence_ids) != len(set(evidence_ids)):
        raise ValueError('duplicate memory evidence')
    revision = args.get('judgment_revision')
    if revision is not None:
        _id(revision)
    review_after = args.get('review_after', time.time() + 86400 * 30)
    if isinstance(review_after, bool) or not isinstance(review_after, (float, int)) or not math.isfinite(review_after) or review_after <= time.time():
        raise ValueError('invalid memory review deadline')
    data = {'id': memory_id, 'kind': args['kind'], 'judgment_revision': revision,
            'evidence_ids': evidence_ids, 'data_class': args['data_class'], 'consent_actor': actor,
            'review_after': review_after}
    existing = db.execute('SELECT data,lifecycle,backend_status,document_id FROM memory_refs WHERE scope=? AND id=?',
                          (scope, memory_id)).fetchone()
    if existing:
        previous = json.loads(existing[0])
        if existing[1] != 'active' or any(previous.get(key) != data[key] for key in
                ('kind', 'judgment_revision', 'evidence_ids', 'data_class')):
            raise ValueError('memory immutable or forgotten')
        return {'id': memory_id, 'status': existing[2], 'authoritative': False}
    count = db.execute('SELECT COUNT(*) FROM memory_refs WHERE scope=? AND lifecycle="active"', (scope,)).fetchone()[0]
    if count >= MAX_RECORDS:
        raise ValueError('project memory quota exceeded')
    _materialize(db, scope, data)
    document_id = hashlib.sha256(_json([scope, memory_id, revision, evidence_ids]).encode()).hexdigest()
    db.execute('INSERT INTO memory_refs VALUES(?,?,?,?,?,?)', (scope, memory_id, _json(data), 'active', 'pending', document_id))
    db.execute('INSERT INTO memory_jobs(scope,id,kind,status) VALUES(?,?,?,?)', (scope, memory_id, 'retain', 'pending'))
    db.execute('INSERT INTO memory_schedule(scope) VALUES(?) ON CONFLICT(scope) DO NOTHING', (scope,))
    return {'id': memory_id, 'status': 'pending', 'authoritative': False}


def _forget(db, scope, memory_id, lifecycle='forgotten'):
    record = _record(db, scope, memory_id)
    if record['lifecycle'] != 'active' and record['backend_status'] == 'deleted':
        return {'id': record['id'], 'lifecycle': record['lifecycle'], 'status': 'deleted',
                'backup_deletion': 'not_performed'}
    db.execute('UPDATE memory_refs SET lifecycle=?,backend_status=? WHERE scope=? AND id=?',
               (lifecycle, 'pending_delete', scope, memory_id))
    # An old retain delivery can never overtake this tombstone.
    db.execute('UPDATE memory_jobs SET status="cancelled" WHERE scope=? AND id=? AND kind="retain"', (scope, memory_id))
    db.execute('INSERT INTO memory_jobs(scope,id,kind,status) VALUES(?,?,?,?) ON CONFLICT(scope,id,kind) DO NOTHING',
               (scope, memory_id, 'forget', 'pending'))
    db.execute('INSERT INTO memory_schedule(scope) VALUES(?) ON CONFLICT(scope) DO UPDATE SET next_run=0', (scope,))
    return {'id': record['id'], 'lifecycle': lifecycle, 'status': 'pending_delete',
            'backup_deletion': 'not_performed'}


def invalidate(db, scope):
    """Block invalid projections and enqueue compensating deletion; no I/O/commit."""
    invalidated = 0
    for row in db.execute('SELECT id FROM memory_refs WHERE scope=? AND lifecycle="active"', (scope,)).fetchall():
        try:
            _materialize(db, scope, _record(db, scope, row[0]))
        except ValueError:
            _forget(db, scope, row[0], 'invalid')
            invalidated += 1
    return {'invalidated': invalidated}


def tick(db):
    """One fair scoped job per tick, persisted backoff; caller owns transaction."""
    now = time.time()
    row = db.execute('SELECT s.scope FROM memory_schedule s WHERE s.next_run<=? AND EXISTS (SELECT 1 FROM memory_jobs j WHERE j.scope=s.scope AND j.status="pending") ORDER BY s.last_run,s.scope LIMIT 1', (now,)).fetchone()
    if not row:
        return {'completed': 0, 'failed': 0, 'partial': False}
    scope = row[0]
    result = _project(db, scope, limit=1)
    attempts = db.execute('SELECT COALESCE(MAX(attempts),0) FROM memory_jobs WHERE scope=? AND status="pending"', (scope,)).fetchone()[0]
    db.execute('UPDATE memory_schedule SET last_run=?,next_run=? WHERE scope=?',
               (now, now + max(5, 2 ** min(attempts, 6)), scope))
    return result


def _project(db, scope, limit=50):
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
        raise ValueError('invalid projection limit')
    # Sweep all active references before remote writes; deletion-only changes need no new content.
    invalidate(db, scope)
    backend = _backend(db, scope)
    completed, failed, budget_denied, awaiting, sync_uncertain = 0, 0, False, 0, 0
    jobs = db.execute('SELECT id,kind,attempts FROM memory_jobs WHERE scope=? AND status="pending" ORDER BY CASE kind WHEN "forget" THEN 0 ELSE 1 END,id LIMIT ?',
                       (scope, limit)).fetchall()
    deadline = time.monotonic() + 4
    for memory_id, kind, attempts in jobs:
        if time.monotonic() > deadline:
            break
        record = _record(db, scope, memory_id)
        try:
            if kind == 'forget':
                backend.forget(record['document_id'])
                state = 'deleted'
            elif record['lifecycle'] != 'active':
                db.execute('UPDATE memory_jobs SET status="cancelled" WHERE scope=? AND id=? AND kind=?', (scope, memory_id, kind))
                continue
            else:
                current = _materialize(db, scope, record)
                backend.retain(record['document_id'], current['content'], {'kind': record['kind'],
                                'memory_id': memory_id, 'judgment_revision': record.get('judgment_revision', '')})
                try:
                    _materialize(db, scope, record)
                except ValueError:
                    _forget(db, scope, memory_id, 'invalid')
                    continue
                # A retry after a lost local ack repeats the same document ID in replace mode.
                state = 'ready'
            db.execute('UPDATE memory_jobs SET attempts=attempts+1,status="done",error=NULL WHERE scope=? AND id=? AND kind=?', (scope, memory_id, kind))
            db.execute('UPDATE memory_refs SET backend_status=? WHERE scope=? AND id=?', (state, scope, memory_id))
            completed += 1
        except SyncOperationUncertain:
            db.execute('UPDATE memory_jobs SET error="sync write uncertain; manual bank isolation required" WHERE scope=? AND id=? AND kind=?', (scope, memory_id, kind))
            sync_uncertain += 1
        except AsyncOperationPending:
            db.execute('UPDATE memory_jobs SET error="async operation awaiting confirmation" WHERE scope=? AND id=? AND kind=?', (scope, memory_id, kind))
            awaiting += 1
        except ModelBudgetUnavailable:
            # No request was admitted: do not consume the retry/dead-letter budget.
            db.execute('UPDATE memory_jobs SET error="model operation budget unavailable" WHERE scope=? AND id=? AND kind=?', (scope, memory_id, kind))
            failed += 1
            budget_denied = True
        except (OSError, ValueError):
            status = 'dead' if attempts + 1 >= MAX_ATTEMPTS else 'pending'
            db.execute('UPDATE memory_jobs SET attempts=attempts+1,status=?,error="backend unavailable or unconfirmed" WHERE scope=? AND id=? AND kind=?',
                       (status, scope, memory_id, kind))
            failed += 1
    return {'completed': completed, 'failed': failed, 'awaiting': awaiting + sync_uncertain,
            'partial': failed > 0 or awaiting > 0 or sync_uncertain > 0,
            'partial_sources': (['memory_model_budget'] if budget_denied else (['memory'] if failed else []))
                               + (['memory_async_pending'] if awaiting else [])
                               + (['memory_sync_uncertain'] if sync_uncertain else [])}


def _eligible(db, scope):
    eligible = {}
    for row in db.execute('SELECT id FROM memory_refs WHERE scope=? AND lifecycle="active" AND backend_status="ready" ORDER BY id', (scope,)).fetchall():
        record = _record(db, scope, row[0])
        try:
            material = _materialize(db, scope, record)
            eligible[record['document_id']] = dict(record, **material)
        except ValueError:
            pass
    return eligible


def _async_pending(db, scope):
    row = db.execute('SELECT data FROM memory_config WHERE scope=?', (scope,)).fetchone()
    config = json.loads(row[0]) if row else {}
    return (config.get('backend') == 'hindsight' and config.get('retain_mode') == 'async'
            and db.execute('SELECT 1 FROM memory_refs WHERE scope=? AND lifecycle="active" AND backend_status="pending" LIMIT 1',
                           (scope,)).fetchone() is not None)


def _sync_uncertain(db, scope):
    row = db.execute('SELECT data FROM memory_config WHERE scope=?', (scope,)).fetchone()
    config = json.loads(row[0]) if row else {}
    if config.get('backend') != 'hindsight' or config.get('retain_mode', 'sync') != 'sync':
        return False
    try:
        path = _authority_path(db) + '.model-usage.sqlite'
        if not os.path.exists(path):
            return False
        uri = 'file:' + urllib.parse.quote(path, safe='/') + '?mode=ro'
        with contextlib.closing(sqlite3.connect(uri, uri=True, timeout=.25)) as ledger:
            table = ledger.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='sync_retains'").fetchone()
            return bool(table and ledger.execute('SELECT 1 FROM sync_retains WHERE scope=? AND state="sending" LIMIT 1', (scope,)).fetchone())
    except (OSError, sqlite3.Error, ModelBudgetUnavailable):
        return True  # Cannot prove that this bank is safe for reflection.


def _recall(db, scope, args):
    query = args.get('query', '')
    if not isinstance(query, str) or len(query) > 2000:
        raise ValueError('invalid memory query')
    eligible = _eligible(db, scope)
    pending = _async_pending(db, scope)
    partial_sources = (['memory_async_pending'] if pending else []) + (['memory_sync_uncertain'] if _sync_uncertain(db, scope) else [])
    if not eligible:
        return {'memories': [], 'partial': bool(partial_sources),
                'partial_sources': partial_sources, 'authoritative': False}
    try:
        recalled = _backend(db, scope).recall(query)
    except ModelBudgetUnavailable:
        return {'memories': [], 'partial': True, 'partial_sources': ['memory_model_budget'], 'authoritative': False}
    except (OSError, ValueError):
        return {'memories': [], 'partial': True, 'partial_sources': ['memory'], 'authoritative': False}
    results, seen = [], set()
    for item in recalled:
        if not isinstance(item, dict):
            continue
        document_id = item.get('document_id')
        if document_id not in eligible or document_id in seen:
            continue
        seen.add(document_id)
        record = eligible[document_id]
        try:
            latest = _record(db, scope, record['id'])
            if latest['lifecycle'] != 'active' or latest['backend_status'] != 'ready':
                continue
            record = dict(latest, **_materialize(db, scope, latest))
        except ValueError:
            continue
        # Backend text and freshness are untrusted. Return only canonical validated content.
        results.append({key: record[key] for key in ('id', 'kind', 'content', 'evidence_ids', 'judgment_revision')})
    return {'memories': results[:50], 'partial': bool(partial_sources),
            'partial_sources': partial_sources, 'authoritative': False}


def _reflection_sources(db, scope, backend):
    eligible = _eligible(db, scope)
    if not eligible or _async_pending(db, scope) or _sync_uncertain(db, scope):
        return {}
    ready_count = db.execute('SELECT COUNT(*) FROM memory_refs WHERE scope=? AND lifecycle="active" AND backend_status="ready"', (scope,)).fetchone()[0]
    if ready_count != len(eligible):
        return {}
    if db.execute('SELECT 1 FROM memory_refs WHERE scope=? AND lifecycle!="active" AND backend_status!="deleted" LIMIT 1', (scope,)).fetchone():
        return {}
    # Hindsight 1.2.3 may still serve derived observations after deletion alone.
    if isinstance(backend, HindsightBackend) and db.execute('SELECT 1 FROM memory_refs WHERE scope=? AND lifecycle!="active" LIMIT 1', (scope,)).fetchone():
        return {}
    if db.execute('SELECT COUNT(*) FROM memory_candidates WHERE scope=?', (scope,)).fetchone()[0] >= 100:
        raise ValueError('project candidate quota exceeded')
    return eligible


def reflect(db, scope, actor, args, call_provider=None):
    query = _text(args.get('query'), 2000)
    unavailable = {'status': 'unavailable', 'partial': True, 'authoritative': False}
    backend = _backend(db, scope)
    eligible = _reflection_sources(db, scope, backend)
    if not eligible:
        return unavailable
    try:
        text = call_provider(backend, query) if call_provider else backend.reflect(query)
    except ModelBudgetUnavailable:
        return dict(unavailable, partial_sources=['memory_model_budget'])
    except (OSError, ValueError):
        return unavailable
    if _reflection_sources(db, scope, backend) != eligible or contains_secret(text):
        return unavailable
    candidate = {'id': 'candidate-' + uuid.uuid4().hex, 'status': 'candidate', 'text': text,
                 'authoritative': False, 'actor': actor, 'created_at': time.time(),
                 'memory_ids': sorted(record['id'] for record in eligible.values()),
                 'review_after': min(record['review_after'] for record in eligible.values())}
    db.execute('INSERT INTO memory_candidates VALUES(?,?,?)', (scope, candidate['id'], _json(candidate)))
    return candidate


def _timeline(db, scope, actor, op, args):
    """User metadata only; ignored-card authority remains in core_feedback."""
    allowed = {'tenant', 'workspace', 'project', 'repo', 'ref', 'source_revision',
               'task', 'executor_task_id', 'cursor', 'cards'}
    if set(args) - allowed:
        raise ValueError('unsupported timeline metadata')
    task = _text(args.get('task', args.get('executor_task_id')), 160)
    if args.get('executor_task_id', task) != task:
        raise ValueError('timeline task mismatch')
    key = (scope, _text(actor, 300), task, _text(args.get('repo'), 300), _text(args.get('ref'), 300))
    high_water = db.execute('SELECT COALESCE(MAX(seq),0) FROM core_events WHERE scope=?', (scope,)).fetchone()[0]
    if op == 'timeline.mark':
        cursor = args.get('cursor')
        if type(cursor) is not int or not 0 <= cursor <= high_water:
            raise ValueError('timeline cursor outside authorized range')
        db.execute('INSERT INTO timeline_reads VALUES(?,?,?,?,?,?,?) ON CONFLICT(scope,actor,task,repo,ref) DO UPDATE SET read_cursor=MAX(read_cursor,excluded.read_cursor),updated_at=excluded.updated_at',
                   key + (cursor, time.time()))
    row = db.execute('SELECT read_cursor FROM timeline_reads WHERE scope=? AND actor=? AND task=? AND repo=? AND ref=?', key).fetchone()
    cards = args.get('cards', [])
    if not isinstance(cards, list) or len(cards) > 200:
        raise ValueError('timeline card batch exceeds budget')
    requested = []
    for card in cards:
        if not isinstance(card, dict) or set(card) != {'recommendation_id', 'judgment_revision'}:
            raise ValueError('invalid timeline card metadata')
        requested.append({'recommendation_id': _id(card['recommendation_id']),
                          'judgment_revision': _id(card['judgment_revision'])})
    # JSON1 is bundled in the supported SQLite runtime. Only metadata crosses
    # this boundary, even when the original feedback holds sensitive correction text.
    dismissed = []
    if requested:
        rows = db.execute('''SELECT json_extract(data,'$.recommendation_id'),
                              json_extract(data,'$.judgment_revision'),MAX(id)
                            FROM core_feedback WHERE scope=?
                            AND json_extract(data,'$.actor')=?
                            AND json_extract(data,'$.executor_task_id')=?
                            AND json_extract(data,'$.repo')=? AND json_extract(data,'$.ref')=?
                            AND json_extract(data,'$.acceptance')='ignored'
                            AND EXISTS (SELECT 1 FROM json_each(?) AS requested
                              WHERE json_extract(requested.value,'$.recommendation_id')=json_extract(data,'$.recommendation_id')
                              AND json_extract(requested.value,'$.judgment_revision')=json_extract(data,'$.judgment_revision'))
                            GROUP BY json_extract(data,'$.recommendation_id'),json_extract(data,'$.judgment_revision')
                            LIMIT 200''', key + (_json(requested),)).fetchall()
        dismissed = [{'recommendation_id': row[0], 'judgment_revision': row[1],
                      'executor_task_id': task, 'feedback_id': row[2]} for row in rows]
    return {'read_cursor': min(row[0], high_water) if row else 0,
            'high_water': high_water, 'dismissed': dismissed, 'metadata_only': True}


def dispatch(db, scope, actor, op, args):
    if not isinstance(scope, str) or not scope or len(scope) > 1000 or not isinstance(args, dict):
        raise ValueError('invalid memory scope or arguments')
    if op in ('timeline.read', 'timeline.mark'):
        return _timeline(db, scope, actor, op, args)
    if op == 'memory.setup':
        return _setup(db, scope, args)
    if op == 'memory.retain':
        return _retain(db, scope, actor, args)
    if op == 'memory.project':
        return _project(db, scope, args.get('limit', 50))
    if op == 'memory.forget':
        return _forget(db, scope, args.get('id'))
    if op == 'memory.retry':
        memory_id = _id(args.get('id'))
        _record(db, scope, memory_id)
        # Operator retry is explicit, not an unbounded automatic loop.
        db.execute('UPDATE memory_jobs SET status="pending",attempts=0,error=NULL WHERE scope=? AND id=? AND status="dead"', (scope, memory_id))
        db.execute('UPDATE memory_schedule SET next_run=0 WHERE scope=?', (scope,))
        return {'id': memory_id, 'status': 'retry_queued'}
    if op == 'memory.recall':
        return _recall(db, scope, args)
    if op == 'memory.wiki':
        return {'pages': [{'id': record['id'], 'title': record['kind'], 'text': record['content'],
                           'evidence_ids': record['evidence_ids'], 'judgment_revision': record['judgment_revision'],
                           'authoritative': False} for record in _eligible(db, scope).values()], 'read_only': True}
    if op == 'memory.reflect':
        return reflect(db, scope, actor, args)
    if op == 'memory.candidates':
        valid = {record['id'] for record in _eligible(db, scope).values()}
        candidates = []
        for row in db.execute('SELECT data FROM memory_candidates WHERE scope=? ORDER BY id', (scope,)).fetchall():
            candidate = json.loads(row[0])
            if candidate['review_after'] > time.time() and set(candidate['memory_ids']).issubset(valid):
                candidates.append(candidate)
        return {'candidates': candidates, 'authoritative': False}
    if op == 'memory.status':
        counts = dict(db.execute('SELECT lifecycle,COUNT(*) FROM memory_refs WHERE scope=? GROUP BY lifecycle', (scope,)).fetchall())
        jobs = dict(db.execute('SELECT status,COUNT(*) FROM memory_jobs WHERE scope=? GROUP BY status', (scope,)).fetchall())
        return {'retained': counts.get('active', 0), 'forgotten': counts.get('forgotten', 0),
                'projected': db.execute('SELECT COUNT(*) FROM memory_refs WHERE scope=? AND backend_status="ready" AND lifecycle="active"', (scope,)).fetchone()[0],
                'pending': jobs.get('pending', 0), 'dead_letters': jobs.get('dead', 0),
                'attempts': db.execute('SELECT COALESCE(SUM(attempts),0) FROM memory_jobs WHERE scope=?', (scope,)).fetchone()[0],
                'model_usage': _model_usage(db, scope)}
    raise ValueError('unknown memory operation')
