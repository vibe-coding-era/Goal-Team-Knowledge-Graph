"""Local Git integration oracles; no remote or user checkout is modified."""
import json
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from thinker import repos


class RepositoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.path = self.root / 'a'
        self.path.mkdir()
        self.git('init', '-b', 'main')
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.git('config', 'user.name', 'Fixture')
        self.first = self.commit('first\n')
        self.db = sqlite3.connect(str(self.root / 'state.sqlite'))
        self.db.row_factory = sqlite3.Row
        repos.init_db(self.db)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.path), *args],
                                       stderr=subprocess.DEVNULL).decode().strip()

    def commit(self, text):
        (self.path / 'same.py').write_text(text)
        self.git('add', 'same.py')
        self.git('commit', '-m', 'fixture')
        return self.git('rev-parse', 'HEAD')

    def call(self, op, scope='A', **args):
        return repos.dispatch(self.db, scope, 'human-admin', op, args)

    def add(self, scope='A', repo='repo', **extra):
        return self.call('repos.add', scope, repo=repo, location=str(self.path),
                         refs=['refs/heads/main'], paths=['same.py'], **extra)

    def status(self, scope='A'):
        return self.call('watch.status', scope)['repos'][0]

    def test_baseline_is_not_historical_event_and_scope_is_opaque(self):
        self.add()
        self.call('watch.reconcile', repo='repo')
        ref = self.status()['refs'][0]
        self.assertEqual(ref['observed_oid'], self.first)
        self.assertEqual(ref['transition_seq'], 0)
        self.assertEqual(self.call('repos.list', 'other')['repos'], [])
        self.assertEqual(self.call('watch.status')['events'], [])
        with self.assertRaises(ValueError):
            self.call('source.read', 'other', repo='repo', ref='refs/heads/main', path='same.py')

    def test_fast_forward_refreshes_evidence_without_claiming_index_current(self):
        self.add()
        old = self.call('source.read', repo='repo', ref='refs/heads/main', path='same.py')['evidence'][0]
        second = self.commit('second\n')
        self.assertFalse(repos.validate_current(self.db, 'A', old))
        result = self.call('watch.reconcile', repo='repo')
        event = result['events'][0]
        self.assertEqual((event['kind'], event['previous_oid'], event['observed_oid']),
                         ('fast_forward', self.first, second))
        self.assertEqual(event['transition_seq'], 1)
        fresh = result['refreshed_evidence'][0]
        self.assertEqual(fresh['text'], 'second\n')
        self.assertNotEqual(fresh['id'], old['id'])
        self.assertEqual(fresh['source_revision'], second)
        self.assertTrue(repos.validate_current(self.db, 'A', fresh))
        self.assertIsNone(self.status()['refs'][0]['indexed_oid'])

    def test_durable_dedupe_after_restart_and_oid_return_is_new_transition(self):
        self.add()
        second = self.commit('second\n')
        first_event = self.call('watch.reconcile', repo='repo')['events'][0]
        self.db.commit()
        self.db.close()
        self.db = sqlite3.connect(str(self.root / 'state.sqlite'))
        self.db.row_factory = sqlite3.Row
        repos.init_db(self.db)
        self.assertEqual(self.call('watch.reconcile', repo='repo')['events'], [])
        self.git('update-ref', 'refs/heads/main', self.first)
        forced = self.call('watch.reconcile', repo='repo')['events'][0]
        self.assertEqual(forced['kind'], 'force_push')
        self.assertEqual(forced['ref_generation'], 2)
        self.git('update-ref', 'refs/heads/main', second)
        returned = self.call('watch.reconcile', repo='repo')['events'][0]
        self.assertGreater(returned['transition_seq'], first_event['transition_seq'])
        self.assertNotEqual(returned['event_id'], first_event['event_id'])

    def test_delete_and_recreate_ref_generation_and_other_ref_survives(self):
        self.git('branch', 'keep')
        self.call('repos.add', repo='repo', location=str(self.path),
                  refs=['refs/heads/main', 'refs/heads/keep'])
        old = self.call('source.read', repo='repo', ref='refs/heads/main', path='same.py')['evidence'][0]
        keep = self.call('source.read', repo='repo', ref='refs/heads/keep', path='same.py')['evidence'][0]
        self.git('update-ref', '-d', 'refs/heads/main')
        self.assertEqual(self.call('watch.reconcile', repo='repo')['events'][0]['kind'], 'deleted')
        self.assertFalse(repos.validate_current(self.db, 'A', old))
        self.assertTrue(repos.validate_current(self.db, 'A', keep))
        self.git('update-ref', 'refs/heads/main', self.first)
        created = self.call('watch.reconcile', repo='repo')['events'][0]
        self.assertEqual(created['kind'], 'created')
        self.assertGreater(created['ref_generation'], old['ref_generation'])

    def test_offline_is_degraded_not_deleted_and_pause_remove_do_not_delete_git(self):
        self.add()
        original = self.call('source.read', repo='repo', ref='refs/heads/main', path='same.py')['evidence'][0]
        moved = self.root / 'offline'
        self.path.rename(moved)
        self.assertEqual(self.call('watch.reconcile', repo='repo')['events'], [])
        status = self.status()
        self.assertEqual(status['health'], 'degraded')
        self.assertEqual(status['refs'][0]['observed_oid'], self.first)
        self.assertFalse(repos.validate_current(self.db, 'A', original))
        moved.rename(self.path)
        self.call('watch.reconcile', repo='repo')
        self.call('repos.pause', repo='repo')
        self.assertFalse(repos.validate_current(self.db, 'A', original))
        self.call('repos.resume', repo='repo')
        self.call('watch.reconcile', repo='repo')
        self.call('repos.remove', repo='repo')
        self.assertTrue((self.path / '.git').exists())
        self.assertFalse(repos.validate_current(self.db, 'A', original))

    def test_linked_worktree_identity_is_shared_but_scopes_not_merged(self):
        linked = self.root / 'linked'
        self.git('worktree', 'add', '-b', 'linked', str(linked))
        a = self.add()['repo']
        b = self.call('repos.add', 'B', repo='repo', location=str(linked),
                      refs=['refs/heads/linked'])['repo']
        self.assertEqual(a['common_dir'], b['common_dir'])
        self.assertNotEqual(a['location'], b['location'])
        self.assertEqual(len(self.call('repos.list')['repos']), 1)
        self.assertEqual(self.call('watch.status')['events'], [])

    def test_hot_configuration_invalidates_stamps_and_tick_is_bounded(self):
        self.add()
        evidence = self.call('source.read', repo='repo', ref='refs/heads/main', path='same.py')['evidence'][0]
        self.add(scope='B')
        self.add()
        self.assertFalse(repos.validate_current(self.db, 'A', evidence))
        self.assertEqual(self.status()['config_revision'], 2)
        tick = repos.tick(self.db)
        self.assertEqual(tick['processed'], 1)
        self.assertIn(tick['scope'], ['A', 'B'])

    def test_dirty_worktree_does_not_leak_and_reader_cannot_supply_adapter(self):
        self.add()
        (self.path / 'same.py').write_text('uncommitted secret\n')
        result = self.call('source.read', repo='repo', ref='refs/heads/main', path='same.py')
        self.assertEqual(result['evidence'][0]['text'], 'first\n')
        with self.assertRaises(ValueError):
            self.call('source.search', repo='repo', ref='refs/heads/main', query='first',
                      adapter={'kind': 'git'}, location='/tmp')

    def test_reconcile_and_registration_obey_outer_transaction(self):
        self.db.commit()
        self.db.execute('BEGIN')
        self.add()
        self.db.rollback()
        self.assertEqual(self.call('repos.list')['repos'], [])

    def test_ref_rules_must_be_explicit_and_no_path_escape(self):
        for ref in ['HEAD', 'refs/heads/*', 'main', 'refs/heads/../main']:
            with self.assertRaises(ValueError):
                self.call('repos.add', repo='repo', location=str(self.path), refs=[ref])
        self.add()
        with self.assertRaises(ValueError):
            self.call('source.read', repo='repo', ref='refs/heads/main', path='../outside')

    def test_empty_query_rechecks_revision_and_search_context_never_writes(self):
        self.add()
        binding = repos.current_binding(self.db, 'A', 'repo', 'refs/heads/main')
        changes = self.db.total_changes
        with patch.object(repos, 'current_binding', side_effect=[binding, ValueError('moved')]):
            result = repos.search_context(self.db, 'A', {
                'repo': 'repo', 'ref': 'refs/heads/main', 'query': 'no-match'})
        self.assertEqual(result['status'], 'stale')
        self.assertEqual(result['evidence'], [])
        self.assertEqual(self.db.total_changes, changes)


if __name__ == '__main__':
    unittest.main()
