import copy
import errno
import fcntl
import hashlib
import json
import os
import pty
import select
import struct
import subprocess
import sys
import termios
import time
import unittest

from thinker import tui


class Client:
    def __init__(self):
        self.calls = []
        self.fail = None
        self.version = 'impact@1'
        self.events = []
        self.cursor = 1
        self.records = {}
        self.read_cursor = 0

    def __call__(self, op, args):
        self.calls.append((op, copy.deepcopy(args)))
        if self.fail:
            raise self.fail
        if op == 'context.get':
            return {'cursor': self.cursor, 'source_revision': 'a' * 40,
                    'as_of': {'source_revision': 'a' * 40},
                    'recommendations': [{'id': 'rec-1', 'judgment_revision': self.version,
                       'executor_task_id': 'task-1', 'next_action': '先查中文证据',
                       'evidence_ids': ['src-1'], 'expected_check': 'check-b',
                       'expires_at': time.time() + 600}],
                    'active_judgments': [], 'partial_sources': [], 'evidence_refs': []}
        if op == 'events.list':
            return {'events': copy.deepcopy(self.events), 'cursor': self.cursor}
        if op in ('timeline.read', 'timeline.mark'):
            if op == 'timeline.mark':
                self.read_cursor = max(self.read_cursor, args['cursor'])
            return {'read_cursor': self.read_cursor, 'high_water': self.cursor,
                    'dismissed': [dict(recommendation_id=item['recommendation_id'],
                                      judgment_revision=item['judgment_revision'],
                                      executor_task_id=item['executor_task_id'], feedback_id=item['id'])
                                  for item in self.records.values() if item['acceptance'] == 'ignored'
                                  and item['project'] == args['project'] and item['task'] == args['task']]}
        if op == 'evidence.get':
            return {'id': 'src-1', 'text': '证据内容', 'source_revision': 'a' * 40,
                    'locator': {'path': 'src/a.py', 'line_start': 2}}
        if op == 'judgment.explain':
            return {'current': {'claim': '新的判断'}, 'revisions': [{'revision': 1}]}
        if op == 'feedback.record':
            self.records.setdefault(args['id'], dict(args))
            return {'id': args['id'], 'outcome': 'unverified'}
        raise ValueError('unknown operation')


class TUITests(unittest.TestCase):
    def setUp(self):
        self.client = Client()
        self.session = tui.Session(self.client, {'project': '项目一', 'task': 'task-1',
                                    'repo': 'repo-a', 'ref': 'refs/heads/main'})
        self.session.refresh()

    def test_controls_and_bidi_are_data_not_terminal_instructions(self):
        raw = 'safe\x1b]52;c;c2VjcmV0\x07\x1b[2J\x9b31m\u202eevil\r\btext'
        clean = tui.sanitize(raw)
        self.assertNotIn('\x1b', clean)
        self.assertNotIn('\x9b', clean)
        self.assertNotIn('\u202e', clean)
        self.assertNotIn('c2VjcmV0', clean)
        self.assertNotIn('\r', clean)
        self.assertNotIn('\b', clean)

    def test_cjk_frames_fit_both_terminal_sizes(self):
        self.session.snapshot['recommendations'][0]['next_action'] = '中文🙂e\u0301' * 100
        for width, height in ((80, 24), (120, 32), (30, 10)):
            frame = self.session.render(width, height)
            self.assertLessEqual(len(frame.splitlines()), height)
            self.assertTrue(all(tui.display_width(line) <= width for line in frame.splitlines()))
            self.assertIn('Thinker', frame)

    def test_evidence_reopens_using_shared_client(self):
        self.session.open_evidence()
        self.session.open_evidence()
        self.assertEqual(sum(op == 'evidence.get' for op, _ in self.client.calls), 2)
        self.assertIn('证据内容', self.session.render(80, 24))

    def test_correction_and_repeat_have_one_version_checked_record(self):
        self.session.act('corrected', '环境故障，补证据')
        self.session.act('corrected', '环境故障，补证据')
        self.assertEqual(len(self.client.records), 1)
        feedback = list(self.client.records.values())[0]
        self.assertEqual(feedback['judgment_revision'], 'impact@1')
        self.assertEqual(feedback['source_revision'], 'a' * 40)
        self.assertEqual(feedback['outcome'], 'unverified')
        self.assertIn('反馈已记录', self.session.message)
        self.assertFalse(any(op in ('execute', 'publish') for op, _ in self.client.calls))

    def test_version_race_refuses_feedback(self):
        self.client.version = 'impact@2'
        self.session.act('accepted')
        self.assertEqual(self.client.records, {})
        self.assertIn('已失效', self.session.message)

    def test_identical_recommendation_ids_are_deduplicated_per_project(self):
        self.session.act('accepted')
        self.session.refresh({'project': '项目二'})
        self.session.act('accepted')
        self.assertEqual(len(self.client.records), 2)
        self.assertEqual({item['project'] for item in self.client.records.values()}, {'项目一', '项目二'})

    def test_ignored_card_stays_closed_on_reopen_but_new_revision_does_not(self):
        self.session.act('ignored')
        self.assertEqual(self.session.cards(), [])
        reopened = tui.Session(self.client, self.session.args)
        reopened.refresh()
        self.assertEqual(reopened.cards(), [])
        self.client.version = 'impact@2'
        reopened.refresh()
        self.assertEqual(len(reopened.cards()), 1)

    def test_read_cursor_survives_reopen_and_review_questions_are_visible(self):
        self.session.handle_key('m')
        reopened = tui.Session(self.client, self.session.args)
        reopened.refresh()
        self.assertEqual(reopened.timeline['read_cursor'], 1)
        reopened.snapshot['open_questions'] = [{'judgment_revision': 'impact@1',
                                               'status': 'needs_evidence', 'reason': 'source_or_evidence_changed'}]
        frame = reopened.render(80, 24)
        self.assertIn('待补证据', frame)
        self.assertIn('impact@1', frame)

    def test_long_evidence_is_wrapped_and_keyboard_scrollable(self):
        self.session.panel = '证据'
        self.session.panel_content = '中文证据' * 500 + '最后一行可以看到'
        frame = self.session.render(80, 24)
        self.assertIn('中文证据', frame)
        for _ in range(30):
            self.session.handle_key('\x1b[6~')
        frame = self.session.render(80, 24)
        self.assertIn('最后一行可以看到', frame)
        self.assertTrue(all(tui.display_width(line) <= 80 for line in frame.splitlines()))

    def test_disconnect_clears_sensitive_body_and_disables_actions(self):
        self.client.fail = OSError('socket lost')
        self.session.poll()
        self.assertFalse(self.session.connected)
        self.assertNotIn('先查中文证据', self.session.render(80, 24))
        self.session.act('accepted')
        self.assertEqual(self.client.records, {})
        self.client.fail = None
        self.session.refresh()
        self.assertTrue(self.session.connected)

    def test_denied_project_removes_all_old_titles_and_text(self):
        self.client.fail = ValueError('forbidden')
        self.session.refresh({'project': 'secret-project'})
        frame = self.session.render(80, 24)
        self.assertNotIn('secret-project', frame)
        self.assertNotIn('项目一', frame)
        self.assertNotIn('先查中文证据', frame)
        self.assertIn('无权', frame)

    def test_event_replay_deduplicates_without_rendering_payload(self):
        self.client.events = [{'event_id': 'event-2', 'seq': 2,
                               'payload': {'secret': 'old revoked body'}}] * 2
        self.client.cursor = 2
        self.session.poll()
        self.session.poll()
        self.assertEqual(self.session.event_count, 1)
        self.assertNotIn('old revoked body', self.session.render(80, 24))
        self.assertEqual(self.session.cursor, 2)

    def test_input_focus_does_not_capture_character_hotkeys(self):
        self.session.handle_key('c')
        for char in 'aicq?中':
            self.session.handle_key(char)
        self.assertEqual(self.session.input_text, 'aicq?中')
        self.assertFalse(self.session.quit)
        self.session.handle_key('\x1b')
        self.assertNotEqual(self.session.focus, 'input')

    def test_ack_loss_retries_same_id(self):
        original = self.client.__call__
        lost = [True]
        def flaky(op, args):
            result = original(op, args)
            if op == 'feedback.record' and lost[0]:
                lost[0] = False
                raise OSError('ack lost')
            return result
        self.session.request = flaky
        self.session.act('corrected', '补证据')
        self.assertIn('待同步', self.session.message)
        self.session.refresh()
        self.session.act('corrected', '补证据')
        self.assertEqual(len(self.client.records), 1)

    def test_real_pty_evidence_correction_and_exit(self):
        for width, height in ((80, 24), (120, 32)):
            master, slave = pty.openpty()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', height, width, 0, 0))
            script = "from thinker_tests.test_tui import Client; from thinker.tui import run; run(Client(), {'project':'P','task':'task-1','repo':'repo-a','ref':'refs/heads/main'})"
            proc = subprocess.Popen([sys.executable, '-c', script], stdin=slave, stdout=slave,
                                    stderr=slave, close_fds=True, env=dict(os.environ, TERM='xterm-256color'))
            os.close(slave)
            data = b''
            def read_until(needle, timeout=5):
                nonlocal data
                deadline = time.monotonic() + timeout
                while needle.encode() not in data and time.monotonic() < deadline:
                    ready, _, _ = select.select([master], [], [], 0.1)
                    if ready:
                        try:
                            data += os.read(master, 65536)
                        except OSError as error:
                            if error.errno == errno.EIO:
                                break
                            raise
                self.assertTrue(needle in data.decode('utf-8', 'replace'),
                                'Missing %s in PTY output; tail: %r' % (needle, data[-1200:]))
            try:
                read_until('Thinker')
                os.write(master, b'e')
                read_until('证据内容')
                os.write(master, b'\x1b')
                time.sleep(0.05)
                os.write(master, 'c环境故障\r'.encode())
                read_until('反馈已记录')
                os.write(master, b'q')
                proc.wait(timeout=5)
                self.assertEqual(proc.returncode, 0)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()
                os.close(master)

    def test_real_service_pty_records_corrected_feedback(self):
        from thinker_tests.test_workflows import Handoff
        from thinker.service import connect
        fixture = Handoff()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        version, _ = fixture.register('terminalrepo')
        evidence = fixture.req('evidence.capture', **version, path='contract.txt')
        fixture.record(version, 'impact', supports=[evidence['id']])
        fixture.req('recommendation.send', **version, id='rec-live', judgment_revision='impact@1',
                    executor_task_id='task-live', next_action='先检查 B 的依赖',
                    expected_check='B integration', expires_at=time.time() + 600)
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 80, 0, 0))
        command = fixture.command + ['tui', '--project', 'alpha', '--task', 'task-live',
                                     '--args', json.dumps(version)]
        proc = subprocess.Popen(command, stdin=slave, stdout=slave, stderr=slave,
                                close_fds=True, env=dict(os.environ, TERM='xterm-256color'))
        os.close(slave)
        data = b''
        def read_until(needle):
            nonlocal data
            deadline = time.monotonic() + 8
            while needle.encode() not in data and time.monotonic() < deadline:
                ready, _, _ = select.select([master], [], [], 0.1)
                if ready:
                    try:
                        data += os.read(master, 65536)
                    except OSError as error:
                        if error.errno == errno.EIO:
                            break
                        raise
            self.assertTrue(needle in data.decode('utf-8', 'replace'),
                            'Missing %s in PTY output; tail: %r' % (needle, data[-1200:]))
        try:
            read_until('rec-live')
            os.write(master, b'e')
            read_until('B imports A')
            os.write(master, b'\x1b')
            time.sleep(0.15)
            os.write(master, 'c需要排除环境故障\r'.encode())
            read_until('反馈已记录')
            with connect(fixture.home) as db:
                records = db.execute('SELECT data FROM core_feedback').fetchall()
                self.assertEqual(len(records), 1)
                feedback = json.loads(records[0][0])
                self.assertEqual(feedback['acceptance'], 'corrected')
                self.assertEqual(feedback['outcome'], 'unverified')
                self.assertEqual(feedback['correction'], '需要排除环境故障')
            os.write(master, b'q')
            proc.wait(timeout=5)
            self.assertEqual(proc.returncode, 0)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            os.close(master)

    def test_real_service_persists_actor_read_and_ignored_state_with_acl(self):
        from thinker_tests.test_workflows import Handoff
        from thinker.client import call
        fixture = Handoff()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        version, _ = fixture.register('timelinerepo')
        evidence = fixture.req('evidence.capture', **version, path='contract.txt')
        fixture.record(version, 'impact', supports=[evidence['id']])
        fixture.req('recommendation.send', **version, id='rec-live', judgment_revision='impact@1',
                    executor_task_id='task-live', next_action='Inspect dependency',
                    expected_check='B integration', expires_at=time.time() + 600)
        for actor, token, role in [('alice', 'a' * 64, 'human'), ('bob', 'b' * 64, 'human'),
                                   ('reader', 'c' * 64, 'reader')]:
            fixture.req('access.grant', token_file_id=actor, actor=actor, role=role,
                        task='task-live', digest=hashlib.sha256(token.encode()).hexdigest())
        args = dict(version, project='alpha', task='task-live')
        alice = lambda op, fields: call(fixture.home, 'a' * 64, op, fields)
        session = tui.Session(alice, args)
        self.assertTrue(session.refresh())
        cursor = session.cursor
        session.handle_key('m')
        session.act('ignored')
        self.assertEqual(session.cards(), [])
        reopened = tui.Session(alice, args)
        self.assertTrue(reopened.refresh())
        self.assertEqual(reopened.timeline['read_cursor'], cursor)
        self.assertEqual(reopened.cards(), [])
        bob = tui.Session(lambda op, fields: call(fixture.home, 'b' * 64, op, fields), args)
        self.assertTrue(bob.refresh())
        self.assertEqual(bob.timeline['read_cursor'], 0)
        self.assertEqual(len(bob.cards()), 1)
        for token, fields in [('c' * 64, args), ('a' * 64, dict(args, task='other-task')),
                              ('a' * 64, dict(args, project='other-project'))]:
            with self.assertRaises(ValueError):
                call(fixture.home, token, 'timeline.mark', dict(fields, cursor=cursor))

    def test_real_service_lost_correction_ack_reconciles_receipt(self):
        from thinker_tests.test_workflows import Handoff
        from thinker.client import call
        from thinker.service import connect
        fixture = Handoff()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        version, _ = fixture.register('ackrepo')
        evidence = fixture.req('evidence.capture', **version, path='contract.txt')
        fixture.record(version, 'impact', supports=[evidence['id']])
        fixture.req('recommendation.send', **version, id='rec-ack', judgment_revision='impact@1',
                    executor_task_id='task-ack', next_action='Check B',
                    expected_check='B integration', expires_at=time.time() + 600)
        lost = [True]
        def transport(op, args):
            result = call(fixture.home, fixture.key, op, args)
            if op == 'feedback.record' and lost[0]:
                lost[0] = False
                raise OSError('ack lost after commit')
            return result
        session = tui.Session(transport, dict(version, project='alpha', task='task-ack'))
        session.refresh()
        session.act('corrected', '需要复核')
        self.assertIn('待同步', session.message)
        session.refresh()
        self.assertIn('反馈已记录', session.message)
        self.assertFalse(session.pending)
        self.assertFalse(session.cards())
        with connect(fixture.home) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM core_feedback').fetchone()[0], 1)


if __name__ == '__main__':
    unittest.main()
