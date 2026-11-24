"""Keyboard terminal client; all authority stays in the shared control service."""

import codecs
import datetime
import json
import os
import re
import select
import shutil
import sys
import termios
import time
import tty
import unicodedata
import uuid


_OSC = re.compile(r'(?:\x1b\]|\x9d)[^\x07\x1b\x9c]*(?:\x07|\x1b\\|\x9c|$)')
_CSI = re.compile(r'(?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]')
_ESC = re.compile(r'\x1b(?:[PX^_][^\x1b]*(?:\x1b\\|$)|[ -/]*[@-~])')


def sanitize(value):
    """Strip terminal commands and invisible format controls from untrusted text."""
    text = str(value)
    text = _ESC.sub('', _CSI.sub('', _OSC.sub('', text)))
    return ''.join(char if char == '\n' or unicodedata.category(char)[0] != 'C' else ''
                   for char in text.replace('\t', '    '))


def display_width(text):
    return sum(0 if unicodedata.combining(char) else
               2 if unicodedata.east_asian_width(char) in ('W', 'F') else 1
               for char in text)


def _clip(text, width):
    output, used = [], 0
    for char in sanitize(text).replace('\n', ' ').replace('\r', ''):
        cells = display_width(char)
        if used + cells > max(0, width):
            break
        output.append(char)
        used += cells
    return ''.join(output)


def _pretty(value):
    return sanitize(json.dumps(value, ensure_ascii=False, indent=2))


def _wrap(text, width):
    lines = []
    for paragraph in sanitize(text).split('\n'):
        current, used = '', 0
        for char in paragraph:
            cells = display_width(char)
            if used + cells > width and current:
                lines.append(current)
                current, used = '', 0
            current += char
            used += cells
        lines.append(current)
    return lines


class Session:
    """Embeddable view model. No shell, background watcher or database access."""

    def __init__(self, request, args):
        self.request = request
        self.args = dict(args)
        self.snapshot = {}
        self.cursor = 0
        self.seen_events = set()
        self.event_count = 0
        self.connected = False
        self.denied = False
        self.selected = 0
        self.focus = 'timeline'
        self.panel = ''
        self.panel_content = ''
        self.input_text = ''
        self.message = '正在同步当前任务'
        self.pending = {}
        self.completed = set()
        self.quit = False
        self.action_index = 0
        self.scroll = 0
        self.timeline = {'read_cursor': 0, 'high_water': 0, 'dismissed': []}

    def _base_args(self):
        args = {key: value for key, value in self.args.items()
                if key in ('tenant', 'workspace', 'project', 'repo', 'ref', 'source_revision', 'task')}
        if args.get('task'):
            args['executor_task_id'] = args['task']
        return args

    def _identity(self):
        return tuple(self.args.get(key, '') for key in ('tenant', 'workspace', 'project', 'repo', 'ref', 'task'))

    def _failure(self, error):
        self.connected = False
        self.denied = isinstance(error, ValueError) and any(
            word in str(error).lower() for word in ('forbidden', 'unauthorized', 'permission', 'denied', '无权'))
        self.snapshot = {}
        self.timeline = {'read_cursor': 0, 'high_water': 0, 'dismissed': []}
        self.panel_content = ''
        self.panel = ''
        self.input_text = ''
        self.message = '无权访问当前项目' if self.denied else '已断线；反馈禁用。按 r 重新连接'

    def refresh(self, args=None):
        if args:
            self.args.update(args)
            self.snapshot = {}
            self.timeline = {'read_cursor': 0, 'high_water': 0, 'dismissed': []}
            self.seen_events.clear()
            self.cursor = 0
            self.selected = 0
            self.panel = ''
            self.panel_content = ''
            self.scroll = 0
        try:
            snapshot = self.request('context.get', self._base_args())
            if not isinstance(snapshot, dict):
                raise ValueError('invalid snapshot')
            self.snapshot = snapshot
            self.cursor = int(snapshot.get('cursor', self.cursor))
            self._load_timeline()
            self.connected, self.denied = True, False
            self.selected = min(self.selected, max(0, len(self.cards()) - 1))
            self.message = '已同步；反馈只记录决定，不运行建议'
            self._reconcile_pending()
            return True
        except (ValueError, OSError, TypeError) as error:
            self._failure(error)
            return False

    def _load_timeline(self):
        if not self.args.get('task'):
            return
        cards = [{'recommendation_id': card['id'], 'judgment_revision': card['judgment_revision']}
                 for card in self.snapshot.get('recommendations', [])
                 if card.get('executor_task_id') == self.args['task']]
        dismissed = []
        for offset in range(0, max(1, len(cards)), 200):
            state = self.request('timeline.read', dict(self._base_args(), cards=cards[offset:offset + 200]))
            dismissed.extend(state.get('dismissed', []))
        self.timeline = dict(state, dismissed=dismissed)

    def mark_read(self):
        if not self.connected or not self.args.get('task'):
            return
        try:
            state = self.request('timeline.mark', dict(self._base_args(), cursor=self.cursor))
            self.timeline['read_cursor'] = state['read_cursor']
            self.message = '当前快照已标记为已读'
        except (ValueError, OSError, KeyError) as error:
            self._failure(error)

    def _reconcile_pending(self):
        for key, record_id in list(self.pending.items())[:10]:
            identity, expected, action, text = key
            if identity != self._identity():
                continue
            try:
                receipt = self.request('feedback.receipt', dict(self._base_args(), id=record_id,
                                       recommendation_id=expected[0], judgment_revision=expected[1],
                                       executor_task_id=expected[2]))
            except ValueError as error:
                if any(word in str(error).lower() for word in ('denied', 'forbidden', 'permission')):
                    raise
                self.message = '反馈待同步；尚无可核对的服务回执'
                continue
            if (receipt.get('receipt_only') is True and receipt.get('id') == record_id
                    and receipt.get('judgment_revision') == expected[1]
                    and receipt.get('acceptance') == action):
                self.pending.pop(key, None)
                self.completed.add(key)
                self.message = '反馈已记录 · 已核对回执 · 未执行建议'

    def cards(self):
        cards = self.snapshot.get('recommendations', [])
        task = self.args.get('task')
        dismissed = {(item['recommendation_id'], item['judgment_revision'], item['executor_task_id'])
                     for item in self.timeline.get('dismissed', [])}
        return [card for card in cards if (not task or card.get('executor_task_id') == task)
                and (card.get('id'), card.get('judgment_revision'), card.get('executor_task_id')) not in dismissed]

    def card(self):
        cards = self.cards()
        return cards[self.selected] if cards and self.selected < len(cards) else None

    def poll(self):
        if not self.connected:
            return
        try:
            result = self.request('events.list', dict(self._base_args(), after_cursor=self.cursor, limit=100))
            if result.get('reset_required') or result.get('cursor_expired'):
                self.refresh()
                return
            changed = False
            for event in result.get('events', []):
                event_id = event.get('event_id')
                if event_id and event_id not in self.seen_events:
                    self.seen_events.add(event_id)
                    self.event_count += 1
                    changed = True
            # Payload text is never rendered: refresh through the current ACL/revision gate.
            self.cursor = max(self.cursor, int(result.get('cursor', self.cursor)))
            if changed:
                self.panel_content = ''
                self.panel = ''
                self.refresh()
        except ValueError as error:
            if any(word in str(error).lower() for word in ('cursor', 'replay')):
                self.refresh()
            else:
                self._failure(error)
        except (OSError, TypeError) as error:
            self._failure(error)

    def open_evidence(self):
        card = self.card()
        if not self.connected or not card:
            return
        try:
            results = [self.request('evidence.get', dict(self._base_args(), id=eid))
                       for eid in card.get('evidence_ids', [])]
            blocks = []
            for item in results:
                locator = item.get('locator', {})
                blocks.append('%s\ncommit %s\n%s:%s–%s\n%s\n' % (
                    item.get('id', ''), item.get('source_revision', ''),
                    locator.get('path', locator.get('run_id', '')),
                    locator.get('line_start', ''), locator.get('line_end', ''), item.get('text', '')))
            self.panel, self.panel_content = '证据', sanitize('\n'.join(blocks))
            self.scroll = 0
        except (ValueError, OSError) as error:
            self._failure(error)

    def open_versions(self):
        card = self.card()
        if not self.connected or not card:
            return
        try:
            judgment_id = card['judgment_revision'].rsplit('@', 1)[0]
            result = self.request('judgment.explain', dict(self._base_args(), judgment_id=judgment_id))
            self.panel, self.panel_content = '判断版本 / 反证', _pretty(result)
            self.scroll = 0
        except (ValueError, OSError, KeyError) as error:
            self._failure(error)

    def act(self, action, text=''):
        if action not in ('accepted', 'ignored', 'corrected'):
            raise ValueError('invalid feedback action')
        card = self.card()
        if not self.connected or not card:
            self.message = '当前不可提交反馈；请连接并查看有效建议'
            return
        if action == 'corrected' and not text.strip():
            self.message = '请输入纠正内容'
            return
        expected = (card.get('id'), card.get('judgment_revision'), card.get('executor_task_id'))
        key = (self._identity(), expected, action, text)
        if key in self.completed:
            self.message = '反馈已记录 · 结果尚未验证 · 未执行建议'
            return
        if not self.refresh():
            return
        current = next((item for item in self.cards() if item.get('id') == expected[0]), None)
        if (not current or current.get('judgment_revision') != expected[1]
                or float(current.get('expires_at', 0)) <= time.time()
                or current.get('status', 'active') in ('withdrawn', 'expired', 'superseded', 'needs_evidence')):
            self.message = '已失效，请查看新版'
            return
        as_of = self.snapshot.get('as_of', {})
        revision = (current.get('source_revision') or self.snapshot.get('source_revision')
                    or (as_of.get('source_revision') if isinstance(as_of, dict) else None)
                    or self.args.get('source_revision'))
        if not revision:
            self.message = '缺少源码版本绑定；无法提交'
            return
        record_id = self.pending.setdefault(key, 'feedback-' + uuid.uuid4().hex)
        payload = dict(self._base_args(), id=record_id, recommendation_id=expected[0],
                       judgment_revision=expected[1], executor_task_id=current.get('executor_task_id'),
                       acceptance=action, outcome='unverified', expected_check=current.get('expected_check', ''),
                       evidence_ids=[], attribution='unknown', source_revision=revision,
                       correction=text, reason=text, dedupe_key=record_id)
        try:
            self.request('feedback.record', payload)
            self.completed.add(key)
            self.pending.pop(key, None)
            try:
                self._load_timeline()
            except (ValueError, OSError) as error:
                self._failure(error)
                self.message = '反馈已记录；界面同步失败，请重连'
                return
            self.selected = min(self.selected, max(0, len(self.cards()) - 1))
            if action == 'ignored':
                self.panel, self.panel_content = '', ''
            self.focus, self.input_text = 'timeline', ''
            self.message = '反馈已记录 · 结果尚未验证 · 未执行建议'
        except OSError as error:
            self._failure(error)
            self.message = '反馈待同步；重连后重试会沿用同一记录 ID'
        except ValueError as error:
            self._failure(error)
            if not self.denied:
                self.message = '已失效，请查看新版；反馈未确认'

    def handle_key(self, key):
        if self.focus == 'input':
            if key == '\x1b':
                self.focus, self.input_text = 'timeline', ''
            elif key in ('\r', '\n'):
                self.act('corrected', self.input_text)
            elif key in ('\x7f', '\b'):
                self.input_text = self.input_text[:-1]
            elif key == '\t':
                self.focus = 'actions'
            elif len(key) == 1 and key.isprintable() and len(self.input_text) < 4096:
                self.input_text += key
            return
        if key in ('q', '\x03'):
            self.quit = True
        elif key == '\x1b':
            self.panel, self.panel_content = '', ''
            self.focus = 'timeline'
            self.scroll = 0
        elif key == '\t':
            self.focus = {'timeline': 'actions', 'actions': 'input'}.get(self.focus, 'timeline')
        elif key in ('j', '\x1b[B'):
            if self.panel:
                self.scroll += 1
            else:
                self.selected = min(max(0, len(self.cards()) - 1), self.selected + 1)
        elif key in ('k', '\x1b[A'):
            if self.panel:
                self.scroll = max(0, self.scroll - 1)
            else:
                self.selected = max(0, self.selected - 1)
        elif key == '\x1b[6~':
            self.scroll += 10
        elif key == '\x1b[5~':
            self.scroll = max(0, self.scroll - 10)
        elif key in ('\x1b[C', 'l') and self.focus == 'actions':
            self.action_index = (self.action_index + 1) % 4
        elif key in ('\x1b[D', 'h') and self.focus == 'actions':
            self.action_index = (self.action_index - 1) % 4
        elif key in ('\r', '\n'):
            if self.focus == 'actions':
                self.handle_key(('e', 'a', 'i', 'c')[self.action_index])
            else:
                self.open_evidence()
        elif key == 'e':
            self.open_evidence()
        elif key == 'v':
            self.open_versions()
        elif key == 'a':
            self.act('accepted')
        elif key == 'i':
            self.act('ignored')
        elif key == 'c' and self.connected and self.card():
            self.focus, self.input_text = 'input', ''
        elif key == 'r':
            self.refresh()
        elif key == 'm':
            self.mark_read()
        elif key == '?':
            self.panel = '帮助'
            self.scroll = 0
            self.panel_content = 'Tab 切焦点；Enter 展开/确认；Esc 返回\ne 证据；v 版本；a 采纳；i 忽略；c 纠正\nPgUp/PgDn 翻页；证据面板 j/k 滚动\nm 标记当前快照已读；r 重连；q 退出。\n输入时普通字符均为正文。采纳不执行建议。'

    def render(self, width=80, height=24):
        width, height = max(10, width), max(6, height)
        title = '无权访问当前项目' if self.denied else '项目 %s · 任务 %s' % (
            self.args.get('project', ''), self.args.get('task', ''))
        lines = ['Thinker · ' + title]
        if not self.denied:
            freshness = '部分来源待对账' if self.snapshot.get('partial_sources') else '版本状态以控制面为准'
            lines.append('仓库 %s · %s · %s' % (self.args.get('repo', ''), self.args.get('ref', ''), freshness))
        lines.append('连接：%s   焦点：%s   已读至 %s / 事件 %s' % (
            '已连接' if self.connected else '已断线', self.focus,
            self.timeline.get('read_cursor', 0), self.cursor if self.connected else 0))
        lines.append('─' * width)
        body = []
        for question in self.snapshot.get('open_questions', []):
            if isinstance(question, dict):
                body.append('待补证据 · %s · 来源或证据已变化' % question.get('judgment_revision', question.get('judgment_id', '')))
            else:
                body.append('待审查 · ' + str(question))
        for index, card in enumerate(self.cards()):
            expires = card.get('expires_at', 0)
            state = '已过期' if float(expires) <= time.time() else '待处理'
            body.extend(['%s 建议 %s · %s · %s' % ('>' if index == self.selected else ' ',
                         card.get('id', ''), card.get('judgment_revision', ''), state),
                         '  ' + str(card.get('next_action', '')),
                         '  证据 %d · 效期 %s' % (len(card.get('evidence_ids', [])),
                             datetime.datetime.fromtimestamp(float(expires), datetime.timezone.utc).isoformat()),
                         '  [e 证据] [a 采纳] [i 忽略] [c 纠正] [v 版本]'])
        if not body:
            body = ['当前任务暂无建议' if self.connected else '离线：不显示缓存正文']
        if self.panel and width >= 110:
            left_width = width * 3 // 5
            body = [line for item in body for line in _wrap(item, left_width)]
            right = [self.panel] + _wrap(self.panel_content, width - left_width - 3)
            body = [_clip(body[i] if i < len(body) else '', left_width)
                    + ' ' * max(0, left_width - display_width(_clip(body[i] if i < len(body) else '', left_width)))
                    + ' │ ' + (right[i] if i < len(right) else '')
                    for i in range(max(len(body), len(right)))]
        elif self.panel:
            body = [self.panel] + _wrap(self.panel_content, width)
        else:
            body = [line for item in body for line in _wrap(item, width)]
        available = max(0, height - len(lines) - 4)
        self.scroll = min(self.scroll, max(0, len(body) - available))
        lines.extend(body[self.scroll:self.scroll + available])
        lines.extend(['─' * width, self.message, '纠正 > ' + self.input_text,
                      'Tab 焦点  Enter 确认  Esc 返回  m 已读  PgUp/Dn 翻页  q 退出'])
        return '\n'.join(_clip(line, width) for line in lines[:height])


def run(request, args):
    """Standalone terminal entry; the caller supplies the authenticated client."""
    session = Session(request, args)
    session.refresh()
    if not sys.stdin.isatty() or not sys.stdout.isatty() or os.environ.get('TERM') == 'dumb':
        print(session.render(80, 24))
        return 0 if session.connected else 1
    fd = sys.stdin.fileno()
    original = termios.tcgetattr(fd)
    decoder = codecs.getincrementaldecoder('utf-8')('replace')
    last_poll, escape = time.monotonic(), ''
    previous_frame = None
    try:
        tty.setcbreak(fd)
        sys.stdout.write('\x1b[?25l')
        while not session.quit:
            size = shutil.get_terminal_size((80, 24))
            frame = session.render(size.columns, size.lines)
            if frame != previous_frame:
                sys.stdout.write('\x1b[H\x1b[2J' + frame)
                sys.stdout.flush()
                previous_frame = frame
            ready, _, _ = select.select([fd], [], [], 0.1)
            if ready:
                chunk = os.read(fd, 4096)
                if not chunk:
                    break
                for char in decoder.decode(chunk):
                    if escape:
                        escape += char
                        if escape in ('\x1b[A', '\x1b[B', '\x1b[C', '\x1b[D', '\x1b[5~', '\x1b[6~'):
                            session.handle_key(escape)
                            escape = ''
                        elif escape not in ('\x1b[', '\x1b[5', '\x1b[6'):
                            session.handle_key('\x1b')
                            for trailing in escape[1:]:
                                session.handle_key(trailing)
                            escape = ''
                    elif char == '\x1b':
                        escape = char
                    else:
                        session.handle_key(char)
            elif escape:
                session.handle_key('\x1b')
                escape = ''
            if time.monotonic() - last_poll >= 1:
                session.poll()
                last_poll = time.monotonic()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, original)
        sys.stdout.write('\x1b[?25h\n')
        sys.stdout.flush()
    return 0
