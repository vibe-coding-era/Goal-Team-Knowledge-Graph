import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from thinker import evidence


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        subprocess.check_call(['git', 'init', '-q', '-b', 'main', str(self.root)])
        self.raw = 'alpha\n中文 beta\nomega\n'.encode()
        (self.root / 'source.txt').write_bytes(self.raw)
        for args in [('config', 'user.email', 'fixture@example.invalid'),
                     ('config', 'user.name', 'Fixture'), ('add', 'source.txt'),
                     ('commit', '-qm', 'fixture')]:
            subprocess.check_call(['git', '-C', str(self.root), *args])
        self.commit = subprocess.check_output(['git', '-C', str(self.root), 'rev-parse', 'HEAD']).decode().strip()
        self.binding = {'scope': 'A', 'repo': 'repo', 'ref': 'refs/heads/main',
                        'source_revision': self.commit, 'config_revision': 1,
                        'ref_generation': 1, 'transition_seq': 0}

    def tearDown(self):
        self.tmp.cleanup()

    def hit(self, start=0, end=None):
        end = len(self.raw) if end is None else end
        return {'path': 'source.txt', 'source_commit': self.commit,
                'file_sha': evidence.digest(self.raw), 'byte_start': start, 'byte_end': end,
                'line_start': self.raw[:start].count(b'\n') + 1,
                'line_end': self.raw[:max(start, end - 1)].count(b'\n') + 1,
                'text': self.raw[start:end].decode()}

    def test_exact_slice_hashes_and_ids_distinguish_same_chunk_crops(self):
        one = evidence.validate_source_hit(str(self.root), self.binding, self.hit(0, 5))
        two = evidence.validate_source_hit(str(self.root), self.binding, self.hit(6, 17))
        self.assertEqual(one['content_hash'], evidence.digest(b'alpha'))
        self.assertEqual(two['content_hash'], evidence.digest(self.raw[6:17]))
        self.assertNotEqual(one['id'], two['id'])
        self.assertEqual(one['file_hash'], two['file_hash'])
        self.assertEqual(one['source_kind'], 'gtkg_source')
        self.assertEqual(one['config_revision'], 1)

    def test_mismatch_hash_text_revision_lines_and_utf8_boundary_rejected(self):
        for field, value in [('text', 'invented'), ('file_sha', 'sha256:' + '0' * 64),
                             ('source_commit', '0' * 40), ('line_start', 9), ('byte_start', 7)]:
            hit = self.hit()
            hit[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                evidence.validate_source_hit(str(self.root), self.binding, hit)

    def test_pinned_blob_ignores_dirty_tree_and_rejects_symlinks(self):
        (self.root / 'source.txt').write_text('dirty')
        self.assertEqual(evidence.git_blob(str(self.root), self.commit, 'source.txt'), self.raw)
        (self.root / 'link').symlink_to('/etc/passwd')
        subprocess.check_call(['git', '-C', str(self.root), 'add', 'link'])
        subprocess.check_call(['git', '-C', str(self.root), 'commit', '-qm', 'link'])
        head = subprocess.check_output(['git', '-C', str(self.root), 'rev-parse', 'HEAD']).decode().strip()
        with self.assertRaises(ValueError):
            evidence.git_blob(str(self.root), head, 'link')

    def test_mock_adapter_obeys_same_validation_and_partial_contract(self):
        adapter = evidence.MockAdapter({'result': {'evidence': [self.hit()], 'status': 'complete'}})
        good = adapter.search(str(self.root), self.binding, 'alpha')
        self.assertEqual(good['status'], 'fresh')
        self.assertEqual(good['evidence'][0]['text'], self.raw.decode())
        broken = self.hit()
        broken['text'] = 'not the source'
        bad = evidence.MockAdapter({'result': {'evidence': [broken], 'status': 'complete'}})
        result = bad.search(str(self.root), self.binding, 'alpha')
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['evidence'], [])

    def test_knowledge_page_has_page_locator_not_fabricated_source_location(self):
        page = '解释：alpha 的说明。\n'
        (self.root / 'page.md').write_text(page)
        hit = {'knowledge_path': 'page.md', 'snippet': page[3:8], 'evidence': {
            'knowledge_path': 'page.md', 'knowledge_sha256': evidence.digest(page.encode()),
            'snippet_char_start': 3, 'snippet_char_end': 8,
            'source_sha256': evidence.digest(self.raw)}}
        result = evidence.bind_knowledge_page(str(self.root), 'sha256:' + 'a' * 64,
                                               self.binding, hit)
        self.assertEqual(result['source_kind'], 'knowledge_page')
        self.assertEqual(result['locator']['page_path'], 'page.md')
        self.assertNotIn('source_path', result['locator'])
        self.assertEqual(result['binding_status'], 'partial')
        self.assertEqual(result['source_bindings'], [])
        self.assertEqual(result['content_hash'], evidence.digest(page[3:8].encode()))
        hit['evidence']['source_bindings'] = [self.hit()]
        bound = evidence.bind_knowledge_page(str(self.root), 'sha256:' + 'a' * 64,
                                              self.binding, hit, location=str(self.root))
        self.assertEqual(bound['binding_status'], 'source_bound')
        self.assertEqual(len(bound['source_bindings']), 1)

    def test_knowledge_page_escape_or_fake_hash_rejected(self):
        hit = {'knowledge_path': '../outside', 'evidence': {'knowledge_path': '../outside',
            'knowledge_sha256': 'sha256:' + 'a' * 64, 'snippet_char_start': 0,
            'snippet_char_end': 1}, 'snippet': 'x'}
        with self.assertRaises(ValueError):
            evidence.bind_knowledge_page(str(self.root), 'sha256:' + 'b' * 64, self.binding, hit)

    def test_gtkg_configuration_is_pinned_and_not_reader_overridable(self):
        with self.assertRaises(ValueError):
            evidence.GTKGAdapter({'handoff': '/missing/handoff.json', 'binary': '/bin/sh'})

    @unittest.skipUnless(os.environ.get('THINKER_REAL_GTKG_HANDOFF'), 'explicit local GTKG fixture not configured')
    def test_real_gtkg_graph_search_pinned_source_roundtrip(self):
        path = Path(os.environ['THINKER_REAL_GTKG_HANDOFF'])
        config = json.loads(path.read_text())
        binary = shutil.which('gtkg') or str(Path.home() / '.cargo' / 'bin' / 'gtkg')
        adapter = evidence.GTKGAdapter({'handoff': str(path), 'binary': binary})
        binding = dict(self.binding, source_revision=config['source_commit'])
        query = os.environ.get('THINKER_REAL_GTKG_QUERY', 'main')
        result = adapter.search(config['source_root'], binding, query, 2)
        self.assertTrue(result['evidence'])
        self.assertTrue(all(item['source_revision'] == config['source_commit'] for item in result['evidence']))
        self.assertTrue(all(item['source_kind'] == 'gtkg_source' for item in result['evidence']))
        self.assertEqual(result['index_revision'], config['source_commit'])


if __name__ == '__main__':
    unittest.main()
