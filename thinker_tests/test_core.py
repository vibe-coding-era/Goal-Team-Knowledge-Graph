import hashlib
import json
import sqlite3
import time
import unittest
from unittest.mock import patch

from thinker import core


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        core.init_db(self.db)
        self.binding = {"repo": "r", "ref": "refs/heads/main", "source_revision": "a" * 40,
                        "config_revision": 1, "ref_generation": 1}
        self.enabled = True
        self.patches = [patch.object(core, "_current_binding", side_effect=self.current),
                        patch.object(core, "_validate_binding", side_effect=self.valid)]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.db.close()

    def current(self, db, scope, repo, ref, source_revision):
        if not self.enabled or any(self.binding[k] != v for k, v in
                                   (("repo", repo), ("ref", ref), ("source_revision", source_revision))):
            raise ValueError("source unavailable")
        return dict(self.binding)

    def valid(self, db, scope, evidence):
        return self.enabled and all(evidence.get(k) == v for k, v in self.binding.items())

    def call(self, op, scope="scope-a", **args):
        with self.db:
            return core.dispatch(self.db, scope, "alice", op, args)

    def version(self):
        return {k: self.binding[k] for k in ("repo", "ref", "source_revision")}

    def evidence(self, eid="e1", scope="scope-a", kind="source", **extra):
        text = extra.pop("text", "dependency A -> B")
        e = dict(self.version(), id=eid, source_kind=kind, text=text,
                 content_hash="sha256:" + hashlib.sha256(text.encode()).hexdigest(),
                 locator={"path": "a.py", "line_start": 1, "line_end": 1})
        e.update(extra)
        return self.call("evidence.record", scope, evidence=e)

    def publish(self, jid="impact", supports=None, base=0, claim="A affects B"):
        proposed = self.call("judgment.propose", **self.version(), judgment_id=jid,
                             base_revision=base, claim=claim, supports=supports or ["e1"],
                             contradicts=[], review_after=time.time() + 3600)
        return self.call("judgment.publish", **self.version(), judgment_id=jid,
                         revision=proposed["revision"], base_revision=base)

    def recommend(self):
        return self.call("recommendation.send", **self.version(), id="rec", judgment_revision="impact@1",
                         executor_task_id="task", next_action="Run B integration", expected_check="B integration",
                         expires_at=time.time() + 600)

    def feedback(self, **extra):
        args = dict(self.version(), id="feedback", recommendation_id="rec", judgment_revision="impact@1",
                    executor_task_id="task", acceptance="accepted", outcome="unverified",
                    expected_check="B integration", evidence_ids=[], attribution="unknown")
        args.update(extra)
        return self.call("feedback.record", **args)

    def test_scope_isolation_and_cross_project_references(self):
        self.evidence()
        self.publish()
        with self.assertRaises(ValueError):
            self.call("evidence.get", "scope-b", id="e1")
        with self.assertRaises(ValueError):
            self.call("judgment.propose", "scope-b", **self.version(), judgment_id="other", base_revision=0,
                      claim="leak", supports=["e1"], contradicts=[], review_after=time.time() + 20)
        self.assertEqual([], self.call("context.get", "scope-b", **self.version())["active_judgments"])
        self.assertEqual([], self.call("events.list", "scope-b")["events"])

    def test_evidence_hash_immutability_and_generated_page_rejection(self):
        self.evidence()
        self.evidence()
        with self.assertRaises(ValueError):
            self.evidence(text="replacement")
        with self.assertRaises(ValueError):
            self.evidence("bad", content_hash="sha256:" + "0" * 64)
        with self.assertRaises(ValueError):
            self.evidence("wiki", kind="generated_wiki")

    def test_publish_requires_real_support_and_expected_base(self):
        self.evidence()
        self.publish()
        with self.assertRaises(ValueError):
            self.call("judgment.propose", **self.version(), judgment_id="impact", base_revision=0,
                      claim="overwrite", supports=["e1"], review_after=time.time() + 60)
        with self.assertRaises(ValueError):
            self.call("judgment.propose", **self.version(), judgment_id="empty", base_revision=0,
                      claim="unsupported", supports=[], review_after=time.time() + 60)

    def test_publish_materializes_versioned_brief_with_citations(self):
        evidence = self.evidence()
        self.publish()
        row = self.db.execute('SELECT data FROM core_briefs WHERE scope=? AND judgment_id=? AND revision=?',
                              ('scope-a', 'impact', 1)).fetchone()
        stored = json.loads(row[0])
        self.assertEqual(stored['text'], 'A affects B')
        self.assertEqual(stored['judgment_revision'], 'impact@1')
        self.assertEqual(stored['citations'][0]['evidence_id'], 'e1')
        self.assertEqual(stored['citations'][0]['content_hash'], evidence['content_hash'])
        self.assertEqual(stored['citations'][0]['locator']['path'], 'a.py')
        before = self.db.total_changes
        context = self.call('context.get', **self.version())
        self.assertTrue(context['briefs'][0]['pre_generated'])
        self.assertFalse(context['briefs'][0]['authoritative'])
        self.assertEqual(context['briefs'][0]['brief_id'], stored['brief_id'])
        self.assertEqual(before, self.db.total_changes)

    def test_brief_publish_and_outbox_roll_back_together(self):
        self.evidence()
        proposed = self.call('judgment.propose', **self.version(), judgment_id='impact', base_revision=0,
                             claim='A affects B', supports=['e1'], review_after=time.time() + 600)
        before = self.call('events.list')['cursor']
        self.db.execute('BEGIN IMMEDIATE')
        core.dispatch(self.db, 'scope-a', 'alice', 'judgment.publish',
                      dict(self.version(), judgment_id='impact', revision=proposed['revision'], base_revision=0))
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM core_briefs').fetchone()[0], 1)
        self.db.rollback()
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM core_briefs').fetchone()[0], 0)
        self.assertEqual(self.call('events.list')['cursor'], before)
        self.assertFalse(self.call('context.get', **self.version())['active_judgments'])

    def test_brief_snapshot_cannot_restore_superseded_or_revoked_text(self):
        self.evidence(text='private source')
        self.publish(claim='private old claim')
        self.publish(base=1, claim='Current corrected claim')
        context = self.call('context.get', **self.version())
        self.assertEqual([b['judgment_revision'] for b in context['briefs']], ['impact@2'])
        self.assertNotIn('private old', str(context['briefs']))
        self.assertEqual([], self.call('context.get', 'scope-b', **self.version())['briefs'])
        self.binding['ref_generation'] = 2
        self.assertEqual([], self.call('context.get', **self.version())['briefs'])
        self.binding['ref_generation'] = 1
        self.call('evidence.revoke', id='e1', reason='withdrawn')
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM core_briefs').fetchone()[0], 2)
        context = self.call('context.get', **self.version())
        self.assertEqual(context['briefs'], [])
        self.assertEqual(context['brief'], '')

    def test_legacy_brief_read_never_backfills_or_promotes_old_snapshot(self):
        self.evidence()
        self.publish()
        self.db.execute('DROP TABLE core_briefs')
        before = self.db.total_changes
        context = self.call('context.get', **self.version())
        self.assertFalse(context['briefs'][0]['pre_generated'])
        self.assertEqual(context['briefs'][0]['generator'], 'legacy_live')
        self.assertFalse(context['briefs'][0]['authoritative'])
        self.assertIsNone(self.db.execute("SELECT name FROM sqlite_master WHERE name='core_briefs'").fetchone())
        self.assertEqual(before, self.db.total_changes)
        self.publish(base=1, claim='New publication')
        self.assertTrue(self.call('context.get', **self.version())['briefs'][0]['pre_generated'])
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM core_briefs').fetchone()[0], 1)

    def test_corrupt_brief_projection_is_not_a_second_authority(self):
        self.evidence()
        self.publish()
        row = self.db.execute('SELECT data FROM core_briefs').fetchone()
        stored = json.loads(row[0])
        stored['text'] = 'unverified snapshot text'
        self.db.execute('UPDATE core_briefs SET data=?', (json.dumps(stored),))
        context = self.call('context.get', **self.version())
        self.assertNotIn('unverified snapshot', str(context))
        self.assertEqual(context['briefs'], [])
        self.assertIn('brief_unavailable', context['partial_sources'])

    def test_revision_compare_and_swap_and_immutable_history(self):
        self.evidence()
        self.publish()
        self.publish(base=1, claim="A affects B and C")
        context = self.call("context.get", **self.version())
        self.assertEqual(["impact@2"], [j["judgment_revision"] for j in context["active_judgments"]])
        history = self.call("judgment.explain", judgment_id="impact")
        self.assertEqual(["superseded", "active"], [j["status"] for j in history["revisions"]])
        with self.assertRaises(ValueError):
            self.call("judgment.publish", **self.version(), judgment_id="impact", revision=1, base_revision=0)

    def test_revoke_blocks_all_reads_and_does_not_leak_text_in_events(self):
        self.evidence(text="private raw evidence")
        self.publish(claim="private derived claim")
        self.recommend()
        self.call("evidence.revoke", id="e1", reason="access withdrawn")
        self.assertEqual([], self.call("context.get", **self.version())["active_judgments"])
        with self.assertRaises(ValueError):
            self.call("evidence.get", id="e1")
        with self.assertRaises(ValueError):
            core.get_live_judgment(self.db, "scope-a", "impact@1")
        self.assertNotIn("private", str(self.call("judgment.explain", judgment_id="impact")))
        self.assertNotIn("private", str(self.call("events.list")))
        with self.assertRaises(ValueError):
            self.feedback()
        with self.assertRaises(ValueError):
            self.evidence(text="private raw evidence")

    def test_expired_judgment_and_evidence_are_not_context(self):
        self.evidence(expires_at=time.time() + 30)
        self.publish()
        with patch.object(core.time, "time", return_value=time.time() + 40):
            self.assertEqual([], self.call("context.get", **self.version())["active_judgments"])
        with patch.object(core.time, "time", return_value=time.time() + 4000):
            with self.assertRaises(ValueError):
                core.get_live_judgment(self.db, "scope-a", "impact@1")

    def test_repo_changed_removed_or_generation_changed_blocks_reuse(self):
        self.evidence()
        self.publish()
        self.recommend()
        self.binding["ref_generation"] = 2
        self.assertEqual([], self.call("context.get", **self.version())["active_judgments"])
        with self.assertRaises(ValueError):
            self.feedback()
        self.enabled = False
        with self.assertRaises(ValueError):
            self.call("evidence.get", id="e1")

    def test_wrong_commit_evidence_cannot_publish(self):
        self.evidence()
        self.binding["source_revision"] = "b" * 40
        with self.assertRaises(ValueError):
            self.publish()

    def test_recommendation_and_feedback_are_idempotent_and_task_bound(self):
        self.evidence()
        self.publish()
        rec = self.recommend()
        args = dict(self.version(), id="rec", judgment_revision="impact@1", executor_task_id="task",
                    next_action="Run B integration", expected_check="B integration", expires_at=rec["expires_at"])
        self.assertEqual(rec, self.call("recommendation.send", **args))
        with self.assertRaises(ValueError):
            self.feedback(executor_task_id="different-task")
        first = self.feedback()
        self.assertEqual(first, self.feedback())
        with self.assertRaises(ValueError):
            self.feedback(acceptance="rejected")
        events = self.call("events.list")["events"]
        self.assertEqual(1, sum(e["type"] == "RecommendationSent" for e in events))
        self.assertEqual(1, sum(e["type"] == "OutcomeRecorded" for e in events))

    def test_adoption_is_not_verified_success_and_ci_must_match_check(self):
        self.evidence()
        self.publish()
        self.recommend()
        self.assertEqual("unverified", self.feedback(outcome="success")["outcome"])
        self.evidence("ci", kind="ci", locator={"run_id": "run-1", "check": "other check", "conclusion": "success"})
        self.assertEqual("unverified", self.feedback(id="f2", outcome="success", evidence_ids=["ci"])["outcome"])

    def test_ci_verified_failure_and_environment_failure_are_different(self):
        self.evidence()
        self.publish()
        self.recommend()
        self.evidence("ci", kind="ci", locator={"run_id": "run-1", "check": "B integration", "conclusion": "failure"}, attribution="code")
        self.assertEqual("failure", self.feedback(outcome="failure", evidence_ids=["ci"], attribution="code")["outcome"])
        self.evidence("env", kind="ci", locator={"run_id": "run-2", "check": "B integration", "conclusion": "failure"}, attribution="environment")
        self.assertEqual("unverified", self.feedback(id="f2", outcome="failure", evidence_ids=["env"], attribution="environment")["outcome"])

    def test_correction_is_candidate_review_not_silent_rule_overwrite(self):
        self.evidence()
        self.publish()
        self.recommend()
        self.feedback(acceptance="corrected", correction="Need a reproducible CI log")
        self.assertEqual([], self.call("context.get", **self.version())["active_judgments"])
        self.assertEqual("needs_evidence", self.call("judgment.explain", judgment_id="impact")["revisions"][0]["status"])

    def test_outbox_and_domain_write_rollback_together(self):
        self.db.execute("BEGIN IMMEDIATE")
        text = "evidence"
        core.dispatch(self.db, "scope-a", "alice", "evidence.record", {"evidence": dict(self.version(),
                      id="rollback", source_kind="source", text=text, locator={"path": "a.py"},
                      content_hash="sha256:" + hashlib.sha256(text.encode()).hexdigest())})
        self.db.rollback()
        self.assertEqual([], self.call("events.list")["events"])
        with self.assertRaises(ValueError):
            self.call("evidence.get", id="rollback")

    def test_cursor_and_budget_are_bounded_without_read_mutation(self):
        self.evidence()
        self.publish()
        before = self.db.total_changes
        page = self.call("events.list", limit=1)
        second = self.call("events.list", after_cursor=page["cursor"], limit=1)
        self.assertNotEqual(page["events"][0]["event_id"], second["events"][0]["event_id"])
        ctx = self.call("context.get", **self.version(), budget=1)
        self.assertEqual([], ctx["active_judgments"])
        self.assertTrue(ctx["partial_sources"])
        self.assertEqual(before, self.db.total_changes)

    def test_revocation_blocks_new_ids_and_subspans_without_cross_project_leak(self):
        first = self.evidence()
        self.call("evidence.revoke", id="e1", reason="access withdrawn")
        different_span = dict(first, id="other-id", locator={"path": "a.py", "line_start": 2, "line_end": 2})
        self.assertTrue(core.is_revoked(self.db, "scope-a", "e1"))
        self.assertTrue(core.is_revoked(self.db, "scope-a", "other-id", different_span))
        self.assertFalse(core.is_revoked(self.db, "scope-b", "other-id", different_span))
        with self.assertRaises(ValueError):
            self.evidence("other-id")

    def test_capture_generation_is_not_silently_restamped(self):
        with self.assertRaises(ValueError):
            self.evidence(config_revision=999, ref_generation=999)

    def test_feedback_replay_cannot_expand_revoked_raw_correction(self):
        self.evidence()
        self.publish()
        self.recommend()
        self.feedback(correction="private correction")
        self.call("evidence.revoke", id="e1", reason="withdrawn")
        with self.assertRaises(ValueError):
            self.feedback(correction="private correction")

    def test_repeated_adapter_capture_keeps_first_observation_time(self):
        first = self.evidence(occurred_at=123.0)
        again = self.evidence(occurred_at=456.0)
        self.assertEqual(first, again)

    def test_unknown_id_revocation_prevents_later_first_import(self):
        self.call("evidence.revoke", id="not-imported", reason="blocked before capture")
        self.assertTrue(core.is_revoked(self.db, "scope-a", "not-imported"))
        with self.assertRaises(ValueError):
            self.evidence("not-imported")

    def test_page_local_evidence_is_visible_but_not_independent_support(self):
        original = self.evidence()
        page = self.evidence("page", kind="knowledge_page", independent_evidence=False,
                             locator={"page_path": "knowledge/overview.md", "bundle_digest": "sha256:" + "a" * 64},
                             source_bindings=[original])
        self.assertEqual("page", self.call("evidence.get", id=page["id"])["id"])
        with self.assertRaises(ValueError):
            self.publish(supports=["page"])
        self.call("evidence.revoke", id="e1", reason="withdrawn source")
        with self.assertRaises(ValueError):
            self.call("evidence.get", id="page")

    def test_source_change_requests_review_once_without_publishing(self):
        self.evidence()
        self.publish()
        self.binding["source_revision"] = "b" * 40
        with self.db:
            first = core.reconcile_source(self.db, "scope-a", "observer", "r", "refs/heads/main")
        with self.db:
            second = core.reconcile_source(self.db, "scope-a", "observer", "r", "refs/heads/main")
        self.assertEqual(1, first["invalidated"])
        self.assertEqual(0, second["invalidated"])
        ctx = self.call("context.get", **self.version())
        self.assertEqual([], ctx["active_judgments"])
        self.assertTrue(any(isinstance(q, dict) and q.get("judgment_id") == "impact" for q in ctx["open_questions"]))
        events = self.call("events.list")["events"]
        self.assertEqual(1, sum(e["type"] == "SourceChanged" for e in events))
        self.assertNotIn("A affects B", str(events))

    def test_explanation_compares_authorized_history_then_redacts_revoked_history(self):
        self.evidence()
        self.publish(claim="First authorized claim")
        self.publish(base=1, claim="Corrected authorized claim")
        history = self.call("judgment.explain", judgment_id="impact")
        self.assertEqual("First authorized claim", history["revisions"][0].get("claim"))
        self.assertEqual(["e1"], history["revisions"][0]["supports"])
        self.assertTrue(history["revisions"][0]["evidence_refs"])
        self.assertFalse(history["partial"])
        self.call("evidence.revoke", id="e1", reason="withdrawn")
        hidden = self.call("judgment.explain", judgment_id="impact")
        self.assertNotIn("authorized claim", str(hidden))
        self.assertTrue(hidden["partial"])
        self.assertTrue(all(r["redacted"] and r["reason_code"] for r in hidden["revisions"]))

    def test_expired_history_and_corrected_context_are_explicitly_partial(self):
        self.evidence()
        self.publish()
        self.recommend()
        with patch.object(core.time, "time", return_value=time.time() + 4000):
            history = self.call("judgment.explain", judgment_id="impact")
            self.assertTrue(history["revisions"][0]["redacted"])
            self.assertEqual("expired", history["revisions"][0]["reason_code"])
        self.feedback(acceptance="corrected", correction="Please verify")
        context = self.call("context.get", **self.version())
        self.assertTrue(context["partial"])
        self.assertIn("judgment_needs_evidence", context["partial_sources"])

    def test_correction_ack_loss_has_owner_only_metadata_receipt_after_revocation(self):
        self.evidence()
        self.publish()
        self.recommend()
        self.feedback(acceptance="corrected", correction="private correction text")
        args = dict(id="feedback", recommendation_id="rec", judgment_revision="impact@1", executor_task_id="task")
        self.call("evidence.revoke", id="e1", reason="source removed after correction")
        receipt = self.call("feedback.receipt", **args)
        self.assertEqual("corrected", receipt["acceptance"])
        self.assertTrue(receipt["receipt_only"])
        self.assertFalse(receipt["current_authority"])
        self.assertNotIn("private", str(receipt))
        self.assertNotIn("correction", receipt)
        with self.assertRaises(ValueError):
            core.dispatch(self.db, "scope-a", "other-actor", "feedback.receipt", args)
        with self.assertRaises(ValueError):
            self.call("feedback.receipt", "scope-b", **args)
        with self.assertRaises(ValueError):
            self.call("feedback.receipt", **dict(args, executor_task_id="other-task"))

    def test_pending_candidate_quota_is_scoped_and_expired_candidates_release_it(self):
        self.evidence()
        self.evidence(scope="scope-b")
        with patch.object(core, "MAX_CANDIDATES_PER_SCOPE", 2, create=True):
            for jid in ("one", "two"):
                self.call("judgment.propose", **self.version(), judgment_id=jid, base_revision=0,
                          claim="Needs human review", supports=["e1"], review_after=time.time() + 30)
            with self.assertRaisesRegex(ValueError, "candidate quota"):
                self.call("judgment.propose", **self.version(), judgment_id="three", base_revision=0,
                          claim="Over quota", supports=["e1"], review_after=time.time() + 30)
            independent = self.call("judgment.propose", "scope-b", **self.version(), judgment_id="three", base_revision=0,
                                    claim="Independent project", supports=["e1"], review_after=time.time() + 30)
            self.assertEqual("candidate", independent["status"])
            with patch.object(core.time, "time", return_value=time.time() + 40):
                released = self.call("judgment.propose", **self.version(), judgment_id="three", base_revision=0,
                                     claim="New review", supports=["e1"], review_after=time.time() + 30)
                self.assertEqual("candidate", released["status"])

    def test_nonadoption_does_not_imply_advice_caused_successful_check(self):
        self.evidence()
        self.publish()
        self.recommend()
        self.evidence("ci", kind="ci", locator={"run_id": "run", "check": "B integration", "conclusion": "success"}, attribution="code")
        feedback = self.feedback(acceptance="rejected", outcome="success", evidence_ids=["ci"], attribution="code")
        self.assertEqual("success", feedback["outcome"])
        self.assertEqual("not_applicable_not_adopted", feedback.get("advice_attribution"))
        self.assertEqual("code", feedback["check_attribution"])


if __name__ == "__main__":
    unittest.main()
