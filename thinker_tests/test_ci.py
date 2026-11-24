import unittest
from unittest.mock import patch

from thinker import ci


class JobVerification(unittest.TestCase):
    version = {"repo":"source","ref":"refs/heads/main","source_revision":"a"*40}
    run_data = {"id":13,"head_sha":"a"*40,"repository":{"full_name":"example/source"},"event":"push","head_branch":"main"}
    job = {"id":27,"run_id":13,"head_sha":"a"*40,"status":"completed","conclusion":"success","name":"integration",
           "completed_at":"2026-01-01T00:00:00Z"}

    def verify(self, run=None, job=None):
        with patch.object(ci,"read_api",side_effect=[job or self.job,run or self.run_data]):
            return ci.verify_job("https://github.com/example/source.git",27,self.version)

    def test_verified_job_bound_to_repository_commit_run_and_check(self):
        record = self.verify()
        self.assertEqual(record["locator"]["check"],"integration")
        self.assertEqual(record["locator"]["run_id"],"13")
        self.assertEqual(record["source_revision"],self.version["source_revision"])
        self.assertEqual(record["locator"]["conclusion"],"success")
        self.assertEqual(record["assurance"],"github_actions_verified")
        self.assertEqual(record["occurred_at"],1767225600.0)

    def test_same_revision_on_another_branch_is_not_evidence_for_main(self):
        with self.assertRaisesRegex(ValueError, "branch"):
            self.verify(run=dict(self.run_data, head_branch="dev"))

    def test_other_repo_other_revision_pending_job_and_local_origin_rejected(self):
        for changed,field in [(dict(self.job,head_sha="c"*40),"job"),(dict(self.job,status="in_progress"),"job"),
                              (dict(self.run_data,repository={"full_name":"other/source"}),"run"),
                              (dict(self.run_data,event="pull_request"),"run")]:
            with self.assertRaises(ValueError):
                self.verify(**{field:changed})
        with self.assertRaises(ValueError):
            ci.verify_job("file:///local", 27, self.version)
