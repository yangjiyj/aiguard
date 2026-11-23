import importlib.util, sys, unittest, tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"release"))
from build_vm_development import is_home_task_path
class TaskRootPaths(unittest.TestCase):
 def test_approved_worktrees_and_artifacts(self):
  for p in ["/home/dev/jjdguard-src","/fast/home-yj/codex-work/token-fix/candidate"]:
   self.assertTrue(is_home_task_path(p),p)
 def test_escape_and_prefix_confusion_are_rejected(self):
  for p in ["/tmp/task","/home/dev-other/task","/fast/home-yj/codex-work-other/task","/fast/home-yj/codex-work/../other/task","/fast/home-yj/codex-work","/home/dev"]:
   self.assertFalse(is_home_task_path(p),p)
 def test_symlink_to_unapproved_root_is_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/"link";p.symlink_to('/tmp',target_is_directory=True)
   self.assertFalse(is_home_task_path(p/'outside'))
if __name__=='__main__':unittest.main()
