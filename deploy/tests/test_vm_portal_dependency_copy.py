import os,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"release"))
import build_vm_development as build
class PortalDependencyCopyTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
  self.source=self.root/"input";self.source.mkdir();(self.source/"nested").mkdir()
  (self.source/"nested/package.js").write_text("fixture dependency content");(self.source/"nested/package.js").chmod(0o640)
  (self.source/"alias.js").symlink_to("nested/package.js");self.target=self.root/"copied"
 def test_complete_copy_preserves_bytes_modes_and_relative_symlinks(self):
  build.copy_portal_dependencies(self.source,self.target,{"PATH":"/usr/bin:/bin"})
  self.assertEqual((self.target/"nested/package.js").read_bytes(),(self.source/"nested/package.js").read_bytes())
  self.assertEqual((self.target/"nested/package.js").stat().st_mode&0o777,0o640)
  self.assertEqual(os.readlink(self.target/"alias.js"),"nested/package.js")
 def test_copy_is_independent_from_reviewed_input(self):
  build.copy_portal_dependencies(self.source,self.target,{"PATH":"/usr/bin:/bin"})
  (self.target/"nested/package.js").write_text("modified build-only content")
  self.assertEqual((self.source/"nested/package.js").read_text(),"fixture dependency content")
 def test_preexisting_target_and_root_symlink_are_rejected(self):
  self.target.mkdir()
  with self.assertRaises(AssertionError):build.copy_portal_dependencies(self.source,self.target,{"PATH":"/usr/bin:/bin"})
  link=self.root/"input-link";link.symlink_to(self.source,target_is_directory=True)
  with self.assertRaises(AssertionError):build.copy_portal_dependencies(link,self.root/"other",{"PATH":"/usr/bin:/bin"})
if __name__=="__main__":unittest.main()
