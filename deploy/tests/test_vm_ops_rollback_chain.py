import copy, hashlib, json, os, sys, tempfile, unittest
from pathlib import Path
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"release"))
import vm_development_apply as vm

class OpsRollbackChainTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.root=Path(self.tmp.name)/"managed";self.root.mkdir(mode=0o700)
  self.work=self.root/"releases/r/deploy/docker-compose";self.work.mkdir(parents=True)
  self.backup=self.root/"ops-backups/gateway-public-url-20261014T134442Z";self.backup.mkdir(parents=True,mode=0o700);self.backup.parent.chmod(0o700)
  self.file=self.backup/"rollback-control-plane.json"
  self.models={"name":"project","services":{"control-plane":{"image":"sha256:"+"a"*64,"environment":{"SETTING":"original"}},"gateway-core":{"image":"sha256:"+"b"*64,"environment":{}},"security-engine":{"image":"sha256:"+"c"*64,"environment":{}}},"networks":{},"volumes":{}}
  self.canonical=self.work/"base.json";self.canonical.write_text(json.dumps(self.models));self.canonical.chmod(0o600)
  self.save_backup(self.models)
  self.rows={name:{"Image":model["image"],"Config":{"Env":[k+"="+v for k,v in model["environment"].items()],"Labels":{"com.docker.compose.project.config_files":str(self.file if name=="control-plane"else self.canonical)}}}for name,model in self.models["services"].items()}
  for attr,value in [("ROOT",self.root),("OPS_BACKUP_OWNER_UID",os.getuid())]:
   patch=mock.patch.object(vm,attr,value,create=True);patch.start();self.addCleanup(patch.stop)
 def save_backup(self,model):
  self.file.write_text(json.dumps(model));self.file.chmod(0o600)
  manifest={"complete":True,"working_dir":str(self.work),"rollback_frozen_config":str(self.file),"chain_path":str(self.work/".upgrade/compose-files"),"files":{"rollback-control-plane.json":{"sha256":hashlib.sha256(self.file.read_bytes()).hexdigest(),"bytes":self.file.stat().st_size}}}
  p=self.backup/"manifest.json";p.write_text(json.dumps(manifest));p.chmod(0o600)
 def resolve(self):
  return vm.resolve_release_compose(self.rows,self.work,tuple(self.rows),False,lambda paths:json.loads(paths[0].read_text()),lambda image:image)
 def test_authenticated_root_backup_keeps_full_historical_contract_checks(self):
  canonical,inputs=self.resolve();self.assertEqual(canonical,(self.canonical,));self.assertIn(self.file,inputs);self.assertIn(self.backup/"manifest.json",inputs)
 def test_rejects_tampered_backup_and_manifest_binding(self):
  self.file.write_text('{}')
  with self.assertRaises(RuntimeError):self.resolve()
  self.save_backup(self.models)
  p=self.backup/"manifest.json";data=json.loads(p.read_text());data["working_dir"]=str(self.root/"foreign");p.write_text(json.dumps(data))
  with self.assertRaises(RuntimeError):self.resolve()
 def test_rejects_writable_backup_or_symlink_manifest(self):
  self.file.chmod(0o660)
  with self.assertRaises(RuntimeError):self.resolve()
  self.file.chmod(0o600);p=self.backup/"manifest.json";p.rename(self.backup/"real.json");p.symlink_to(self.backup/"real.json")
  with self.assertRaises(RuntimeError):self.resolve()
 def test_backup_exception_is_control_plane_only(self):
  self.rows["gateway-core"]["Config"]["Labels"]["com.docker.compose.project.config_files"]=str(self.file)
  with self.assertRaises(RuntimeError):self.resolve()
 def test_authenticated_backup_cannot_change_live_contract(self):
  for field,value in [("privileged",True),("image","sha256:"+"d"*64),("environment",{"SETTING":"changed"})]:
   with self.subTest(field=field):
    changed=copy.deepcopy(self.models);changed["services"]["control-plane"][field]=value;self.save_backup(changed)
    with self.assertRaises(RuntimeError):self.resolve()
if __name__=="__main__":unittest.main()
