import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "deploy/hotfix/anthropic-catalog-2.6.14/hotfix.py"
spec = importlib.util.spec_from_file_location("anthropic_hotfix", MODULE)
hotfix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hotfix)

class HotfixContracts(unittest.TestCase):
 def test_complete_package_verified_and_tamper_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)
   payloads={"manifest.json":json.dumps({"schema":"jjdguard-anthropic-hotfix.v1","patch_id":"anthropic-catalog-2614-v1","version":"2.6.14","base_revision":"23e9605c83021ba8cf4b6db83aa0d58b6998a4ec","patched_revision":"fixture","binaries":{"amd64":"bin/control-plane-amd64","arm64":"bin/control-plane-arm64"}}).encode(),"bin/control-plane-amd64":b"amd64","bin/control-plane-arm64":b"arm64","hotfix.py":b"script","install.sh":b"install","rollback.sh":b"rollback","verify.sh":b"verify","README.md":b"notes"}
   for name,body in payloads.items():
    (p/name).parent.mkdir(parents=True,exist_ok=True);(p/name).write_bytes(body)
   (p/"SHA256SUMS").write_text("".join(hashlib.sha256(body).hexdigest()+"  "+name+"\n" for name,body in payloads.items()))
   self.assertEqual(hotfix.verify_package(p)["version"],"2.6.14")
   (p/"bin/control-plane-amd64").write_bytes(b"tampered")
   with self.assertRaisesRegex(RuntimeError,"校验"):hotfix.verify_package(p)
 def test_incomplete_or_traversal_checksum_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d);(p/"SHA256SUMS").write_text("0"*64+"  ../victim\n")
   with self.assertRaises(RuntimeError):hotfix.verify_package(p)
 def test_symlink_payload_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d);(p/"real").write_bytes(b"body");(p/"manifest.json").symlink_to(p/"real")
   (p/"SHA256SUMS").write_text(hashlib.sha256(b"body").hexdigest()+"  manifest.json\n")
   with self.assertRaises(RuntimeError):hotfix.verify_package(p)
 def test_receipt_disk_failure_does_not_skip_auto_restore(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d);(p/"bin").mkdir();(p/"bin/control-plane-amd64").write_bytes(b"fixture");(p/"SHA256SUMS").write_bytes(b"fixture")
   tool=hotfix.Hotfix.__new__(hotfix.Hotfix)
   tool.package=p;tool.manifest={"binaries":{"amd64":"bin/control-plane-amd64"}};tool.arch="amd64"
   tool.state_dir=p;tool.state_file=p/"state.json";tool.target=self.target()
   tool.root=p;tool.compose_dir=p;tool.image_ref="repo:old";tool.project="fixture";tool.inputs={};tool.config={}
   tool.lock=lambda:None;tool.stable_inputs=lambda _inputs:None;tool.other_services=lambda:{}
   tool.inspect=lambda ref:{"Id":"sha256:patched"} if ref!="cid" else {"Image":"sha256:original"}
   tool.run=lambda args,**kwargs:"2.6.14" if "exec" in args else ""
   tool.recreate=mock.Mock();tool.restore=mock.Mock()
   disk_full=False
   def store(path,value):
    nonlocal disk_full
    if value.get("phase")=="applying":disk_full=True
    if disk_full:raise OSError("disk full")
   with mock.patch.object(hotfix,"atomic_json",side_effect=store):
    with self.assertRaisesRegex(RuntimeError,"已自动回滚"):tool.install()
   tool.restore.assert_called_once()

 def target(self):
  return {"Id":"cid","Image":"sha256:original","Config":{"Image":"repo:old","Labels":{"com.docker.compose.service":"control-plane","com.docker.compose.project":"fixture","com.docker.compose.project.working_dir":"/opt/jjdguard/deploy/docker-compose"},"Env":["A=b"],"Cmd":["./control-plane"],"Entrypoint":None,"User":"app","WorkingDir":"/app","Hostname":"cid"},"Mounts":[],"HostConfig":{"NetworkMode":"fixture_default"},"State":{"Running":True,"Status":"running","Health":{"Status":"healthy"}}}
 def test_instance_and_binary_mount_validation(self):
  c=self.target();hotfix.validate_service(c,Path("/opt/jjdguard"),Path("/opt/jjdguard/deploy/docker-compose"))
  for key,value in [("com.docker.compose.project.working_dir","/opt/other"),("com.docker.compose.service","gateway-core")]:
   bad=copy.deepcopy(c);bad["Config"]["Labels"][key]=value
   with self.assertRaises(RuntimeError):hotfix.validate_service(bad,Path("/opt/jjdguard"),Path("/opt/jjdguard/deploy/docker-compose"))
  for mount in ["/app","/app/control-plane","/app/VERSION"]:
   bad=copy.deepcopy(c);bad["Mounts"]=[{"Destination":mount}]
   with self.assertRaises(RuntimeError):hotfix.validate_service(bad,Path("/opt/jjdguard"),Path("/opt/jjdguard/deploy/docker-compose"))
 def test_runtime_contract_preserves_secrets_commands_and_mounts(self):
  c=self.target();other=copy.deepcopy(c);other["Id"]="new";other["Image"]="sha256:patched";other["Config"]["Hostname"]="new";c["Config"]["Labels"]["com.docker.compose.image"]="sha256:original";other["Config"]["Labels"]["com.docker.compose.image"]="sha256:patched";other["Config"]["Labels"]["com.docker.compose.replace"]="old-name"
  self.assertEqual(hotfix.runtime_contract(c),hotfix.runtime_contract(other))
  for modify in [lambda x:x["Config"]["Env"].append("SECRET=changed"),lambda x:x["Config"].update(Cmd=["/other"]),lambda x:x["Mounts"].append({"Source":"/new","Destination":"/data"})]:
   bad=copy.deepcopy(other);modify(bad)
   self.assertNotEqual(hotfix.runtime_contract(c),hotfix.runtime_contract(bad))

if __name__=="__main__":unittest.main()
