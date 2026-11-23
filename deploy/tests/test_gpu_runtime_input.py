#!/usr/bin/env python3
import importlib.util,pathlib,tempfile,json,hashlib,unittest,copy
P=pathlib.Path
spec=importlib.util.spec_from_file_location('gpu_runtime',P(__file__).parents[1]/'docker-compose/gpu-judge-addon/prepare-runtime-input.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class RuntimeInputs(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=P(self.tmp.name);self.core=self.root/'core';self.core.mkdir();self.output=self.root/'out';items=[]
  for i in range(33):
   p=self.core/'build/bin'/('file%d'%i);p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(('native%d'%i).encode());items.append({'path':str(p.relative_to(self.core)),'bytes':p.stat().st_size,'sha256':m.digest(p),'symlink':False})
  (self.core/'build-result.json').write_text(json.dumps({'build_files':items}));self.addon=self.root/'addon.so';self.addon.write_bytes(b'cuda');self.lib=self.root/'libcudart.so.12';self.lib.write_bytes(b'cuda runtime');self.license=self.root/'copyright';self.license.write_text('license')
  self.extension=self.root/'extension.json';self.extension.write_text(json.dumps({'revision':'fixed','cuda_architecture':'86-real','original33_recompiled':False,'original33':items,'addon':{'path':str(self.addon)}}))
  self.lock={'core_build_receipt_sha256':m.digest(self.core/'build-result.json'),'extension_receipt_sha256':m.digest(self.extension),'llama_revision':'fixed','addon_sha256':m.digest(self.addon),'base_image':'sha256:fixed','cuda_architectures':[86],'cuda_toolkit':'12.4','libraries':[{'input':str(self.lib),'soname':self.lib.name,'bytes':self.lib.stat().st_size,'sha256':m.digest(self.lib),'copyright':str(self.license),'copyright_sha256':m.digest(self.license)}]}
 def tearDown(self):self.tmp.cleanup()
 def prepare(self):return m.prepare(self.core,self.extension,self.output,self.lock)
 def rejected(self):
  with self.assertRaises(ValueError):self.prepare()
  self.assertFalse(self.output.exists())
 def test_valid_inputs_copy_payload_and_license_without_driver(self):
  result=self.prepare();self.assertFalse(result['driver_included']);self.assertFalse(result['original33_recompiled']);self.assertEqual((self.output/'llama/libggml-cuda.so').read_bytes(),b'cuda');self.assertTrue((self.output/'licenses/libcudart.so.12.copyright').is_file())
 def test_tampered_core_receipt(self):(self.core/'build-result.json').write_text('{}');self.rejected()
 def test_tampered_extension_receipt(self):self.extension.write_text('{}');self.rejected()
 def test_tampered_original_binary(self):(self.core/'build/bin/file0').write_bytes(b'changed');self.rejected()
 def test_tampered_cuda_extension(self):self.addon.write_bytes(b'changed');self.rejected()
 def test_tampered_cuda_library(self):self.lib.write_bytes(b'changed');self.rejected()
 def test_tampered_license(self):self.license.write_text('changed');self.rejected()
 def test_existing_output_preserved(self):
  self.output.mkdir();(self.output/'existing').write_text('keep')
  with self.assertRaises(ValueError):self.prepare()
  self.assertEqual((self.output/'existing').read_text(),'keep')
if __name__=='__main__':unittest.main()
