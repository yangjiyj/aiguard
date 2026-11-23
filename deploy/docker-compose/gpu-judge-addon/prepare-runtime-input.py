#!/usr/bin/env python3
"""Prepare only the reviewed GPU extension and redistributable CUDA runtime inputs.
No compilation, package installation, driver copying, network or model inference.
"""
import argparse,hashlib,json,pathlib,shutil,os
P=pathlib.Path

def digest(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def prepare(core,extension,output,lock):
 if output.exists():raise ValueError('output must not exist')
 if digest(core/'build-result.json')!=lock['core_build_receipt_sha256']:raise ValueError('core receipt hash mismatch')
 if digest(extension)!=lock['extension_receipt_sha256']:raise ValueError('extension receipt hash mismatch')
 receipt=json.loads(extension.read_bytes());original=json.loads((core/'build-result.json').read_bytes())
 if receipt['revision']!=lock['llama_revision'] or receipt['cuda_architecture']!='86-real' or receipt['original33_recompiled'] is not False:raise ValueError('unreviewed runtime identity')
 if original['build_files']!=receipt['original33'] or len(original['build_files'])!=33:raise ValueError('original33 receipt mismatch')
 for item in original['build_files']:
  relative=P(item['path'])
  if relative.is_absolute() or '..' in relative.parts:raise ValueError('unsafe core path')
  p=core/relative
  if p.is_symlink()!=item['symlink'] or digest(p)!=item['sha256']:raise ValueError('original33 payload mismatch')
 addon=P(receipt['addon']['path'])
 if digest(addon)!=lock['addon_sha256']:raise ValueError('CUDA extension hash mismatch')
 inputs=[]
 for entry in lock['libraries']:
  source=P(entry['input']);license=P(entry['copyright'])
  if not source.is_file() or digest(source)!=entry['sha256'] or source.stat().st_size!=entry['bytes']:raise ValueError('CUDA library mismatch: '+entry['soname'])
  if digest(license)!=entry['copyright_sha256']:raise ValueError('CUDA copyright mismatch')
  inputs.extend([(source,'lib/'+entry['soname']),(license,'licenses/'+entry['soname']+'.copyright')])
 inputs.append((addon,'llama/libggml-cuda.so'))
 output.mkdir(mode=0o700,parents=False)
 files=[]
 for source,relative in inputs:
  dest=output/relative;dest.parent.mkdir(mode=0o700,parents=True,exist_ok=True);shutil.copyfile(source,dest);os.chmod(dest,0o444)
  with dest.open('rb') as f:os.fsync(f.fileno())
  files.append({'path':relative,'bytes':dest.stat().st_size,'sha256':digest(dest)})
 result={'schema':'jjdguard-gpu-runtime-input/v1','lock_sha256':digest(P(__file__).with_name('runtime-input.lock.json')),'base_image':lock['base_image'],'llama_revision':lock['llama_revision'],'cuda_architectures':lock['cuda_architectures'],'cuda_toolkit':lock['cuda_toolkit'],'original33':receipt['original33'],'original33_recompiled':False,'extension_receipt_sha256':digest(extension),'files':files,'driver_included':False}
 with (output/'receipt.json').open('x') as f:json.dump(result,f,indent=2,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
 return result

if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('--core',type=P,required=True);parser.add_argument('--extension-receipt',type=P,required=True);parser.add_argument('--output',type=P,required=True);args=parser.parse_args()
 lock=json.loads(P(__file__).with_name('runtime-input.lock.json').read_bytes());result=prepare(args.core,args.extension_receipt,args.output,lock);print(json.dumps({'status':'VERIFIED_RUNTIME_INPUT_PREPARED','files':len(result['files']),'original33_recompiled':False}))
