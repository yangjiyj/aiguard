#!/usr/bin/env python3
"""Verify the image payload against admitted inputs and the current source wrappers."""
import argparse,hashlib,json,pathlib,subprocess
P=pathlib.Path

def run(image,args):
 p=subprocess.run(['docker','run','--pull=never','--network=none','--rm','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--memory=256m','--memory-swap=256m','--cpus=0.5','--entrypoint',args[0],image,*args[1:]],capture_output=True,check=True)
 return p.stdout

def verify(image,receipt,source,revision):
 if not image.startswith('sha256:') or len(image)!=71:raise ValueError('immutable image ID required')
 expected=json.loads(receipt.read_bytes());actual=json.loads(run(image,['/bin/cat','/usr/share/jjdguard/gpu-runtime-input.json']))
 if expected!=actual:raise ValueError('image input receipt mismatch')
 labels=json.loads(subprocess.check_output(['docker','image','inspect','--format','{{json .Config.Labels}}',image]))
 for key,value in {'org.opencontainers.image.revision':revision,'com.jjdguard.cuda_architectures':'86','com.jjdguard.build_mode':'verified-runtime-reuse','com.jjdguard.llama_cpp_revision':expected['llama_revision']}.items():
  if labels.get(key)!=value:raise ValueError('image label mismatch: '+key)
 files={};links={}
 for item in expected['original33']:
  name=P(item['path']).name;path='/opt/llama/'+name;files[path]=item['sha256'];links[path]=item['symlink']
 if len(files)!=33:raise ValueError('invalid original33 manifest')
 for item in expected['files']:
  rel=item['path']
  if rel.startswith('llama/'):target='/opt/llama/'+rel[6:]
  elif rel.startswith('lib/'):target='/opt/jjdguard/cuda-lib/'+rel[4:]
  elif rel.startswith('licenses/'):target='/usr/share/licenses/jjdguard-cuda-runtime/'+rel[9:]
  else:raise ValueError('unexpected runtime input path')
  files[target]=item['sha256']
 for name,target in [('entrypoint.sh','/usr/local/bin/jjdguard-gpu-judge'),('healthcheck.sh','/usr/local/bin/jjdguard-gpu-judge-health')]:files[target]=hashlib.sha256((source/name).read_bytes()).hexdigest()
 output=run(image,['/usr/bin/sha256sum','--',*sorted(files)]).decode();observed={line[66:]:line[:64] for line in output.splitlines()}
 if observed!=files:raise ValueError('image payload checksum mismatch')
 kinds=run(image,['/usr/bin/stat','--format=%F','--',*sorted(links)]).decode().splitlines()
 for path,kind in zip(sorted(links),kinds,strict=True):
  if (kind=='symbolic link')!=links[path]:raise ValueError('native symlink kind mismatch: '+path)
 return {'status':'GPU_IMAGE_PAYLOAD_VERIFIED','image_id':image,'payload_files':len(files),'original33_verified':True,'source_wrappers_verified':True,'cuda_architectures':expected['cuda_architectures'],'original33_recompiled':False,'revision':revision}
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--image',required=True);p.add_argument('--receipt',type=P,required=True);p.add_argument('--source',type=P,required=True);p.add_argument('--revision',required=True);a=p.parse_args();print(json.dumps(verify(a.image,a.receipt,a.source,a.revision),sort_keys=True))
