#!/usr/bin/env python3
"""Source-gated VM internal-token rotation; dry-run unless --apply is explicit."""
import argparse
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'deploy/release'))
from build_vm_development import source_gate
from deploy_vm_development import guest


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply',action='store_true')
    parser.add_argument('--vm',default='jjdguard-gateway')
    args=parser.parse_args()
    revision=subprocess.check_output(['git','-C',str(ROOT),'rev-parse','HEAD'],text=True).strip()
    source_gate(ROOT,revision)
    def frozen(path):return subprocess.check_output(['git','-C',str(ROOT),'show',revision+':'+path],text=True)
    pieces=['import types,json\n']
    for name,path in [('vm','deploy/release/vm_development_apply.py'),('crypto','deploy/maintenance/internal_secret_crypto.py'),('rotation','deploy/maintenance/internal_secret_rotation_guest.py')]:
        pieces.append(name+'=types.ModuleType('+repr(name)+')\nexec('+repr(frozen(path))+','+name+'.__dict__)\n')
    pieces.append('try:\n rotation.rotate('+repr(args.apply)+','+repr(revision)+',vm,crypto)\nexcept BaseException as error:\n print(json.dumps({"status":"failed","error_type":type(error).__name__,"code":str(error) if isinstance(error,rotation.RotationError) else "protected_rotation_error"}))\n raise SystemExit(1)\n')
    source_gate(ROOT,revision)
    guest(args.vm,''.join(pieces),seconds=1800)


if __name__=='__main__':main()
