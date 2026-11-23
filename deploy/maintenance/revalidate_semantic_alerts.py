#!/usr/bin/env python3
"""Recompute exact semantic evidence; dry-run first, then apply a reviewed plan hash."""
import argparse,json,sys,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'deploy/release'))
from deploy_vm_development import guest
def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--since',default='2026-09-19 00:23:00+08')
 p.add_argument('--previous-backup',default='/opt/jjdguard/maintenance-backups/semantic-revalidate-20260921T195146738141Z.jsonl')
 p.add_argument('--max-judge-calls',type=int,default=256)
 p.add_argument('--output',required=True)
 p.add_argument('--reuse-outcomes',action='store_true')
 p.add_argument('--apply-plan');p.add_argument('--plan-sha256')
 a=p.parse_args()
 if not 0<=a.max_judge_calls<=2000:p.error('judge limit must be 0..2000')
 if bool(a.apply_plan)!=bool(a.plan_sha256):p.error('apply requires the reviewed plan and SHA256 together')
 folder=Path(__file__).parent
 counter_source=(ROOT/'packages/shared-go/alertcounter/sql.go').read_text()
 facts=re.search(r'const facts = `(.+?)`',counter_source,re.S).group(1)
 counter_sql='WITH target AS (SELECT id AS group_id FROM alert_groups WHERE tenant_id=$1 AND id=$2)'+facts+' SELECT row_to_json(agg) FROM agg'
 code='COUNTER_SQL='+repr(counter_sql)+'\nOPTIONS='+repr(vars(a))+'\nCORE='+repr((folder/'semantic_recompute.py').read_text())+'\nWORKER='+repr((folder/'semantic_recompute_worker.py').read_text())+'\n'+(folder/'semantic_recompute_guest.py').read_text()
 guest('jjdguard-gateway',code,seconds=10800)
if __name__=='__main__':main()
