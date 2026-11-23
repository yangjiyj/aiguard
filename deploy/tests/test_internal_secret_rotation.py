"""Real PostgreSQL crypto migration/CAS test, using a network-isolated fixture."""
import importlib.util
from pathlib import Path
import json
import subprocess
import tempfile
import time
import unittest
import uuid

ROOT=Path(__file__).resolve().parents[2]
def module(name,file):
    spec=importlib.util.spec_from_file_location(name,ROOT/'deploy/maintenance'/file)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
crypto=module('crypto_rotation_fixture','internal_secret_crypto.py')
rotation=module('rotation_fixture','internal_secret_rotation_guest.py')


class InternalRotationTests(unittest.TestCase):
    def test_real_sql_preserves_payloads_and_rejects_a_concurrent_row(self):
        image=subprocess.check_output(['docker','image','inspect','--format','{{.Id}}','postgres:16-alpine'],text=True).strip()
        name='jjdguard-secret-rotation-test-'+uuid.uuid4().hex[:12]
        container=subprocess.check_output(['docker','run','--rm','-d','--network','none','--name',name,'-e','POSTGRES_HOST_AUTH_METHOD=trust',image],text=True).strip()
        command=['docker','exec','-i',container,'psql','-X','-qAt','-v','ON_ERROR_STOP=1','-U','postgres','-d','postgres']
        def sql(text):return subprocess.check_output(command,input=text,text=True,stderr=subprocess.PIPE)
        try:
            for _ in range(100):
                final_process=subprocess.run(['docker','exec',container,'cat','/proc/1/comm'],capture_output=True,text=True).stdout.strip()=='postgres'
                if final_process and subprocess.run(['docker','exec',container,'pg_isready','-U','postgres'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:break
                time.sleep(.2)
            else:self.fail('fixture unavailable')
            sql('CREATE TABLE ca_certificates(id text,tenant_id text,private_key_encrypted text,certificate_pem text); CREATE TABLE proxy_inspection_parts(tenant_id text,request_id text,part_index integer,payload_encrypted text,result_encrypted text,PRIMARY KEY(tenant_id,request_id,part_index));')
            old='rotation-fixture-old';new='rotation-fixture-new'
            plain='保留待检内容与已完成结果'.encode()
            ca=crypto.CA_PREFIX+crypto._seal(b'private fixture',crypto.ca_key(old),crypto.CA_DOMAIN)
            sql("INSERT INTO ca_certificates VALUES('ca','tenant',"+rotation.quote(ca)+",'unchanged-public-certificate');")
            sql("INSERT INTO ca_certificates VALUES('ca-global',NULL,"+rotation.quote(ca)+",'unchanged-global-certificate');")
            for index in range(3):
                payload=crypto._seal(plain,crypto.queue_key(old),f'tenant/request/{index}/payload'.encode())
                result=crypto._seal(plain,crypto.queue_key(old),f'tenant/request/{index}/result'.encode())
                sql("INSERT INTO proxy_inspection_parts VALUES('tenant','request',"+str(index)+','+rotation.quote(payload)+','+rotation.quote(result)+');')
            with tempfile.TemporaryDirectory(prefix='rotation-plan-') as folder:
                path=Path(folder)/'forward.sql'
                probe={}
                counts=rotation.prepare_rekey(sql,old,new,path,crypto,probe)
                self.assertEqual(counts,{'ca':2,'parts':3})
                self.assertNotIn(old,path.read_text());self.assertNotIn(new,path.read_text())
                extra=crypto._seal(plain,crypto.queue_key(old),b'tenant/request/99/payload')
                sql("INSERT INTO proxy_inspection_parts VALUES('tenant','request',99,"+rotation.quote(extra)+",'');")
                attempt=subprocess.run(command,input=path.read_text(),text=True,capture_output=True)
                self.assertNotEqual(attempt.returncode,0)
                self.assertEqual(sql("SELECT private_key_encrypted FROM ca_certificates WHERE id='ca';").strip(),ca)
                sql('DELETE FROM proxy_inspection_parts WHERE part_index=99;')
                sql(path.read_text())
                self.assertEqual(sql(probe['query']).strip(),probe['new'])
                revised=sql("SELECT private_key_encrypted FROM ca_certificates WHERE id='ca-global';").strip()
                self.assertEqual(crypto._open(revised[len(crypto.CA_PREFIX):],crypto.ca_key(new),crypto.CA_DOMAIN),b'private fixture')
                self.assertEqual(sql("SELECT certificate_pem FROM ca_certificates WHERE id='ca';").strip(),'unchanged-public-certificate')
                for line in sql('SELECT row_to_json(p) FROM proxy_inspection_parts p ORDER BY part_index;').splitlines():
                    row=json.loads(line)
                    for kind in ('payload','result'):
                        aad=f"tenant/request/{row['part_index']}/{kind}".encode()
                        self.assertEqual(crypto._open(row[kind+'_encrypted'],crypto.queue_key(new),aad),plain)
                        with self.assertRaises(Exception):crypto._open(row[kind+'_encrypted'],crypto.queue_key(old),aad)
                reverse=Path(folder)/'reverse.sql'
                rotation.prepare_rekey(sql,new,old,reverse,crypto);sql(reverse.read_text())
                restored=sql("SELECT private_key_encrypted FROM ca_certificates WHERE id='ca';").strip()
                self.assertEqual(crypto._open(restored[len(crypto.CA_PREFIX):],crypto.ca_key(old),crypto.CA_DOMAIN),b'private fixture')
        finally:
            row=json.loads(subprocess.check_output(['docker','inspect',container],text=True))[0]
            if row['Name']!='/'+name or row['Image']!=image:raise RuntimeError('fixture identity changed')
            subprocess.run(['docker','stop','-t','2',container],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)


if __name__=='__main__':unittest.main()
