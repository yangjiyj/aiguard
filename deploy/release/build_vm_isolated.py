#!/usr/bin/env python3
"""Supervise an engineering build on the fixed isolated VM; source gates stay on home."""
import argparse, fcntl, hashlib, json, os, re, shlex, subprocess, tarfile
from pathlib import Path
from build_vm_development import source_gate, digest, ENGINEERING_SERVICES

VM = "jjdguard-2.6.6-accept"
UUID = "524ef708-c837-4cde-8a05-802506df0665"
SSH = "yj@192.168.122.218"
TASK_ROOT = "/home/dev/jjdguard-isolated-builds"

def remote(argv, **kwargs):
    return subprocess.run(["ssh", "-o", "BatchMode=yes", SSH, shlex.join(argv)], check=True, **kwargs)

def checked_bases(path):
    values = json.loads(Path(path).read_text())
    if set(values) != set(ENGINEERING_SERVICES):
        raise ValueError("isolated engineering build requires exactly three bases")
    if not all(isinstance(v, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", v) for v in values.values()):
        raise ValueError("base images must use complete immutable IDs")
    return values

def validate_media(media, revision, tree, bases, source_sha):
    manifest = json.loads((media/"manifest.json").read_text())
    if manifest["revision"] != revision or manifest["tree"] != tree:
        raise ValueError("returned source identity differs")
    if not manifest.get("engineering_only") or set(manifest["services"]) != set(bases):
        raise ValueError("returned service scope differs")
    if manifest.get("migrations") or manifest.get("enable_file_detection"):
        raise ValueError("returned release changes configuration")
    for service, base in bases.items():
        if manifest["services"][service]["base_image_id"] != base:
            raise ValueError("returned base differs")
    if digest(media/"images.tar") != manifest["images_sha256"]:
        raise ValueError("returned images differ")
    if manifest.get("isolated_source_sha256") != source_sha:
        raise ValueError("returned archive identity differs")
    return manifest

def build(args):
    os.umask(0o077)
    repo = Path(args.repo).resolve()
    out = Path(args.output).resolve()
    if not out.is_relative_to("/home/dev") or out.exists():
        raise ValueError("output must be a new task directory under /home/dev")
    tree = source_gate(repo, args.revision)
    bases = checked_bases(args.bases)
    actual = subprocess.check_output(["virsh", "domuuid", VM], text=True).strip()
    if actual != UUID:
        raise ValueError("isolated VM domain identity differs")
    identity = remote(["sudo", "-n", "cat", "/sys/class/dmi/id/product_uuid"], capture_output=True, text=True).stdout.strip()
    if identity != UUID:
        raise ValueError("isolated SSH guest identity differs")
    lock_path = Path("/home/dev/.cache/jjdguard/home-release.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        out.mkdir(mode=0o700)
        archive = out/"source.tar"
        with archive.open("wb") as stream:
            subprocess.run(["git", "-C", str(repo), "archive", args.revision], stdout=stream, check=True)
        sha = digest(archive)
        job = TASK_ROOT+"/"+args.revision+"-"+out.name
        if not re.fullmatch(r"/home/dev/jjdguard-isolated-builds/[0-9a-f]{40}-[A-Za-z0-9_-]+", job):
            raise ValueError("unsafe isolated job path")
        remote(["mkdir", "-p", TASK_ROOT])
        remote(["mkdir", "-m", "700", job])
        subprocess.run(["scp", str(archive), SSH+":"+job+"/source.tar"], check=True)
        config = dict(revision=args.revision, tree=tree, source_sha256=sha, bases=bases, job=job, uuid=UUID, billing_enabled=args.billing_enabled)
        config_path = out/"worker.json"
        config_path.write_text(json.dumps(config))
        subprocess.run(["scp", str(config_path), SSH+":"+job+"/worker.json"], check=True)
        # Export only reviewed dependency IDs. This is dependency transport, not a customer package.
        base_file = out/"bases.tar"
        export_tags = []
        for service, image in bases.items():
            tag = "jjdguard-isolated-base/"+service+":"+image.split(":")[1]
            subprocess.run(["docker", "image", "tag", image, tag], check=True)
            actual = subprocess.check_output(["docker", "image", "inspect", "--format", "{{.Id}}", tag], text=True).strip()
            if actual != image:
                raise ValueError("dependency export tag differs")
            export_tags.append(tag)
        with base_file.open("wb") as stream:
            subprocess.run(["docker", "image", "save", *export_tags], stdout=stream, check=True)
        base_sha = digest(base_file)
        subprocess.run(["scp", str(base_file), SSH+":"+job+"/bases.tar"], check=True)
        worker = """
import argparse, hashlib, importlib.util, json, os, pathlib, subprocess, tarfile
os.umask(0o077)
root=pathlib.Path(JOB)
cfg=json.loads((root/'worker.json').read_text())
assert pathlib.Path('/sys/class/dmi/id/product_uuid').read_text().strip()==cfg['uuid']
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
assert sha(root/'source.tar')==cfg['source_sha256']
assert sha(root/'bases.tar')==BASE_SHA
subprocess.run(['docker','image','load','-i',str(root/'bases.tar')],check=True,stdout=subprocess.DEVNULL)
source=root/'bootstrap'
source.mkdir()
with tarfile.open(root/'source.tar') as archive:
 assert archive.pax_headers.get('comment')==cfg['revision']
 archive.extractall(source,filter='data')
spec=importlib.util.spec_from_file_location('isolated_builder',source/'deploy/release/build_vm_development.py')
builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
(root/'bases.json').write_text(json.dumps(cfg['bases']))
args=argparse.Namespace(repo=str(source),revision=cfg['revision'],output=str(root/'candidate'),bases=str(root/'bases.json'),billing_enabled=cfg['billing_enabled'],portal_only=False,preserve_tier1=False,engineering_only=True,enable_file_detection=False,migration=[],npm_cache='/home/dev/.npm',go_binary='/home/dev/model-takeover/go/bin/go')
builder.build_fixed_source(args,cfg['tree'],(root/'source.tar',cfg['source_sha256']))
media=root/'candidate/media'
manifest=json.loads((media/'manifest.json').read_text())
manifest['isolated_source_sha256']=cfg['source_sha256']
manifest['build_vm_uuid']=cfg['uuid']
(media/'manifest.json').write_text(json.dumps(manifest,indent=2))
with tarfile.open(root/'media.tar','w') as archive:
 archive.add(media,arcname='media')
(root/'media.sha256').write_text(sha(root/'media.tar'))
"""
        worker = worker.replace("JOB", repr(job)).replace("BASE_SHA", repr(base_sha))
        with (out/"isolated-build.log").open("w") as log:
            remote(["sudo", "-n", "python3", "-"], input=worker, text=True, stdout=log, stderr=subprocess.STDOUT)
        result = out/"media.tar"
        with result.open("wb") as stream:
            remote(["sudo", "-n", "cat", job+"/media.tar"], stdout=stream)
        expected = remote(["sudo", "-n", "cat", job+"/media.sha256"], capture_output=True, text=True).stdout.strip()
        if digest(result) != expected:
            raise ValueError("return transport digest differs")
        with tarfile.open(result) as archive:
            archive.extractall(out, filter="data")
        manifest = validate_media(out/"media", args.revision, tree, bases, sha)
        source_gate(repo, args.revision)
        (out/"source-gate-receipt.json").write_text(json.dumps(dict(revision=args.revision, tree=tree, source_sha256=sha, manifest_sha256=digest(out/"media/manifest.json"), vm_uuid=UUID, isolated_job=job), indent=2))
        print(json.dumps(dict(release_id=manifest["release_id"], media=str(out/"media"))), flush=True)

if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo",required=True)
    parser.add_argument("--revision",required=True)
    parser.add_argument("--bases",required=True)
    parser.add_argument("--output",required=True)
    parser.add_argument("--billing-enabled",choices=("true","false"),required=True)
    build(parser.parse_args())
