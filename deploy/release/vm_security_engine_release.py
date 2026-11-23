#!/usr/bin/env python3
"""Narrow VM transaction: only SE changes; rollback is bound to a pinned receipt."""
import argparse
import copy
import fcntl
import hashlib
import json
import os
import re
import shutil
import tarfile
import time
from pathlib import Path

import vm_development_apply as vm

SERVICE = "security-engine"
RELEASE_ID = r"dev-[A-Za-z0-9-]+"
SHA256 = r"[0-9a-f]{64}"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def object_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def protected(path, directory=False):
    """Never accept writable/symlinked guest evidence or follow an escaped path."""
    path = Path(path)
    require(path.is_absolute() and path.is_relative_to(vm.ROOT), "evidence escapes release root")
    for parent in [*reversed(path.parents), path]:
        if not parent.is_relative_to(vm.ROOT):
            continue
        info = parent.lstat()
        require(not parent.is_symlink() and info.st_uid == 0 and not info.st_mode & 0o022,
                "unprotected release evidence")
    require(path.is_dir() if directory else path.is_file(), "release evidence unavailable")
    return path


def inspect_all():
    ids = vm.run(["docker", "ps", "-aq"]).split()
    require(bool(ids), "VM containers unavailable")
    return json.loads(vm.run(["docker", "inspect", *ids]))


def project_services(rows, project):
    result = {}
    for row in rows:
        labels = row["Config"].get("Labels") or {}
        if labels.get("com.docker.compose.project") != project:
            continue
        service = labels.get("com.docker.compose.service")
        require(service and service not in result, "ambiguous project service")
        result[service] = row
    require(SERVICE in result, "security-engine container absent")
    return result


def fingerprints(rows):
    result = {}
    for row in rows:
        stable = {k: row.get(k) for k in ("Config", "HostConfig", "Mounts", "NetworkSettings", "Name", "Path", "Args")}
        stable["Mounts"] = sorted(row.get("Mounts") or [], key=object_hash)
        result[row["Id"]] = dict(vm.safe_identity({"row": row})["row"], config_sha256=object_hash(stable),
                                 runtime_contract=runtime_contract(row))
    return result


def non_target(rows, project):
    target = project_services(rows, project)[SERVICE]["Id"]
    return fingerprints([row for row in rows if row["Id"] != target])


def runtime_contract(row):
    """Recreation may change hostname and Compose bookkeeping, not runtime inputs."""
    config = copy.deepcopy(row["Config"])
    for key in ("Hostname", "Image"):
        config.pop(key, None)
    config["Env"] = sorted(config.get("Env") or [])
    labels = config.get("Labels") or {}
    for key in ("com.docker.compose.config-hash", "com.docker.compose.project.config_files"):
        labels.pop(key, None)
    networks = {name: {key: value.get(key) for key in ("NetworkID", "IPAMConfig", "Aliases", "Links", "DriverOpts")}
                for name, value in row.get("NetworkSettings", {}).get("Networks", {}).items()}
    mounts = sorted(row.get("Mounts") or [], key=object_hash)
    return object_hash(dict(config=config, host=row.get("HostConfig"), mounts=mounts, networks=networks))


def check_image_archive(media, manifest):
    require(vm.digest(media/"images.tar") == manifest["images_sha256"], "image transfer differs")
    record = manifest["services"][SERVICE]
    with tarfile.open(media/"images.tar") as archive:
        index = json.load(archive.extractfile("manifest.json"))
        require(len(index) == 1 and index[0].get("RepoTags") == [record["tag"]],
                "security-engine-only archive contains other images")
        config = archive.extractfile(index[0]["Config"])
        require(config is not None and "sha256:"+hashlib.file_digest(config, "sha256").hexdigest() == record["image_id"],
                "archive image config differs")


def frozen_models(model, manifest, old_image, new_image):
    old, new = copy.deepcopy(model), copy.deepcopy(model)
    for value, image in ((old, old_image), (new, new_image)):
        item = value["services"][SERVICE]
        item["image"] = image
        item.pop("build", None)
        item.pop("env_file", None)
        item["pull_policy"] = "never"
    new["services"][SERVICE].setdefault("environment", {}).update(
        JJD_COMMIT=manifest["revision"], JJD_VERSION=manifest["version"],
        JJD_BUILT_AT=manifest["created_at"], SECURITY_ENGINE_BUILD=manifest["revision"])
    new["services"][SERVICE]["environment"].update(vm.semantic_parallel_environment(manifest))
    return old, new


class SecurityEngineRelease:
    def __init__(self, media, expected_manifest):
        self.media = protected(media, directory=True)
        require(self.media.parent == vm.ROOT/"development-releases", "unexpected release directory")
        require(vm.digest(protected(self.media/"manifest.json")) == expected_manifest, "manifest hash differs")
        self.manifest_sha = expected_manifest
        self.manifest = json.loads((self.media/"manifest.json").read_text())
        m = self.manifest
        require(m.get("schema") == 1 and m.get("purpose") == "development-vm" and m.get("security_engine_only") is True,
                "unsupported security-engine release")
        vm.release_service_sets(m)
        require(re.fullmatch(RELEASE_ID, m["release_id"]) and self.media.name == m["release_id"] and
                re.fullmatch(r"[0-9a-f]{40}", m["revision"]), "invalid release identity")
        for name, field in (("vm_development_apply.py", "apply_script_sha256"),
                            ("vm_security_engine_release.py", "security_engine_script_sha256")):
            require(vm.digest(protected(self.media/name)) == m[field], "release script differs")
        require(m.get("candidate_validation") == {"file_selftest_passed": True, "file_http_selftest_passed": True,
                                                  "tier1": "preserved_not_touched"}, "candidate validation absent")
        require(not m.get("migration_preconditions") and "tier1_probe_sha256" not in m and
                not (self.media/"tier1-window-smoke.py").exists(), "unexpected migration/model inputs")
        self.record = m["services"][SERVICE]
        require(bool(self.record.get("payload_sha256")), "runtime payload evidence absent")
        for key in ("image_id", "base_image_id"):
            require(re.fullmatch(vm.IMAGE_PATTERN, self.record[key]), "unfixed image identity")
        lock_path = self.media.parent/".release.lock"
        self.lock = os.fdopen(os.open(lock_path, os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600), "w")
        protected(lock_path)
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.state = self.media/"state"
        self.pointer = self.media.parent/"current.json"
        self.log = self.media/"apply.log"

    def event(self, message):
        with self.log.open("a") as stream:
            stream.write(message+"\n")
        print(message, flush=True)

    def image(self, name):
        return json.loads(vm.run(["docker", "image", "inspect", name]))[0]

    def compose(self, *args, files=None):
        command = [str(self.workdir/"bin/docker-compose"), "--project-directory", str(self.workdir), "-p", self.project]
        for path in files or (self.live,):
            command += ["-f", str(path)]
        return vm.run(command+list(args), log=None if args[0] == "config" else self.log)

    def render(self, files):
        return json.loads(self.compose("config", "--format", "json", files=files))

    def pointer_bytes(self):
        return protected(self.pointer).read_bytes() if self.pointer.exists() or self.pointer.is_symlink() else None

    def runtime_path(self, path, directory=False):
        # Existing installations and their Compose binary may be installer-user
        # owned. Freeze their bytes; root ownership is required for new evidence.
        path = Path(path)
        require(path.is_absolute() and path.is_relative_to(self.workdir) and ".." not in path.parts, "runtime path escaped")
        for parent in [path, *path.parents]:
            if parent.is_relative_to(self.workdir):
                require(not parent.is_symlink(), "symlinked runtime input")
        require(path.is_dir() if directory else path.is_file(), "runtime input missing")
        return path

    def stage(self):
        require(not self.state.exists(), "release state exists; inspect before retrying")
        require(shutil.disk_usage(self.media).free >= 4*1024**3, "insufficient free space")
        rows = inspect_all()
        engines = [r for r in rows if (r["Config"].get("Labels") or {}).get("com.docker.compose.service") == SERVICE]
        require(len(engines) == 1, "ambiguous security-engine deployment")
        original = engines[0]
        labels = original["Config"]["Labels"]
        self.project = labels["com.docker.compose.project"]
        self.workdir = Path(labels["com.docker.compose.project.working_dir"]).resolve()
        require(self.workdir.is_relative_to(vm.ROOT/"releases"), "unexpected runtime path")
        self.runtime_path(self.workdir/"active-config", directory=True)
        self.live = self.workdir/"active-config"/(self.manifest["release_id"]+".json")
        require(not self.live.exists() and not self.live.is_symlink(), "active config already exists")
        services = {s: r for s, r in project_services(rows, self.project).items() if r["State"]["Status"] == "running"}
        require(SERVICE in services, "security-engine baseline is not running")
        for row in services.values():
            require(row["State"]["Status"] == "running" and row["State"].get("Health", {}).get("Status", "healthy") == "healthy",
                    "project baseline unhealthy")
        chains = {s: vm.resolve_compose_chain(services, self.workdir, (s,)) for s in services}
        files = {p for chain in chains.values() for p in chain} | {self.workdir/".env", self.workdir/"bin/docker-compose"}
        hashes = {str(p): vm.digest(self.runtime_path(p)) for p in sorted(files)}
        model = self.render(chains[SERVICE])
        for service, chain in chains.items():
            historical = self.render(chain)
            require(historical.get("name") == model.get("name") == self.project, "Compose project differs")
            left, right = (copy.deepcopy(value["services"][service]) for value in (model, historical))
            for item in (left, right):
                item["image"] = self.image(item["image"])["Id"]
                for key in ("build", "env_file", "pull_policy"):
                    item.pop(key, None)
            require(left == right and left["image"] == services[service]["Image"], "historical service config differs")
            for kind in ("networks", "volumes"):
                require(model.get(kind) == historical.get(kind), "historical resources differ")
            actual_env = dict(v.split("=", 1) for v in services[service]["Config"].get("Env", []) if "=" in v)
            require(all(str(v) == actual_env.get(k) for k, v in left.get("environment", {}).items() if v is not None),
                    "runtime environment differs from Compose")
        check_image_archive(self.media, self.manifest)
        vm.run(["docker", "image", "load", "-i", str(self.media/"images.tar")], timeout=600, log=self.log)
        candidate = self.image(self.record["tag"])
        require(vm.portable_image_id(candidate) == self.record["image_id"], "candidate image config differs")
        expected_labels = {"org.opencontainers.image.revision": self.manifest["revision"],
                           "com.jjdguard.source.tree": self.manifest["tree"],
                           "com.jjdguard.base.image": self.record["base_image_id"],
                           "com.jjdguard.release.id": self.manifest["release_id"]}
        require(all(candidate["Config"].get("Labels", {}).get(k) == v for k, v in expected_labels.items()), "candidate provenance differs")
        old, new = frozen_models(model, self.manifest, original["Image"], candidate["Id"])
        self.state.mkdir(mode=0o700)
        vm.write_json(self.state/"candidate.json", new)
        vm.write_json(self.state/"rollback.json", old)
        for name, value in (("candidate", new), ("rollback", old)):
            require(self.render((self.state/(name+".json"),)) == value, "frozen Compose round-trip differs")
        previous = self.pointer_bytes()
        vm.write_json(self.state/"previous-current.json", None if previous is None else previous.decode())
        require(fingerprints(inspect_all()) == fingerprints(rows), "runtime changed during stage")
        require(all(vm.digest(self.runtime_path(p)) == checksum for p, checksum in hashes.items()), "configuration changed during stage")
        before = dict(project=self.project, workdir=str(self.workdir), live=str(self.live),
                      runtime=fingerprints(rows), non_target=non_target(rows, self.project),
                      old_image=original["Image"], new_image=candidate["Id"], old_contract=runtime_contract(original),
                      files=hashes,
                      artifacts={name: vm.digest(self.state/name) for name in ("candidate.json", "rollback.json", "previous-current.json")})
        vm.write_json(self.state/"before.json", before)
        self.event("STAGED security-engine only; no services or database changed")

    def load_state(self):
        self.before = json.loads(protected(self.state/"before.json").read_text())
        self.project = self.before["project"]
        self.workdir = Path(self.before["workdir"])
        self.live = Path(self.before["live"])
        require(self.workdir.is_relative_to(vm.ROOT/"releases") and
                self.live == self.workdir/"active-config"/(self.manifest["release_id"]+".json"), "saved runtime path differs")
        for name, checksum in self.before["artifacts"].items():
            require(name in ("candidate.json", "rollback.json", "previous-current.json") and
                    vm.digest(protected(self.state/name)) == checksum, "saved rollback/configuration differs")
        require(set(self.before["artifacts"]) == {"candidate.json", "rollback.json", "previous-current.json"}, "saved artifacts incomplete")
        self.previous = json.loads((self.state/"previous-current.json").read_text())
        self.previous = None if self.previous is None else self.previous.encode()

    def check_preserved(self, rows):
        require(non_target(rows, self.project) == self.before["non_target"], "non-target container identity/configuration changed")
        for path, checksum in self.before["files"].items():
            require(vm.digest(self.runtime_path(path)) == checksum, "original Compose/environment changed")

    def preflight(self):
        self.load_state()
        rows = inspect_all()
        self.check_preserved(rows)
        require(fingerprints(rows) == self.before["runtime"], "runtime changed since stage")
        require(self.pointer_bytes() == self.previous, "active release changed since stage")
        require(not self.live.exists() and not self.live.is_symlink(), "active config already exists")
        require(vm.portable_image_id(self.image(self.before["new_image"])) == self.record["image_id"], "candidate image changed")
        require(self.image(self.before["old_image"])["Id"] == self.before["old_image"], "rollback image unavailable")

    def replace(self, name):
        # Never stop writers, migrate, fence shared ingress, or restore a database.
        vm.atomic_bytes(self.live, (self.state/name).read_bytes())
        self.compose("up", "-d", "--no-deps", "--pull", "never", "--force-recreate", SERVICE)

    def verify(self, rollback=False):
        deadline = time.monotonic()+180
        while True:
            rows = inspect_all()
            self.check_preserved(rows)
            row = project_services(rows, self.project)[SERVICE]
            if row["State"]["Status"] == "running" and row["State"].get("Health", {}).get("Status", "healthy") == "healthy":
                break
            require(time.monotonic() < deadline, "security-engine health deadline exceeded")
            time.sleep(2)
        expected = self.before["old_image" if rollback else "new_image"]
        require(row["Image"] == expected and row["RestartCount"] == 0, "security-engine image/restarts differ")
        expected_file = "rollback.json" if rollback else "candidate.json"
        require(vm.digest(self.runtime_path(self.live)) == self.before["artifacts"][expected_file], "active configuration differs")
        if rollback:
            require(runtime_contract(row) == self.before["old_contract"], "restored security-engine runtime config differs")
        else:
            env = dict(v.split("=", 1) for v in row["Config"].get("Env", []) if "=" in v)
            require(env.get("JJD_COMMIT") == env.get("SECURITY_ENGINE_BUILD") == self.manifest["revision"], "running revision differs")
            for path, checksum in self.record["payload_sha256"].items():
                require(path.startswith("/app/") and ".." not in Path(path).parts, "invalid payload path")
                actual = vm.run(["docker", "exec", row["Id"], "sha256sum", "--", path]).split()[0]
                require(actual == checksum, "runtime payload differs")
        # Read the credential in the container; never pass it in argv or log the response.
        probe = ("import json,os,urllib.request; "
                 "r=urllib.request.Request('http://127.0.0.1:8000/ready',"
                 "headers={'X-JJDGuard-Internal-Token':os.environ.get('JJD_INTERNAL_API_SECRET','')}); "
                 "v=json.load(urllib.request.urlopen(r,timeout=30)); "
                 "print('ready' if v.get('ready') else 'unready')")
        require(vm.run(["docker", "exec", row["Id"], "python", "-c", probe]) == "ready", "security-engine not ready")
        self.check_preserved(inspect_all())
        return fingerprints(rows)

    def commit(self, after):
        vm.write_json(self.state/"after.json", after)
        receipt = dict(schema=1, purpose="security-engine-only", status="deployed", release_id=self.manifest["release_id"],
                       revision=self.manifest["revision"], manifest_sha256=self.manifest_sha,
                       before_sha256=vm.digest(self.state/"before.json"), after_sha256=vm.digest(self.state/"after.json"),
                       old_image=self.before["old_image"], image=self.before["new_image"])
        vm.write_json(self.media/"receipt.json", receipt)
        receipt_sha = vm.digest(self.media/"receipt.json")
        vm.write_json(self.pointer, dict(release=str(self.media), receipt_sha256=receipt_sha))
        self.event("COMMIT security-engine receipt_sha256="+receipt_sha)

    def restore_pointer(self):
        current = self.pointer_bytes()
        if current == self.previous:
            return
        pointer = json.loads(current) if current is not None else {}
        require(pointer.get("release") == str(self.media) and
                pointer.get("receipt_sha256") == vm.digest(protected(self.media/"receipt.json")), "active receipt changed; pointer not restored")
        if self.previous is None:
            self.pointer.unlink()
        else:
            vm.atomic_bytes(self.pointer, self.previous)

    def restore(self):
        # Attempt to recover SE even if another container drifted during apply;
        # verify still refuses to declare success until every preservation check passes.
        require(vm.digest(protected(self.state/"rollback.json")) == self.before["artifacts"]["rollback.json"], "rollback config changed")
        require(self.image(self.before["old_image"])["Id"] == self.before["old_image"], "rollback image unavailable")
        self.replace("rollback.json")
        after = self.verify(rollback=True)
        vm.write_json(self.media/"rollback.json", dict(status="rolled_back", release_id=self.manifest["release_id"],
                                                      old_image=self.before["old_image"], runtime=after))
        self.restore_pointer()
        self.event("ROLLBACK security-engine verified; other containers unchanged")

    def apply(self):
        self.preflight()
        try:
            self.replace("candidate.json")
            self.commit(self.verify())
        except BaseException:
            try:
                self.restore()
            except BaseException:
                raise RuntimeError("security-engine rollback incomplete; inspect protected state before retrying") from None
            raise

    def rollback(self, expected_receipt):
        receipt = pinned_receipt(self.media, expected_receipt)
        require(receipt["manifest_sha256"] == self.manifest_sha, "receipt manifest differs")
        require(vm.digest(protected(self.state/"before.json")) == receipt["before_sha256"] and
                vm.digest(protected(self.state/"after.json")) == receipt["after_sha256"], "receipt evidence changed")
        self.load_state()
        require(receipt["old_image"] == self.before["old_image"] and receipt["image"] == self.before["new_image"], "receipt image identity differs")
        rows = inspect_all()
        self.check_preserved(rows)
        row = project_services(rows, self.project)[SERVICE]
        after = json.loads((self.state/"after.json").read_text())
        actual = fingerprints([row])[row["Id"]]
        recorded = after.get(row["Id"], {})
        # SE may be unhealthy/restarted after external tests, but must still be
        # this receipt's exact container, image and runtime configuration.
        require(all(actual.get(k) == recorded.get(k) for k in ("id", "image", "runtime_contract")), "active SE no longer belongs to receipt")
        require(vm.digest(self.runtime_path(self.live)) == self.before["artifacts"]["candidate.json"], "active config changed")
        self.restore()


def pinned_receipt(media, expected):
    require(re.fullmatch(SHA256, expected), "full receipt SHA256 required")
    pointer = json.loads(protected(vm.ROOT/"development-releases/current.json").read_text())
    require(pointer == {"release": str(media), "receipt_sha256": expected}, "only the active recorded release can be rolled back")
    require(vm.digest(protected(media/"receipt.json")) == expected, "receipt hash differs")
    receipt = json.loads((media/"receipt.json").read_text())
    require(receipt.get("schema") == 1 and receipt.get("purpose") == "security-engine-only" and
            receipt.get("status") == "deployed" and receipt.get("release_id") == media.name, "unsupported rollback receipt")
    require(vm.digest(protected(media/"manifest.json")) == receipt["manifest_sha256"], "recorded manifest changed")
    return receipt


def rollback_guest_code(release_id, receipt_sha):
    """Bootstrap emitted ONLY after the current checkout passes live source_gate.

    The pinned active receipt anchors old media before any code in it executes.
    No caller-selected paths, revisions, replacement scripts or images are accepted.
    """
    require(re.fullmatch(RELEASE_ID, release_id) and re.fullmatch(SHA256, receipt_sha), "invalid rollback identity")
    # Inline only data validation; do not import an unverified media module.
    import inspect
    validators = "\n\n".join(inspect.getsource(fn) for fn in (require, protected, pinned_receipt))
    return ("import hashlib,json,os,re,subprocess\nfrom pathlib import Path\nfrom types import SimpleNamespace\n"
            "def digest(p):\n with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()\n"
            "vm=SimpleNamespace(ROOT=Path('/opt/jjdguard'),digest=digest)\nSHA256="+repr(SHA256)+"\n"+validators+"\n"
            "media=vm.ROOT/'development-releases'/"+repr(release_id)+"\n"
            "receipt=pinned_receipt(media,"+repr(receipt_sha)+")\n"
            "require(not (media/'__pycache__').exists() and not list(media.glob('*.pyc')),'unexpected cached release code')\n"
            "manifest=json.loads((media/'manifest.json').read_text())\n"
            "for name,field in [('vm_security_engine_release.py','security_engine_script_sha256'),('vm_development_apply.py','apply_script_sha256')]:\n"
            " require(digest(protected(media/name))==manifest[field],'recorded release script changed')\n"
            "subprocess.run(['/usr/bin/python3','-B',str(media/'vm_security_engine_release.py'),'rollback','--release-id',"
            +repr(release_id)+",'--receipt-sha256',"+repr(receipt_sha)+"],check=True)\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("rollback",))
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--receipt-sha256", required=True)
    args = parser.parse_args()
    require(os.geteuid() == 0, "requires VM root")
    require(re.fullmatch(RELEASE_ID, args.release_id), "invalid release identity")
    os.umask(0o077)
    media = vm.ROOT/"development-releases"/args.release_id
    receipt = pinned_receipt(media, args.receipt_sha256)
    release = SecurityEngineRelease(media, receipt["manifest_sha256"])
    release.rollback(args.receipt_sha256)


if __name__ == "__main__":
    main()
