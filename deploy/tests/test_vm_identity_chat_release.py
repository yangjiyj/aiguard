"""Identity/chat five-service release uses fake Docker/Compose/guest only."""
import contextlib
import hashlib
import os
import shutil
import tarfile
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"release"))
import build_vm_development as build
import deploy_vm_development as deploy
import vm_development_apply as vm

TARGETS = ("control-plane", "gateway-core", "web-console", "chat-portal-ui", "chat-portal-proxy")
MODEL_SERVICES = ("security-engine", "tier1-classifier", "llm-judge", "chat-idp")
FORBIDDEN = build.CONSOLE_FORBIDDEN_OVERRIDES


def build_args(**changes):
    values = dict(identity_chat_only=True, console_only=False, chat_theme_only=False,
                  security_engine_only=False, engineering_only=False, portal_only=False,
                  preserve_tier1=False, migration=["951_user_model_access.sql",
                  "952_chat_login_tickets.sql"], enable_file_detection=False)
    values.update(changes)
    return SimpleNamespace(**values)


def manifest(**changes):
    values = dict(schema=1, purpose="development-vm", identity_chat_only=True,
                  preserve_tier1=True, portal_only=False, engineering_only=False,
                  revision="a"*40, tree="b"*40, version="2.9.0", created_at="fixture",
                  release_id="dev-identity-chat-test", billing_enabled="true",
                  migrations={"951_user_model_access.sql":"d"*64,
                              "952_chat_login_tickets.sql":"e"*64},
                  migration_preconditions={}, enable_file_detection=False,
                  services={name:dict(image_id="sha256:"+"c"*64) for name in TARGETS})
    values.update(changes)
    return values


class IdentityChatScopeTests(unittest.TestCase):
    def test_generic_dynamic_adapter_preserves_its_original_backup_failure(self):
        import test_vm_development_release as common
        fake=common.Fake(fail="backup")
        with self.assertRaisesRegex(RuntimeError,"backup"):
            vm.perform(fake)
        self.assertEqual(fake.calls,["fence","stop_writers","backup","restart_original","unfence"])

    def test_builder_exactly_selects_five_services_with_reviewed_migrations(self):
        self.assertEqual(build.release_services(build_args()), TARGETS)

    def test_builder_accepts_additional_explicit_reviewed_migration(self):
        args = build_args(migration=["940_reviewed_dependency.sql", "951_user_model_access.sql"])
        self.assertEqual(build.release_services(args), TARGETS)

    def test_builder_rejects_every_other_mode_and_unapproved_setting(self):
        changes = [{key:True} for key in ("console_only", "chat_theme_only", "security_engine_only",
                    "engineering_only", "portal_only", "preserve_tier1", "enable_file_detection")]
        changes += [{key:2} for key in FORBIDDEN]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(AssertionError):
                build.release_services(build_args(**change))

    def test_vm_accepts_exact_scope_and_keeps_models_preserved(self):
        target, preserved = vm.release_service_sets(manifest())
        self.assertEqual(target, TARGETS)
        self.assertEqual(preserved, ("tier1-classifier",))

    def test_vm_refuses_mode_tampering_nonboolean_flags_and_security_overrides(self):
        changes = [{key:True} for key in ("console_only", "chat_theme_only", "security_engine_only",
                    "engineering_only", "portal_only", "enable_file_detection")]
        changes += [dict(identity_chat_only=1), dict(preserve_tier1=False)]
        changes += [{key:2} for key in FORBIDDEN]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                vm.release_service_sets(manifest(**change))

    def test_vm_refuses_missing_or_extra_images(self):
        for extra in MODEL_SERVICES + ("proxy-server", "worker"):
            services = dict(manifest()["services"], **{extra:{}})
            with self.subTest(extra=extra), self.assertRaises(RuntimeError):
                vm.release_service_sets(manifest(services=services))
        services = dict(manifest()["services"])
        services.pop("chat-portal-proxy")
        with self.assertRaises(RuntimeError):
            vm.release_service_sets(manifest(services=services))

    def test_host_accepts_five_service_boot_persistence(self):
        deploy.validate_persist_scope(manifest())

    def test_host_persistence_rejects_extra_images_and_other_modes(self):
        for change in (dict(portal_only=True), dict(console_only=True), dict(identity_chat_only=1),
                       dict(services=dict(manifest()["services"], **{"security-engine":{}}))):
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                deploy.validate_persist_scope(manifest(**change))

    def test_cli_exposes_explicit_identity_chat_flag(self):
        import subprocess
        result = subprocess.run([sys.executable, "-B", str(Path(build.__file__)), "--help"],
                                capture_output=True, text=True, check=True)
        self.assertIn("--identity-chat-only", result.stdout)

    def test_five_service_writer_pause_never_stops_models_or_idp(self):
        with tempfile.TemporaryDirectory() as directory:
            release = vm.Release.__new__(vm.Release)
            release.manifest = manifest()
            release.target_services = TARGETS
            release.workdir = vm.ROOT/"releases"/"fixture"/"deploy"/"docker-compose"
            release.rows = {name:{} for name in vm.WRITERS + ("postgres", "llm-judge", "chat-idp")}
            release.live = Path(directory)/"live.json"
            release.state_dir = Path(directory)
            (release.state_dir/"candidate.json").write_text("{}")
            calls = []
            release.event = lambda message: None
            release.compose = lambda *args, **kwargs: calls.append((args, kwargs))
            with patch.object(vm,"read_drain_evidence",return_value={"active":{},"prepared":{}}):
                release.stop_writers()
            release.switch()
            stopped = calls[0][0][3:]
            self.assertEqual(set(stopped), set(TARGETS + ("proxy-server", "worker", "security-engine")))
            self.assertFalse(set(stopped) & {"tier1-classifier", "llm-judge", "chat-idp"})
            self.assertEqual(calls[1][0][-5:], TARGETS)
            self.assertEqual(set(calls[2][0][1:]), {"proxy-server", "worker", "security-engine"})

    def test_five_service_build_model_preserves_non_target_settings_and_resources(self):
        services = vm.WRITERS + ("postgres", "llm-judge", "chat-idp")
        model = dict(name="fixed", services={name:dict(image="sha256:"+"1"*64,
                     environment={"SECURITY_AUDIT_ONLY":"false", "PRIVATE_SECRET":"preserved"},
                     volumes=[dict(type="volume", source="data", target="/data")]) for name in services},
                     volumes={"data":{}}, networks={"fixed":{}})
        running = {name:dict(Image="sha256:"+"1"*64) for name in services}
        updated = vm.build_model(model, manifest(), running)
        for name in set(services)-set(TARGETS):
            self.assertEqual(updated["services"][name]["environment"], model["services"][name]["environment"])
            self.assertEqual(updated["services"][name]["image"], model["services"][name]["image"])
        self.assertEqual(updated["volumes"], model["volumes"])
        self.assertEqual(updated["networks"], model["networks"])


    def test_proxy_server_requires_explicit_exact_scope_in_builder_host_and_guest(self):
        targets = TARGETS + ("proxy-server",)
        self.assertEqual(build.release_services(build_args(include_proxy_server=True)), targets)
        selected = manifest(include_proxy_server=True, services={name:{} for name in targets})
        self.assertEqual(vm.release_service_sets(selected)[0], targets)
        deploy.validate_persist_scope(selected)
        for flag in (1, "true", None):
            with self.subTest(flag=flag):
                changed = dict(selected, include_proxy_server=flag)
                with self.assertRaises(RuntimeError): vm.release_service_sets(changed)
                with self.assertRaises(RuntimeError): deploy.validate_persist_scope(changed)
        for services in (manifest()["services"], dict(selected["services"], worker={})):
            changed = dict(selected, services=services)
            with self.assertRaises(RuntimeError): vm.release_service_sets(changed)
            with self.assertRaises(RuntimeError): deploy.validate_persist_scope(changed)
        with self.assertRaises(AssertionError):
            build.release_services(build_args(identity_chat_only=False, include_proxy_server=True))
        changed = dict(selected, identity_chat_only=False)
        with self.assertRaises(RuntimeError): vm.release_service_sets(changed)
        with self.assertRaises(RuntimeError): deploy.validate_persist_scope(changed)


class IdentityChatBuildTests(unittest.TestCase):
    def setUp(self):
        old_umask = os.umask(0o077)
        self.addCleanup(os.umask, old_umask)
        self.temp = tempfile.TemporaryDirectory(prefix="identity-chat-build-", dir="/home/dev")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root/"fixture-source"
        self.source.mkdir()
        self.revision, self.tree = "a"*40, "b"*40
        self.query, self.schema = b"fixed-musl-query", b"fixed-musl-schema"
        self.engines = {"libquery_engine-linux-musl-openssl-3.0.x.so.node":self.query,
                        "schema-engine-linux-musl-openssl-3.0.x":self.schema}
        files = {"VERSION":b"2.9.0\n", "deploy/seeds/policy.json":b"{}",
                 "apps/control-plane/cmd/server/main.go":b"package main",
                 "apps/gateway-core/cmd/server/main.go":b"package main",
                 "apps/web-console/package-lock.json":b"{}",
                 "apps/web-console/server.js":b"frozen console server",
                 "enterprise-ai-portal/package-lock.json":json.dumps({"lockfileVersion":3,"packages":{
                     "":{"devDependencies":{"prisma":"6.19.3"}},
                     "node_modules/prisma":{"version":"6.19.3","dependencies":{"@prisma/engines":"6.19.3"}},
                     "node_modules/@prisma/engines":{"version":"6.19.3"}}}).encode(),
                 "enterprise-ai-portal/public/logo.svg":b"<svg/>",
                 "enterprise-ai-portal/prisma/schema.prisma":b"frozen portal schema",
                 "portal-proxy/prisma/schema.prisma":b"frozen proxy schema",
                 "portal-proxy/pnpm-lock.yaml":b"frozen-pnpm-lock",
                 "portal-proxy/tsconfig.json":b"{}",
                 "portal-proxy/src/server.ts":b"frozen proxy source",
                 "portal-proxy/package.json":json.dumps({"packageManager":"pnpm@10.10.0",
                                      "dependencies":{"prisma":"6.19.3","@prisma/client":"6.19.3"}}).encode(),
                 "deploy/migrations/951_user_model_access.sql":b"ALTER fixture 951",
                 "deploy/migrations/952_chat_login_tickets.sql":b"ALTER fixture 952"}
        repository = Path(build.__file__).resolve().parents[2]
        for name in ("enterprise-ai-portal/Dockerfile", "enterprise-ai-portal/docker-entrypoint.sh",
                     "portal-proxy/Dockerfile", "deploy/release/vm_development_apply.py",
                     "deploy/lib/migration-runner.sh", "deploy/lib/migration-version.sh"):
            files[name] = (repository/name).read_bytes()
        locked = dict(prisma_version="6.19.3", platform="linux-musl-openssl-3.0.x",
                      manifest=[dict(path=name,size=len(content),sha256=hashlib.sha256(content).hexdigest())
                                for name, content in self.engines.items()])
        files["deploy/docker-compose/release-prisma-engines.lock.json"] = json.dumps(locked).encode()
        for name, content in files.items():
            path = self.source/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        installed = self.root/"enterprise-ai-portal/node_modules"
        installed.mkdir(parents=True)
        (installed/".package-lock.json").write_bytes(files["enterprise-ai-portal/package-lock.json"])
        self.archive = self.root/"immutable.tar"
        with tarfile.open(self.archive, "w", format=tarfile.PAX_FORMAT,
                          pax_headers={"comment":self.revision}) as archive:
            for path in sorted(self.source.rglob("*")):
                if path.is_file(): archive.add(path, arcname=path.relative_to(self.source), recursive=False)
        self.bases = {name:"sha256:"+letter*64 for name,letter in zip(TARGETS,"12345")}
        self.bases_file = self.root/"bases.json"
        self.bases_file.write_text(json.dumps(self.bases))
        self.images, self.containers, self.calls = {}, {}, []
        self.bad_base_lock = self.bad_payload = self.bad_engines = False
        self.portal_static_engine_env = True
        self.portal_stale_closure = self.portal_extra_file = self.portal_mode_tamper = self.portal_old_app_layer = False
        self.portal_mutate_frozen_payload = False

    def args(self):
        return build_args(repo=str(self.root), output=str(self.root/"candidate"),
                          revision=self.revision, bases=str(self.bases_file),
                          billing_enabled="true", npm_cache="/home/dev/.npm")

    def fake_run(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if argv[0] == "/usr/bin/cp":
            self.assertEqual(argv[1:3],["-a","--"])
            self.assertEqual(len(argv),5)
            shutil.copytree(Path(argv[3]),Path(argv[4]),symlinks=True)
            return ""
        if "go" in Path(argv[0]).name and argv[1] == "build":
            self.assertEqual(kwargs["env"]["GOPROXY"], "off")
            Path(argv[argv.index("-o")+1]).write_bytes(b"frozen-go-binary")
            return ""
        if argv[:2] == ["corepack", "pnpm"]:
            self.assertEqual(kwargs["env"]["COREPACK_ENABLE_NETWORK"], "0")
            command = argv[2:]
            if command == ["--version"]: return "10.10.0"
            if command[0] == "install":
                self.assertIn("--offline",argv)
                self.assertIn("--frozen-lockfile",argv)
                self.assertIn("--ignore-scripts",argv)
                (Path(kwargs["cwd"])/"node_modules").mkdir()
                return ""
            if command == ["run","build"]:
                dist = Path(kwargs["cwd"])/"dist"
                dist.mkdir()
                (dist/"server.js").write_bytes(b"new-proxy-code")
                return ""
        if argv[0] == "npm":
            self.assertEqual(kwargs["env"]["NEXT_PUBLIC_BILLING_ENABLED"],"true")
            app = Path(kwargs["cwd"])
            if argv[1] == "ci":
                self.assertIn("--offline",argv)
                return ""
            if app.name == "enterprise-ai-portal":
                standalone = app/".next/standalone"
                standalone.mkdir(parents=True)
                (standalone/"server.js").write_bytes(b"new-portal-server")
                (standalone/".next").mkdir()
                (standalone/".next/app-path-routes-manifest.json").write_text("{}")
                (app/".next/static").mkdir()
                (app/".next/static/frozen.js").write_bytes(b"new-portal-static")
            else:
                (app/"dist").mkdir()
                (app/"dist/index.html").write_text("<main>new console</main>")
            return ""
        self.assertEqual(argv[0],"docker")
        self.assertEqual(kwargs["env"]["DOCKER_HOST"],"unix:///var/run/docker.sock")
        if argv[1:3] == ["image","inspect"]:
            name = argv[3]
            if name in self.images: return json.dumps([self.images[name]["record"]])
            if "@sha256:" in name:
                return json.dumps([dict(Id="sha256:"+"9"*64,RootFS=dict(Layers=["pinned-node"]))])
            service = next(name for name,value in self.bases.items()
                           if argv[3] in (value,"jjdguard-isolated-base/"+name+":"+value[7:]))
            config = dict(User="portal" if service=="chat-portal-ui" else "10001",
                          Entrypoint=["docker-entrypoint.sh"], WorkingDir="/app",
                          Env=["NODE_ENV=production","npm_config_registry=https://registry.npmjs.org",
                               "PRISMA_ENGINES_CHECKSUM_IGNORE_MISSING=1",
                               "PRISMA_SCHEMA_ENGINE_BINARY=/app/node_modules/@prisma/engines/schema-engine-linux-musl-openssl-3.0.x",
                               "PRISMA_QUERY_ENGINE_LIBRARY=/app/node_modules/@prisma/engines/libquery_engine-linux-musl-openssl-3.0.x.so.node"],
                          ExposedPorts={"3100/tcp":{}})
            if service=="chat-portal-ui" and not self.portal_static_engine_env:
                config["Env"]=[item for item in config["Env"] if not item.startswith(("PRISMA_SCHEMA_ENGINE_BINARY=", "PRISMA_QUERY_ENGINE_LIBRARY="))]
                config["Env"] += ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                                  "NODE_VERSION=22.22.3","YARN_VERSION=1.22.22"]
            if service=="chat-portal-proxy":
                config=dict(Entrypoint=["docker-entrypoint.sh"], WorkingDir="/app",Env=["NODE_ENV=production","NODE_VERSION=22.22.3"],
                            Cmd=["sh","-c","./node_modules/.bin/prisma migrate deploy && exec node dist/server.js"],
                            ExposedPorts={"8788/tcp":{}})
            layers = ["pinned-node", "portal-workdir", "portal-user", "portal-prisma", "old-portal"] if service=="chat-portal-ui" else ["old-"+service]
            return json.dumps([dict(Id=self.bases[service],Config=config,RootFS=dict(Layers=layers))])
        if argv[1]=="run":
            self.assertIn("--network=none",argv)
            self.assertIn("--pull=never",argv)
            self.assertIn("--rm",argv)
            if argv[-1] == build.PORTAL_IDENTITY_PROBE:
                self.assertIn("--read-only",argv)
                self.assertIn("--cap-drop=ALL",argv)
                self.assertIn("--security-opt=no-new-privileges",argv)
                self.assertNotIn("--user",argv)
                return "uid=100\ngid=101\ngroups=101\npasswd=portal:100:101\ngroup=portal:101\n"
            bindings=[argv[i+1] for i,v in enumerate(argv) if v=="--mount"]
            output=next(Path(item.split("src=",1)[1].split(",",1)[0]) for item in bindings if "dst=/out" in item)
            paths={"node_modules/.bin/prisma":b"#!/bin/sh\nexec node /app/node_modules/prisma/build/index.js",
                   "node_modules/prisma/package.json":b'{"version":"6.19.3"}',
                   "node_modules/@prisma/client/package.json":b'{"version":"6.19.3"}',
                   "node_modules/.prisma/client/index.js":b"new-generated-client",
                   "node_modules/.prisma/client/index.d.ts":b"new-generated-types"}
            paths.update({"node_modules/@prisma/engines/"+name:content for name,content in self.engines.items()})
            if output.name == "verified-prisma-closure":
                paths["node_modules/prisma/package.json"] = json.dumps({"version":"6.18.0" if self.portal_stale_closure else "6.19.3",
                                                                         "dependencies":{"@prisma/engines":"6.19.3"}}).encode()
                paths["node_modules/@prisma/engines/package.json"] = b'{"version":"6.19.3"}'
            for name,content in paths.items():
                path=output/name
                path.parent.mkdir(parents=True,exist_ok=True)
                path.write_bytes(b"tampered-engine" if self.bad_engines and "schema-engine" in name else content)
            for path in output.rglob("*"):
                if path.is_dir(): path.chmod(0o755)
                elif path.is_file(): path.chmod(0o644)
            return ""
        if argv[1]=="build":
            self.assertIn("--network=none",argv)
            self.assertIn("--pull=false",argv)
            context=Path(argv[-1])
            service=context.name
            if service == "chat-portal-ui" and self.portal_mutate_frozen_payload:
                (context/"runtime/app/server.js").write_bytes(b"changed after proof")
            labels=dict(argv[i+1].split("=",1) for i,value in enumerate(argv) if value=="--label")
            config=json.dumps({"service":service,"labels":labels}).encode()
            image="sha256:"+hashlib.sha256(config).hexdigest()
            layers = ["pinned-node", "portal-workdir", "portal-user", "portal-prisma", "old-portal" if self.portal_old_app_layer else "new-portal"] if service=="chat-portal-ui" else ["pinned-node","new-"+service]
            entry=dict(record=dict(Id=image,Size=50*1024*1024,Config=dict(Labels=labels,**({"User":"portal"} if service=="chat-portal-ui" else {})),
                                   RootFS=dict(Layers=layers)),context=context,config=config)
            self.images[argv[argv.index("-t")+1]]=entry
            self.images[image]=entry
            return ""
        if argv[1]=="create":
            name="identity-chat-fake-"+str(len(self.containers))
            self.containers[name]=argv[2]
            return name
        if argv[1]=="cp":
            pair=argv[3] if argv[2]=="-L" else argv[2]
            target=Path(argv[4] if argv[2]=="-L" else argv[3])
            container,relative=pair.split(":",1)
            image=self.containers[container]
            if image not in self.images:
                name="portal-proxy/"+Path(relative).name
                if relative=="/app/node_modules":
                    target.mkdir()
                else:
                    target.write_bytes(b"wrong-base-lock" if self.bad_base_lock and "lock" in relative else (self.source/name).read_bytes())
            else:
                source=self.images[image]["context"]/"runtime"/relative.lstrip("/")
                if source.exists():
                    closure=self.images[image]["context"]/"verified-prisma-closure"
                    if source.is_dir() and closure.is_dir() and relative == "/app":
                        shutil.copytree(closure,target,symlinks=True)
                        shutil.copytree(source,target,dirs_exist_ok=True,symlinks=True)
                        if self.portal_extra_file: (target/"old-business-code.js").write_bytes(b"must reject")
                        if self.portal_mode_tamper: target.chmod(0o777)
                    else:
                        shutil.copytree(source,target) if source.is_dir() else shutil.copy2(source,target)
                    if self.bad_payload and source.is_file(): target.write_bytes(b"wrong payload")
                else:
                    target.write_bytes(b"required-prisma-runtime")
            return ""
        if argv[1]=="rm":
            self.containers.pop(argv[2])
            return ""
        if argv[1:3]==["image","save"]:
            with tarfile.open(argv[argv.index("-o")+1],"w") as archive:
                index=[]
                for tag in argv[5:]:
                    entry=self.images[tag]
                    name=entry["context"].name+".json"
                    info=tarfile.TarInfo(name); info.size=len(entry["config"])
                    archive.addfile(info,io.BytesIO(entry["config"]))
                    index.append(dict(Config=name,RepoTags=[tag],Layers=[]))
                content=json.dumps(index).encode()
                info=tarfile.TarInfo("manifest.json"); info.size=len(content)
                archive.addfile(info,io.BytesIO(content))
            return ""
        raise AssertionError("unexpected fake build command: "+repr(argv))

    def execute(self):
        real_open = Path.open
        def fixture_open(path,*args,**kwargs):
            if str(path)=="/home/dev/.cache/jjdguard/home-release.lock":
                stream=real_open(self.root/"fake-build.lock",*args,**kwargs)
                self.addCleanup(stream.close)
                return stream
            return real_open(path,*args,**kwargs)
        with patch.object(build,"run",self.fake_run),patch.object(build.fcntl,"flock"), \
                patch.object(build.Path,"open",fixture_open):
            build.build_fixed_source(self.args(),self.tree,(self.archive,build.digest(self.archive)))
        return self.root/"candidate/media"

    def test_six_image_build_freezes_proxy_server_and_authenticates_the_exact_archive(self):
        args = self.args()
        args.include_proxy_server = True
        self.args = lambda: args
        self.bases["proxy-server"] = "sha256:"+"6"*64
        self.bases_file.write_text(json.dumps(self.bases))
        source = self.source/"apps/proxy-server/cmd/server/main.go"
        source.parent.mkdir(parents=True)
        source.write_text("package main")
        with tarfile.open(self.archive, "w", format=tarfile.PAX_FORMAT, pax_headers={"comment":self.revision}) as archive:
            for path in sorted(self.source.rglob("*")):
                if path.is_file(): archive.add(path, arcname=path.relative_to(self.source), recursive=False)
        media = self.execute()
        result = json.loads((media/"manifest.json").read_text())
        self.assertIs(result["include_proxy_server"], True)
        self.assertEqual(set(result["services"]), set(TARGETS+("proxy-server",)))
        proxy = self.root/"candidate/build/proxy-server/runtime/app/proxy-server"
        self.assertEqual(proxy.read_bytes(), b"frozen-go-binary")
        self.assertEqual(len([a for a,k in self.calls if a[:2]==["docker","build"]]), 6)
        build.verify_identity_chat_image_archive(media, result)
        deploy.validate_persist_scope(result)
        with patch.object(deploy.subprocess, "check_output", self.frozen_git):
            deploy.validate_identity_chat_source_media(self.root, media, result)
        changed = dict(result)
        changed.pop("include_proxy_server")
        with self.assertRaises(AssertionError): build.verify_identity_chat_image_archive(media, changed)

    def test_five_image_build_freezes_every_payload_and_explicit_migration(self):
        media=self.execute()
        result=json.loads((media/"manifest.json").read_text())
        self.assertEqual(set(result["services"]),set(TARGETS))
        self.assertTrue(result["identity_chat_only"])
        self.assertTrue(result["preserve_tier1"])
        self.assertEqual(result["source_archive_sha256"],build.digest(self.archive))
        self.assertEqual(set(result["migrations"]),set(manifest()["migrations"]))
        self.assertFalse(any("smoke" in path.name or "probe" in path.name for path in media.iterdir()))
        self.assertFalse(self.containers)
        self.assertEqual(len([a for a,k in self.calls if a[:2]==["docker","build"]]),5)
        proxy=self.root/"candidate/build/chat-portal-proxy"
        recipe=(proxy/"Dockerfile").read_text()
        self.assertIn("RUN rm -rf /app",recipe)
        self.assertNotIn("USER root",recipe)
        self.assertNotIn("npm install",recipe)
        self.assertNotIn("apk add",recipe)
        self.assertEqual((proxy/"runtime/app/dist/server.js").read_bytes(),b"new-proxy-code")
        self.assertEqual((proxy/"runtime/app/prisma/schema.prisma").read_bytes(),b"frozen proxy schema")
        self.assertIn("/app/node_modules/.prisma/client/index.js",result["services"]["chat-portal-proxy"]["payload_sha256"])
        build.verify_identity_chat_image_archive(media,result)

    def test_five_image_build_accepts_product_portal_env_without_injecting_engine_paths(self):
        self.portal_static_engine_env=False
        media=self.execute()
        result=json.loads((media/"manifest.json").read_text())
        self.assertEqual(set(result["services"]),set(TARGETS))
        recipe=(self.root/"candidate/build/chat-portal-ui/Dockerfile").read_text()
        self.assertNotIn("PRISMA_SCHEMA_ENGINE_BINARY=",recipe)
        self.assertNotIn("PRISMA_QUERY_ENGINE_LIBRARY=",recipe)
        self.assertIn('PRISMA_ENGINES_CHECKSUM_IGNORE_MISSING="1"',recipe)
        self.assertEqual([line for line in recipe.splitlines() if line.startswith("ENTRYPOINT ")],
                         ['ENTRYPOINT ["docker-entrypoint.sh"]'])
        self.assertTrue(recipe.endswith("USER portal\n"))
        self.assertFalse(self.containers)

    def test_verified_stable_prisma_layer_retains_complete_source_and_union_proof(self):
        media = self.execute()
        result = json.loads((media/"manifest.json").read_text())
        proof = result["services"]["chat-portal-ui"]["portal_build_proof"]
        context = self.root/"candidate/build/chat-portal-ui"
        self.assertEqual(proof["source_archive_sha256"], build.digest(self.archive))
        self.assertEqual(proof["source_revision"], self.revision)
        self.assertEqual(proof["source_tree"], self.tree)
        self.assertEqual(proof["candidate_recipe_sha256"], build.digest(context/"Dockerfile"))
        self.assertEqual(proof["expected_union_tree_sha256"], proof["verified_union_tree_sha256"])
        self.assertEqual(proof["layer_reuse"]["prisma_reuse_candidate_index"], 3)
        self.assertEqual(proof["layer_reuse"]["prisma_reuse_diff_id"], "portal-prisma")
        self.assertEqual(proof["closure_packages"], {"prisma":"6.19.3", "@prisma/engines":"6.19.3"})
        self.assertIn("/app/.jjdguard-portal-build-proof.json", result["services"]["chat-portal-ui"]["payload_sha256"])

    def test_portal_old_cli_package_version_stops_before_candidate_build(self):
        self.portal_stale_closure = True
        with self.assertRaisesRegex(AssertionError, "Prisma package differs"):
            self.execute()
        self.assertFalse(any(a[:2]==["docker","build"] and Path(a[-1]).name=="chat-portal-ui" for a,k in self.calls))

    def test_portal_frozen_payload_change_aborts_before_stable_layer_acceptance(self):
        self.portal_mutate_frozen_payload = True
        with patch.object(build,"verify_portal_layers") as layers:
            with self.assertRaisesRegex(AssertionError, "frozen portal payload changed"):
                self.execute()
        layers.assert_not_called()

    def test_portal_exact_union_rejects_extra_business_files(self):
        self.portal_extra_file = True
        with self.assertRaisesRegex(AssertionError, "application tree differs"):
            self.execute()
        self.assertFalse(self.containers)

    def test_portal_exact_union_rejects_root_permission_change(self):
        self.portal_mode_tamper = True
        with self.assertRaisesRegex(AssertionError, "application tree differs"):
            self.execute()
        self.assertFalse(self.containers)

    def test_portal_old_application_layer_is_rejected_even_with_fresh_payload(self):
        self.portal_old_app_layer = True
        with self.assertRaisesRegex(AssertionError, "previous portal application layers"):
            self.execute()
        self.assertFalse(self.containers)

    def frozen_git(self,argv,**kwargs):
        if "show" in argv:
            relative=argv[-1].split(":",1)[1]
            return (self.source/relative).read_bytes()
        if "archive" in argv: return self.archive.read_bytes()
        raise AssertionError("unexpected source authentication command: "+repr(argv))

    def test_host_authenticates_every_frozen_helper_migration_and_archive(self):
        media=self.execute()
        result=json.loads((media/"manifest.json").read_text())
        with patch.object(deploy.subprocess,"check_output",self.frozen_git):
            deploy.validate_identity_chat_source_media(self.root,media,result)
            (media/"migration-version.sh").write_text("unreviewed helper")
            with self.assertRaisesRegex(RuntimeError,"frozen source"):
                deploy.validate_identity_chat_source_media(self.root,media,result)

    def test_host_refuses_extra_media_and_source_archive_tampering(self):
        media=self.execute()
        result=json.loads((media/"manifest.json").read_text())
        with patch.object(deploy.subprocess,"check_output",self.frozen_git):
            (media/"tier1-window-smoke.py").write_text("unapproved model probe")
            with self.assertRaisesRegex(RuntimeError,"unexpected.*media"):
                deploy.validate_identity_chat_source_media(self.root,media,result)
            (media/"tier1-window-smoke.py").unlink()
            result["source_archive_sha256"]="f"*64
            with self.assertRaisesRegex(RuntimeError,"archive"):
                deploy.validate_identity_chat_source_media(self.root,media,result)

    def test_proxy_build_uses_the_explicit_offline_store_and_noninteractive_environment(self):
        self.execute()
        commands=[(argv,kwargs) for argv,kwargs in self.calls if argv[:3]==["corepack","pnpm","install"]]
        self.assertEqual(len(commands),1)
        argv,kwargs=commands[0]
        self.assertEqual(argv[argv.index("--store-dir")+1],"/home/dev/jjdguard-src/.pnpm-store")
        self.assertEqual(kwargs["env"]["CI"],"true")
        self.assertEqual(kwargs["env"]["COREPACK_ENABLE_NETWORK"],"0")
        self.assertNotEqual(kwargs["env"]["NPM_CONFIG_USERCONFIG"],str(Path.home()/".npmrc"))

    def execute_with_only_corepack_launcher(self, version="10.10.0"):
        tools = self.root/"corepack-only"
        tools.mkdir()
        calls = self.root/"corepack-calls.jsonl"
        launcher = tools/"corepack"
        launcher.write_text("#!"+sys.executable+"\n"+r'''
import json, os, sys
from pathlib import Path
assert sys.argv[1] == "pnpm"
assert os.environ["COREPACK_ENABLE_NETWORK"] == "0"
assert os.environ["CI"] == "true"
assert os.environ["NPM_CONFIG_OFFLINE"] == "true"
command = sys.argv[2:]
with Path(CALLS).open("a") as stream:
    stream.write(json.dumps(command)+"\n")
if command == ["--version"]:
    print(VERSION)
elif command[0] == "install":
    assert all(flag in command for flag in ("--offline", "--frozen-lockfile", "--ignore-scripts", "--store-dir"))
    Path("node_modules").mkdir()
elif command == ["run", "build"]:
    Path("dist").mkdir()
    Path("dist/server.js").write_bytes(b"new-proxy-code")
else:
    raise AssertionError("unexpected Corepack command")
'''.replace("CALLS", repr(str(calls))).replace("VERSION", repr(version)))
        launcher.chmod(0o755)
        fake_run = self.fake_run
        real_run = build.run
        def run_with_restricted_path(argv, **kwargs):
            if argv[0] in ("pnpm", "corepack"):
                self.calls.append((argv, kwargs))
                kwargs["env"] = dict(kwargs["env"], PATH=str(tools))
                try:
                    return real_run(argv, **kwargs)
                except FileNotFoundError:
                    self.fail("proxy builder requires an unavailable pnpm shim instead of the fixed-path Corepack launcher")
            return fake_run(argv, **kwargs)
        self.fake_run = run_with_restricted_path
        result = self.execute()
        return result, [json.loads(line) for line in calls.read_text().splitlines()]

    def test_proxy_build_works_without_a_separate_pnpm_shim_on_path(self):
        result, calls = self.execute_with_only_corepack_launcher()
        recorded = json.loads((result/"manifest.json").read_text())
        self.assertEqual(set(recorded["services"]), set(TARGETS))
        self.assertEqual([command[:1] for command in calls], [["--version"], ["install"], ["run"]])
        self.assertEqual(calls[-1], ["run", "build"])

    def test_corepack_still_rejects_a_nonpinned_pnpm_version_before_install(self):
        with self.assertRaisesRegex(AssertionError, "proxy pnpm tool differs"):
            self.execute_with_only_corepack_launcher(version="11.0.0")
        self.assertFalse((self.root/"candidate/media").exists())
        calls = [json.loads(line) for line in (self.root/"corepack-calls.jsonl").read_text().splitlines()]
        self.assertEqual(calls, [["--version"]])

    def proxy_prisma_build_script(self):
        scripts = [argv[-1] for argv, _ in self.calls if argv[:2] == ["docker", "run"]
                   and "cp -R /app/node_modules /tmp/proxy/node_modules" in argv[-1]]
        self.assertEqual(len(scripts), 1)
        return scripts[0]

    def test_proxy_generator_works_when_the_copied_tmp_cli_cannot_execute(self):
        import subprocess
        self.execute()
        script = self.proxy_prisma_build_script()
        command = "DATABASE_URL="+script.split("DATABASE_URL=", 1)[1].split("; node /source/", 1)[0]
        base = self.root/"readable-base"
        cli = base/"node_modules/prisma/build/index.js"
        cli.parent.mkdir(parents=True)
        cli.write_text('const fs=require("fs"); if(process.argv[2]!=="generate") throw Error("unexpected command"); fs.mkdirSync("node_modules/.prisma/client",{recursive:true}); fs.writeFileSync("node_modules/.prisma/client/index.js","new-frozen-schema-client");')
        cli.chmod(0o444)
        copied = self.root/"nonexecutable-tmp-copy"
        wrapper = copied/"node_modules/.bin/prisma"
        wrapper.parent.mkdir(parents=True)
        wrapper.write_text("#!/bin/sh\nexit 91\n")
        wrapper.chmod(0o644)
        command = command.replace("/app/",str(base)+"/")
        result = subprocess.run(["/bin/sh", "-ec", command], cwd=copied,
                                env={"PATH":"/usr/bin:/bin", "HOME":str(self.root)}, capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual((copied/"node_modules/.prisma/client/index.js").read_text(),"new-frozen-schema-client")
        docker = next(argv for argv,_ in self.calls if argv[:2]==["docker","run"] and argv[-1]==script)
        self.assertIn("--network=none",docker)
        self.assertIn("--read-only",docker)
        self.assertFalse("exec" in docker[docker.index("--tmpfs")+1].split(":",1)[1].split(","))

    def test_proxy_production_closure_runs_inside_esm_package_inputs(self):
        import shlex,subprocess
        self.execute()
        script = self.proxy_prisma_build_script()
        inputs = self.root/"candidate/build/chat-portal-proxy/proxy-inputs"
        package = json.loads((inputs/"package.json").read_text())
        package["type"] = "module"
        (inputs/"package.json").write_text(json.dumps(package))
        copied = self.root/"closure-new-proxy"
        modules = copied/"node_modules"
        for name in package["dependencies"]:
            target = modules/name
            target.mkdir(parents=True)
            (target/"package.json").write_text('{"version":"6.19.3"}')
        client = modules/".prisma/client"
        client.mkdir(parents=True)
        (client/"index.js").write_text("new-generated-client")
        (copied/"package.json").write_text(json.dumps(package))
        output = self.root/"closure-new-runtime"
        command = shlex.split("node /source/"+script.split("; node /source/",1)[1])
        command = [arg.replace("/source/",str(inputs)+"/").replace("/tmp/proxy/",str(copied)+"/").replace("/out/",str(output)+"/") for arg in command]
        result = subprocess.run(command,env={"PATH":"/usr/bin:/bin", "HOME":str(self.root)},capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual((output/"node_modules/.prisma/client/index.js").read_text(),"new-generated-client")
        self.assertFalse(any(path.is_symlink() for path in (output/"node_modules").rglob("*")))

    def test_proxy_dependencies_cannot_differ_from_frozen_lock(self):
        self.bad_base_lock=True
        with self.assertRaisesRegex(AssertionError,"proxy.*(lock|dependencies)"):
            self.execute()
        self.assertFalse((self.root/"candidate/media").exists())
        self.assertFalse(self.containers)

    def test_proxy_prisma_engine_must_match_the_frozen_musl_lock(self):
        self.bad_engines=True
        with self.assertRaisesRegex(AssertionError,"Prisma.*engine"):
            self.execute()
        self.assertFalse((self.root/"candidate/media").exists())

    def test_candidate_readback_rejects_modified_payload(self):
        self.bad_payload=True
        with self.assertRaisesRegex(AssertionError,"payload differs"):
            self.execute()
        self.assertFalse((self.root/"candidate/media").exists())


class IdentityChatApplyTests(unittest.TestCase):
    def setUp(self):
        import test_vm_development_release as common
        self.common=common
        self.addCleanup(os.umask,os.umask(0o077))
        self.rig=common.RollbackTests("runTest")
        self.rig.setUp()
        self.addCleanup(self.rig.doCleanups)
        rig=self.rig
        rig.before_policy["billing_enabled"]="true"
        shutil.rmtree(rig.media/"state")
        rig.live.unlink()
        self.model=json.loads(rig.base.read_text())
        self.model["services"]["postgres"]["environment"]={"POSTGRES_DB":"jjd","POSTGRES_USER":"jjd"}
        self.model["services"]["chat-portal-ui"]["environment"]["NEXT_PUBLIC_BILLING_ENABLED"]="true"
        self.model["services"]["chat-portal-proxy"].update(command=["sh","-c","product-startup"],user="",working_dir="/app")
        rig.base.write_text(json.dumps(self.model))
        for service,row in rig.rows.items():
            row["Image"]=common.OLD
            row["State"]["StartedAt"]="2026-10-10T14:00:00.000000000Z"
            row["Config"]["Labels"].update({"com.docker.compose.project":"stable-project",
                 "com.docker.compose.project.working_dir":str(rig.workdir),
                 "com.docker.compose.project.config_files":str(rig.base)})
            if service!="postgres":
                row["Config"]["Env"]=[key+"="+value for key,value in self.model["services"][service]["environment"].items()]
            row["Config"].update(User="",Cmd=["fixture-command"],Entrypoint=["fixture-entrypoint"],WorkingDir="/app")
        for name in ("llm-judge","chat-idp"):
            rig.rows[name]=copy.deepcopy(rig.rows["tier1-classifier"])
            rig.rows[name]["Id"]=name+"-1"
            rig.rows[name]["Config"]["Labels"]["com.docker.compose.service"]=name
            self.model["services"][name]=copy.deepcopy(self.model["services"]["tier1-classifier"])
        rig.base.write_text(json.dumps(self.model))
        self.fixed_payload=hashlib.sha256(b"fixed-service-payload").hexdigest()
        self.m=manifest(revision="c"*40,release_id=rig.media.name,
                        services={name:dict(image_id=common.NEW,base_image_id=common.OLD,
                            tag="jjdguard-dev/"+name+":fixture",payload_sha256={"/app/frozen":self.fixed_payload})
                            for name in TARGETS},
                        candidate_validation={"identity_chat_payload_verified":True,
                                              "portal_navigation_paths":"explicit_base_path",
                                              "model_services":"preserved_not_touched"})
        repository=Path(vm.__file__).resolve().parents[2]
        for name in ("vm_development_apply.py",):
            shutil.copy2(repository/"deploy/release"/name,rig.media/name)
            (rig.media/name).chmod(0o600)
        self.m["apply_script_sha256"]=vm.digest(rig.media/"vm_development_apply.py")
        build.copy_migration_runtime(repository,rig.media,self.m)
        (rig.media/"images.tar").write_bytes(b"fixed-fake-images")
        self.m["images_sha256"]=vm.digest(rig.media/"images.tar")
        (rig.media/"migrations").mkdir()
        for name in self.m["migrations"]:
            (rig.media/"migrations"/name).write_bytes(name.encode())
            self.m["migrations"][name]=vm.digest(rig.media/"migrations"/name)
        (rig.media/"manifest.json").write_text(json.dumps(self.m))
        rig.pointer.write_text(rig.previous_pointer)
        self.commands,self.subprocess_commands=[],[]
        self.fail_verify=False
        self.context=contextlib.ExitStack()
        self.addCleanup(self.context.close)
        self.context.enter_context(patch.object(vm,"ROOT",rig.root))
        self.context.enter_context(patch.object(vm,"run",self.fake_run))
        self.context.enter_context(patch.object(vm.subprocess,"run",self.fake_subprocess))
        self.context.enter_context(patch.object(vm,"run_database_restore",self.fake_database_restore))
        self.context.enter_context(patch.object(vm,"read_identity_chat_mount_policy",return_value={
            "schema":1,"selinux":"disabled","daemon_id":"fixture-daemon",
            "docker_security_options":["name=apparmor","name=seccomp,profile=builtin","name=cgroupns"],
            "kernel_enforce":"absent"}))
        self.context.enter_context(patch.object(vm.shutil,"disk_usage",return_value=SimpleNamespace(free=10**12)))

    def fake_run(self,argv,**kwargs):
        rig=self.rig
        self.commands.append(argv)
        if argv[:2]==["docker","ps"]:
            return "\n".join(row["Id"] for row in rig.rows.values())
        if argv[:3]==["docker","image","inspect"]:
            name=argv[3]
            service=next((key for key,record in self.m["services"].items() if name==record["tag"]),None)
            if service is not None or name==self.common.NEW:
                selected=service or TARGETS[0]
                labels={"org.opencontainers.image.revision":self.m["revision"],
                        "com.jjdguard.release.id":self.m["release_id"],
                        "com.jjdguard.source.tree":self.m["tree"],
                        "com.jjdguard.base.image":self.m["services"][selected]["base_image_id"]}
                return json.dumps([dict(Id=self.common.NEW,Config=dict(Labels=labels))])
            return json.dumps([dict(Id=name)])
        if argv[:3]==["docker","image","load"]: return "fixed-fake-images"
        if argv[:2]==["docker","exec"] and "sha256sum" in argv:
            if self.fail_verify: raise RuntimeError("payload differs")
            return "\n".join(self.fixed_payload+"  "+name for name in argv[argv.index("--")+1:])
        if argv[:2]==["docker","exec"] and "cat" in argv:
            return json.dumps({name:name for name in vm.PORTAL_ROUTES})
        if argv[:2]==["docker","exec"] and "pg_terminate_backend" in argv[-1]:
            return ""
        if argv[0]==str(rig.compose_bin) and "start" in argv:
            result=rig.fake_run(argv,**kwargs)
            for service in argv[argv.index("start")+1:]:
                if service in rig.rows:
                    rig.rows[service]["State"]["StartedAt"]="2026-10-10T14:01:00.000000000Z"
                    rig.rows[service]["RestartCount"]=0
            return result
        if argv[0]==str(rig.compose_bin) and "up" in argv:
            start=argv.index("--force-recreate")+1
            for service in argv[start:]:
                rig.fake_run(argv[:start]+[service],**kwargs)
                rig.rows[service]["State"]["StartedAt"]="2026-10-10T14:02:00.000000000Z"
            return ""
        return rig.fake_run(argv,**kwargs)

    def fake_database_restore(self,pg,user,backup_path,state_dir,timeout,event):
        self.assertGreaterEqual(timeout,3600)
        return self.fake_subprocess(["docker","exec","-i",pg,"pg_restore","--clean","--if-exists","--create","--exit-on-error","-U",user,"-d","postgres"])

    def fake_subprocess(self,argv,**kwargs):
        self.subprocess_commands.append(argv)
        if argv[0]=="bash":
            self.assertEqual(argv[1],str(self.rig.media/"migration-runner.sh"))
            self.assertIn("MIGRATION_PSQL",kwargs["env"])
            self.assertTrue((self.rig.media/"state/psql-command").is_file())
            if "--dry-run" not in argv:
                self.rig.current_ledger.update(self.m["migrations"])
            return SimpleNamespace(returncode=0)
        if "pg_dump" in argv:
            kwargs["stdout"].write(b"consistent-fake-database")
            return SimpleNamespace(returncode=0)
        if "pg_restore" in argv:
            if "--clean" in argv: self.rig.current_ledger=dict(self.rig.before_ledger)
            return SimpleNamespace(returncode=0)
        raise AssertionError("unexpected subprocess: "+repr(argv))

    def stage(self):
        self.release=vm.Release(self.rig.media,vm.digest(self.rig.media/"manifest.json"))
        self.addCleanup(self.release.lock_file.close)
        self.release.stage()
        return self.release

    def test_fake_stage_apply_persist_and_recorded_rollback_preserve_boundaries(self):
        release=self.stage()
        original_chain=self.rig.chain.read_bytes()
        before=copy.deepcopy(self.rig.rows)
        vm.perform(release)
        self.assertEqual(self.rig.current_ledger,dict(self.rig.before_ledger,**self.m["migrations"]))
        receipt_path=self.rig.media/"receipt.json"
        apply_pin=vm.digest(receipt_path)
        release.lock_file.close()
        final_pin=vm.perform_persist_boot(self.rig.media,vm.digest(self.rig.media/"manifest.json"),apply_pin)
        self.assertNotEqual(apply_pin,final_pin)
        for name in set(self.rig.rows)-set(TARGETS):
            self.assertEqual(self.rig.rows[name]["Id"],before[name]["Id"])
            self.assertEqual(self.rig.rows[name]["Image"],before[name]["Image"])
            self.assertEqual(self.rig.rows[name]["RestartCount"],before[name]["RestartCount"])
        self.assertFalse(any("tier1-classifier" in command or "llm-judge" in command or "chat-idp" in command
                             for command in self.rig.stops+self.rig.starts))
        ledger=copy.deepcopy(self.rig.current_ledger)
        vm.perform_rollback(self.rig.media,vm.digest(self.rig.media/"manifest.json"),final_pin)
        self.assertEqual(self.rig.current_ledger,ledger)
        self.assertEqual(self.rig.chain.read_bytes(),original_chain)
        self.assertEqual(self.rig.pointer.read_text(),self.rig.previous_pointer)
        self.assertTrue(all(self.rig.rows[name]["Image"]==self.common.OLD for name in TARGETS))
        self.assertFalse(any("tier1-classifier" in command or "llm-judge" in command or "chat-idp" in command
                             for command in self.rig.stops+self.rig.starts))
        self.assertFalse(any("app.file" in str(command) or "tier1-window" in str(command) for command in self.commands))
        self.assertEqual(len([command for command in self.subprocess_commands if "pg_dump" in command]),1)
        self.assertFalse(any("--clean" in command for command in self.subprocess_commands))
        persisted=json.loads(receipt_path.read_text())
        self.assertIn("identity_chat_runtime",persisted)

    def select_proxy_server(self):
        self.m["include_proxy_server"] = True
        record = copy.deepcopy(self.m["services"]["gateway-core"])
        record["tag"] = "jjdguard-dev/proxy-server:fixture"
        self.m["services"]["proxy-server"] = record
        key = "isolated-fixture-attestation-key"
        for name in ("control-plane", "proxy-server"):
            self.model["services"][name]["environment"]["JJD_SEMANTIC_GATEWAY_ATTESTATION_KEY"] = key
            self.rig.rows[name]["Config"]["Env"].append("JJD_SEMANTIC_GATEWAY_ATTESTATION_KEY="+key)
        self.rig.base.write_text(json.dumps(self.model))
        (self.rig.media/"manifest.json").write_text(json.dumps(self.m))

    def test_six_services_apply_persist_and_recorded_rollback_preserve_models_and_data(self):
        self.select_proxy_server()
        release = self.stage()
        targets = TARGETS+("proxy-server",)
        self.assertEqual(release.target_services, targets)
        before = copy.deepcopy(self.rig.rows)
        original_chain = self.rig.chain.read_bytes()
        vm.perform(release)
        self.assertTrue(all(self.rig.rows[name]["Image"] == self.common.NEW for name in targets))
        receipt = self.rig.media/"receipt.json"
        release.lock_file.close()
        pin = vm.perform_persist_boot(self.rig.media, vm.digest(self.rig.media/"manifest.json"), vm.digest(receipt))
        ledger = copy.deepcopy(self.rig.current_ledger)
        vm.perform_rollback(self.rig.media, vm.digest(self.rig.media/"manifest.json"), pin)
        self.assertEqual(self.rig.current_ledger, ledger)
        self.assertEqual(self.rig.chain.read_bytes(), original_chain)
        self.assertTrue(all(self.rig.rows[name]["Image"] == self.common.OLD for name in targets))
        for name in MODEL_SERVICES:
            if name == "security-engine":
                self.assertEqual(self.rig.rows[name]["Id"], before[name]["Id"])
                self.assertEqual(self.rig.rows[name]["Image"], before[name]["Image"])
            else: self.assertEqual(self.rig.rows[name], before[name])
        self.assertFalse(any("--clean" in command for command in self.subprocess_commands))

    def test_six_service_failed_verification_restores_proxy_and_database_before_unfence(self):
        self.select_proxy_server()
        release = self.stage()
        self.fail_verify = True
        with self.assertRaisesRegex(RuntimeError, "payload differs"): vm.perform(release)
        self.assertEqual(self.rig.current_ledger, self.rig.before_ledger)
        self.assertTrue(all(self.rig.rows[name]["Image"] == self.common.OLD for name in TARGETS+("proxy-server",)))
        self.assertTrue((self.rig.media/"rollback.json").is_file())
        self.assertTrue(any("--clean" in command for command in self.subprocess_commands))
        self.assertTrue(any("-D" in command for command in self.rig.iptables))

    def test_stage_refuses_a_base_that_is_not_the_current_live_image(self):
        self.m["services"]["control-plane"]["base_image_id"]="sha256:"+"f"*64
        (self.rig.media/"manifest.json").write_text(json.dumps(self.m))
        with self.assertRaisesRegex(RuntimeError,"base image"):
            self.stage()
        self.assertFalse(self.rig.stops)
        self.assertFalse(self.rig.iptables)

    def test_non_target_compose_label_drift_is_not_normalized_away(self):
        release=self.stage()
        self.rig.rows["chat-idp"]["Config"]["Labels"]["com.docker.compose.project.config_files"]="unapproved-history"
        with self.assertRaisesRegex(RuntimeError,"runtime contract"):
            release.fence()
        self.assertFalse(self.rig.iptables)

    def test_identity_stage_preflights_boot_nonscalar_drift_before_stopping_writers(self):
        overlay=self.rig.workdir/"active-config/foreign-boot.json"
        overlay.write_text(json.dumps({"services":{"chat-portal-ui":{"volumes":[dict(type="volume",source="foreign",target="/foreign")]}}}))
        self.rig.chain.write_text(str(overlay)+"\n")
        with self.assertRaisesRegex(RuntimeError,"outside permitted"):
            self.stage()
        self.assertFalse(self.rig.stops)
        self.assertFalse(self.rig.iptables)

    def missing_billing_row_runtime(self, flag):
        self.rig.before_policy.pop("billing_enabled",None)
        for name in ("control-plane","gateway-core"):
            env=self.model["services"][name]["environment"]
            env.pop("BILLING_ENABLED",None)
            if flag is not None: env["BILLING_ENABLED"]=flag
            self.rig.rows[name]["Config"]["Env"]=[key+"="+value for key,value in env.items()]
        self.rig.base.write_text(json.dumps(self.model))

    def test_missing_billing_row_uses_explicit_frozen_runtime_mode_without_writing_policy(self):
        self.missing_billing_row_runtime("true")
        original=copy.deepcopy(self.rig.before_policy)
        release=self.stage()
        self.assertEqual(release.before_policy,original)
        self.assertNotIn("billing_enabled",release.before_policy)
        self.assertEqual(self.rig.before_policy,original)
        self.assertEqual(self.rig.stops,[])
        vm.perform(release)
        self.assertEqual(release.policy(),original)
        self.assertEqual(json.loads((self.rig.media/"receipt.json").read_text())["policy"],original)

    def test_missing_billing_row_refuses_missing_false_or_invalid_runtime_mode(self):
        for flag in (None,"false","1","unexpected"):
            with self.subTest(flag=flag):
                self.missing_billing_row_runtime(flag)
                receipt=self.rig.media/"receipt.json"
                original_receipt=receipt.read_bytes() if receipt.exists() else None
                with self.assertRaisesRegex(RuntimeError,"billing build differs"):
                    self.stage()
                self.release.lock_file.close()
                self.assertEqual(receipt.read_bytes() if receipt.exists() else None,original_receipt)
                self.assertEqual(self.rig.stops,[])
                shutil.rmtree(self.rig.media/"state")

    def test_explicit_billing_database_row_keeps_priority_over_runtime_fallback(self):
        self.missing_billing_row_runtime("true")
        self.rig.before_policy["billing_enabled"]="false"
        with self.assertRaisesRegex(RuntimeError,"billing build differs"):
            self.stage()
        self.assertEqual(self.rig.before_policy["billing_enabled"],"false")

    def test_billing_snapshot_and_rollback_policy_include_managed_billing(self):
        release=self.stage()
        self.assertEqual(release.before_policy["billing_enabled"],"true")
        before=len(self.commands)
        vm.read_policy(self.rig.rows,include_billing=True)
        calls=self.commands[before:]
        self.assertTrue(any("psql" in command for command in calls))

    def test_non_target_environment_drift_between_stage_and_apply_rejects_before_fence(self):
        release=self.stage()
        self.rig.rows["chat-idp"]["Config"]["Env"].append("UNAPPROVED_SETTING=true")
        count=len(self.rig.iptables)
        with self.assertRaisesRegex(RuntimeError,"runtime contract|non-target"):
            release.fence()
        self.assertEqual(len(self.rig.iptables),count)
        self.assertFalse(self.rig.stops)

    def test_target_provenance_version_and_build_time_must_equal_the_manifest(self):
        release=self.stage()
        release.fence(); release.stop_writers(); release.backup(); release.migrate(); release.switch()
        for key in ("JJD_VERSION","JJD_BUILT_AT"):
            original=list(self.rig.rows["gateway-core"]["Config"]["Env"])
            self.rig.rows["gateway-core"]["Config"]["Env"]=[value for value in original if not value.startswith(key+"=")]+[key+"=unapproved"]
            with self.subTest(key=key),self.assertRaisesRegex(RuntimeError,"provenance|revision"):
                release.verify()
            self.rig.rows["gateway-core"]["Config"]["Env"]=original

    def enable_chat_proxy_trust(self):
        self.m["chat_login_proxy_trust"] = True
        (self.rig.media/"manifest.json").write_text(json.dumps(self.m))
        master = "fixture-internal-master-"+"a"*32
        self.model["services"]["control-plane"]["environment"]["JJD_INTERNAL_API_SECRET"] = master
        self.rig.rows["control-plane"]["Config"]["Env"].append("JJD_INTERNAL_API_SECRET="+master)
        self.rig.base.write_text(json.dumps(self.model))
        self.enterContext(patch.object(vm, "chat_portal_defaults_preflight"))

    def test_approved_chat_proxy_trust_survives_apply_persist_and_rollback(self):
        self.enable_chat_proxy_trust()
        release = self.stage()
        original_env = list(self.rig.rows["control-plane"]["Config"]["Env"])
        expected_signing = vm.login_ip_forward_environment(self.m, self.rig.rows)
        vm.perform(release)
        for name, approved in expected_signing.items():
            self.assertIn("JJD_LOGIN_IP_FORWARD_SECRET="+approved["JJD_LOGIN_IP_FORWARD_SECRET"],
                          self.rig.rows[name]["Config"]["Env"])
        self.assertIn("JJD_CHAT_LOGIN_TRUSTED_PROXY_HOSTS=chat-portal-ui,web-console",
                      self.rig.rows["control-plane"]["Config"]["Env"])
        receipt = self.rig.media/"receipt.json"
        release.lock_file.close()
        pin = vm.perform_persist_boot(self.rig.media, vm.digest(self.rig.media/"manifest.json"), vm.digest(receipt))
        vm.perform_rollback(self.rig.media, vm.digest(self.rig.media/"manifest.json"), pin)
        self.assertEqual(sorted(self.rig.rows["control-plane"]["Config"]["Env"]), sorted(original_env))

    def test_chat_proxy_trust_drift_and_unapproved_environment_remain_rejected(self):
        self.enable_chat_proxy_trust()
        release = self.stage()
        release.fence(); release.stop_writers(); release.backup(); release.migrate(); release.switch()
        row = self.rig.rows["control-plane"]
        original = list(row["Config"]["Env"])
        for addition in ("JJD_CHAT_LOGIN_TRUSTED_PROXY_HOSTS=unapproved",
                         "JJD_LOGIN_IP_FORWARD_SECRET=unapproved",
                         "UNAPPROVED_SETTING=true"):
            row["Config"]["Env"] = [v for v in original if not v.startswith(addition.split("=",1)[0]+"=")]+[addition]
            with self.subTest(addition=addition), self.assertRaisesRegex(RuntimeError, "runtime contract"):
                release.verify()
        row["Config"]["Env"] = original
        release.verify()

    def test_target_mount_drift_is_detected_after_switch(self):
        release=self.stage()
        release.fence(); release.stop_writers(); release.backup(); release.migrate(); release.switch()
        self.rig.rows["gateway-core"]["Mounts"]=[dict(Type="bind",Source="/unapproved",Destination="/app/extra")]
        with self.assertRaisesRegex(RuntimeError,"runtime contract"):
            release.verify()

    def test_non_target_writer_restart_is_allowed_but_identity_and_config_are_fixed(self):
        release=self.stage()
        release.fence(); release.stop_writers(); release.backup(); release.migrate(); release.switch()
        for name in ("proxy-server","worker","security-engine"):
            self.rig.rows[name]["State"]["StartedAt"]="2026-10-10T14:01:00.000000000Z"
        release.verify()
        self.rig.rows["security-engine"]["RestartCount"]=1
        with self.assertRaisesRegex(RuntimeError,"identity|non-target"):
            release.verify()

    def test_explicit_writer_start_resets_historical_counter_to_exact_zero(self):
        for name in ("proxy-server", "worker"):
            self.rig.rows[name]["RestartCount"]=1
        release=self.stage()
        release.fence(); release.stop_writers(); release.backup(); release.migrate(); release.switch()
        release.verify()
        for name in ("proxy-server", "worker"):
            self.assertEqual(self.rig.rows[name]["RestartCount"],0)

    def test_resumed_writer_with_new_automatic_restart_is_rejected(self):
        self.rig.rows["proxy-server"]["RestartCount"]=1
        release=self.stage()
        release.fence(); release.stop_writers(); release.backup(); release.migrate(); release.switch()
        for count in (1,2,False):
            self.rig.rows["proxy-server"]["RestartCount"]=count
            with self.subTest(count=count),self.assertRaisesRegex(RuntimeError,"restart|identity|non-target"):
                release.verify()

    def test_unpaused_service_counter_reset_is_not_authorised(self):
        self.rig.rows["chat-idp"]["RestartCount"]=1
        release=self.stage()
        release.fence(); release.stop_writers(); release.backup(); release.migrate(); release.switch()
        self.rig.rows["chat-idp"]["RestartCount"]=0
        with self.assertRaisesRegex(RuntimeError,"identity|non-target"):
            release.verify()

    def test_backup_failure_resumes_historical_writer_counters_to_zero(self):
        for name in ("control-plane","proxy-server","worker"):
            self.rig.rows[name]["RestartCount"]=1
        release=self.stage()
        release.backup=lambda: (_ for _ in ()).throw(RuntimeError("simulated backup failure"))
        with self.assertRaisesRegex(RuntimeError,"simulated backup failure"):
            vm.perform(release)
        failure=json.loads((self.rig.media/"failure.json").read_text())
        self.assertEqual((failure["rollback"],failure["ingress"]),("complete","open"))
        for name in ("control-plane","proxy-server","worker"):
            self.assertEqual(self.rig.rows[name]["RestartCount"],0)

    def test_failed_apply_restores_historical_writer_counters_to_zero(self):
        for name in ("proxy-server","worker"):
            self.rig.rows[name]["RestartCount"]=1
        release=self.stage()
        self.fail_verify=True
        with self.assertRaisesRegex(RuntimeError,"payload differs"):
            vm.perform(release)
        failure=json.loads((self.rig.media/"failure.json").read_text())
        self.assertEqual((failure["rollback"],failure["ingress"]),("complete","open"))
        self.assertTrue(all(self.rig.rows[name]["Image"]==self.common.OLD for name in TARGETS))
        for name in ("proxy-server","worker"):
            self.assertEqual(self.rig.rows[name]["RestartCount"],0)

    def test_persist_refuses_runtime_drift_without_writing_chain(self):
        release=self.stage()
        vm.perform(release)
        release.lock_file.close()
        pin=vm.digest(self.rig.media/"receipt.json")
        original=self.rig.chain.read_bytes()
        self.rig.rows["chat-idp"]["Config"]["Env"].append("UNAPPROVED=true")
        with self.assertRaisesRegex(RuntimeError,"runtime|non-target"):
            vm.perform_persist_boot(self.rig.media,vm.digest(self.rig.media/"manifest.json"),pin)
        self.assertEqual(self.rig.chain.read_bytes(),original)

    def test_backup_failure_resumes_original_five_and_writers_after_started_at_advances(self):
        release=self.stage()
        original=copy.deepcopy(self.rig.rows)
        def fail_backup(): raise RuntimeError("simulated pg_dump failure before mutation")
        release.backup=fail_backup
        with self.assertRaisesRegex(RuntimeError,"simulated pg_dump failure"):
            vm.perform(release)
        failure=json.loads((self.rig.media/"failure.json").read_text())
        self.assertEqual(failure["rollback"],"complete")
        self.assertEqual(failure["ingress"],"open")
        self.assertTrue(any("-D" in command for command in self.rig.iptables))
        for name in TARGETS+("proxy-server","worker","security-engine"):
            self.assertEqual(self.rig.rows[name]["Id"],original[name]["Id"])
            self.assertEqual(self.rig.rows[name]["Image"],original[name]["Image"])
            self.assertEqual(self.rig.rows[name]["RestartCount"],original[name]["RestartCount"])
            self.assertNotEqual(self.rig.rows[name]["State"]["StartedAt"],original[name]["State"]["StartedAt"])
        for name in ("tier1-classifier","llm-judge","chat-idp"):
            self.assertEqual(self.rig.rows[name],original[name])

    def test_backup_failure_refuses_backwards_and_invalid_started_at(self):
        for timestamp in ("2026-10-10T13:00:00.000000000Z", "resumed", "2026-02-30T14:01:00Z",
                          "2026-10-10T14:01:00.1234567890Z"):
            with self.subTest(timestamp=timestamp):
                case=IdentityChatApplyTests("runTest")
                case.setUp()
                try:
                    release=case.stage()
                    def fail_backup(): raise RuntimeError("simulated pg_dump failure")
                    release.backup=fail_backup
                    original=case.fake_run
                    def run(argv,**kwargs):
                        result=original(argv,**kwargs)
                        if argv[0]==str(case.rig.compose_bin) and "start" in argv:
                            case.rig.rows["gateway-core"]["State"]["StartedAt"]=timestamp
                        return result
                    with patch.object(vm,"run",side_effect=run),self.assertRaisesRegex(RuntimeError,"StartedAt|timestamp"):
                        vm.perform(release)
                    failure=json.loads((case.rig.media/"failure.json").read_text())
                    self.assertEqual((failure["rollback"],failure["ingress"]),("incomplete","fenced"))
                    self.assertFalse(any("-D" in command for command in case.rig.iptables))
                finally:
                    case.doCleanups()

    def test_started_at_validation_retains_nanosecond_precision_and_allows_equal_instants(self):
        self.assertEqual(vm.docker_started_at_ns("2026-10-10T14:00:00Z"),
                         vm.docker_started_at_ns("2026-10-10T14:00:00.000000000Z"))
        first=vm.docker_started_at_ns("2026-10-10T14:00:00.000000001Z")
        second=vm.docker_started_at_ns("2026-10-10T14:00:00.000000002Z")
        self.assertEqual(second-first,1)
        self.assertEqual(first,vm.docker_started_at_ns("2026-10-10T22:00:00.000000001+08:00"))

    def test_backup_failure_waits_for_resumed_targets_to_become_healthy_before_unfence(self):
        release=self.stage()
        def fail_backup(): raise RuntimeError("simulated pg_dump failure before mutation")
        release.backup=fail_backup
        original=self.fake_run
        checks=[]
        resumed=False
        def run(argv,**kwargs):
            nonlocal resumed
            if argv[0]==str(self.rig.compose_bin) and "start" in argv:
                output=original(argv,**kwargs)
                resumed=True
                for name in TARGETS+("proxy-server","worker","security-engine"):
                    self.rig.rows[name]["State"]["Health"]["Status"]="starting"
                return output
            if resumed and argv[:2]==["docker","inspect"]:
                checks.append(argv)
                if len(checks)>1:
                    for name in TARGETS+("proxy-server","worker","security-engine"):
                        self.rig.rows[name]["State"]["Health"]["Status"]="healthy"
            if resumed and argv[:2]==["iptables","-D"]:
                self.assertGreaterEqual(len(checks),2)
                self.assertTrue(all(self.rig.rows[name]["State"]["Health"]["Status"]=="healthy"
                                    for name in TARGETS+("proxy-server","worker","security-engine")))
            return original(argv,**kwargs)
        with patch.object(vm,"run",side_effect=run),patch.object(vm.time,"sleep"), \
                self.assertRaisesRegex(RuntimeError,"simulated pg_dump failure"):
            vm.perform(release)
        self.assertGreaterEqual(len(checks),2)
        failure=json.loads((self.rig.media/"failure.json").read_text())
        self.assertEqual((failure["rollback"],failure["ingress"]),("complete","open"))

    def test_backup_failure_cannot_ignore_recreated_target_or_unpaused_service_timestamp(self):
        for changed in ("gateway-core","chat-idp"):
            with self.subTest(changed=changed):
                release=self.stage()
                def fail_backup(): raise RuntimeError("simulated pg_dump failure")
                release.backup=fail_backup
                original=self.fake_run
                def run(argv,**kwargs):
                    result=original(argv,**kwargs)
                    if argv[0]==str(self.rig.compose_bin) and "start" in argv:
                        if changed=="gateway-core": self.rig.rows[changed]["Id"]="unapproved-new-container"
                        else: self.rig.rows[changed]["State"]["StartedAt"]="unapproved-restart"
                    return result
                with patch.object(vm,"run",side_effect=run),self.assertRaisesRegex(RuntimeError,"identity|runtime"):
                    vm.perform(release)
                failure=json.loads((self.rig.media/"failure.json").read_text())
                self.assertEqual((failure["rollback"],failure["ingress"]),("incomplete","fenced"))
                self.assertFalse(any("-D" in command for command in self.rig.iptables))
                # This test has one disposable rig; the first case leaves it fenced.
                # Finish its cleanups before constructing the next independent case.
                if changed=="gateway-core":
                    self.doCleanups()
                    self.setUp()

    def test_failure_after_receipt_pointer_write_restores_the_exact_previous_pointer(self):
        release=self.stage()
        original_commit=release.commit
        def fail_commit():
            original_commit()
            raise RuntimeError("commit failed after pointer write")
        release.commit=fail_commit
        with self.assertRaisesRegex(RuntimeError,"commit failed"):
            vm.perform(release)
        self.assertEqual(self.rig.pointer.read_text(),self.rig.previous_pointer)
        failure=json.loads((self.rig.media/"failure.json").read_text())
        self.assertEqual(failure["rollback"],"complete")
        self.assertEqual(failure["ingress"],"open")
        self.assertEqual(self.rig.current_ledger,self.rig.before_ledger)

    def test_restore_failure_retains_fence_and_protected_failure_evidence(self):
        release=self.stage()
        self.fail_verify=True
        def fail_restore(): raise RuntimeError("restore failed")
        release.restore=fail_restore
        with self.assertRaisesRegex(RuntimeError,"restore failed"):
            vm.perform(release)
        failure=json.loads((self.rig.media/"failure.json").read_text())
        self.assertEqual(failure["rollback"],"incomplete")
        self.assertEqual(failure["ingress"],"fenced")
        self.assertFalse(any("-D" in command for command in self.rig.iptables))
        self.assertEqual((self.rig.media/"failure.json").stat().st_mode & 0o777,0o600)

    def test_verify_failure_restores_database_and_exact_old_five_images(self):
        release=self.stage()
        self.fail_verify=True
        with self.assertRaisesRegex(RuntimeError,"payload differs"):
            vm.perform(release)
        self.assertEqual(self.rig.current_ledger,self.rig.before_ledger)
        self.assertTrue(all(self.rig.rows[name]["Image"]==self.common.OLD for name in TARGETS))
        self.assertTrue((self.rig.media/"rollback.json").is_file())
        self.assertTrue(any("--clean" in command for command in self.subprocess_commands))
        self.assertFalse(any("tier1-classifier" in command for command in self.rig.stops+self.rig.starts))

    def test_boot_nonscalar_drift_remains_fail_closed(self):
        release=self.stage()
        vm.perform(release)
        release.lock_file.close()
        original=self.rig.chain.read_bytes()
        base=json.loads(self.rig.base.read_text())
        base["services"]["chat-portal-ui"]["volumes"]=[dict(type="volume",source="foreign",target="/data")]
        # stage bound inputs remain immutable. This authenticated fixture introduces
        # the resource drift only in the boot renderer, not into staged files.
        original_render=vm.render_compose
        def render(*args):
            return base if args[-1][0]==self.rig.base else original_render(*args)
        pin=vm.digest(self.rig.media/"receipt.json")
        with patch.object(vm,"render_compose",side_effect=render),self.assertRaisesRegex(RuntimeError,"outside permitted"):
            vm.perform_persist_boot(self.rig.media,vm.digest(self.rig.media/"manifest.json"),pin)
        self.assertEqual(self.rig.chain.read_bytes(),original)


class IdentityChatHostTests(unittest.TestCase):
    def setUp(self):
        import test_vm_development_persist_host as common
        self.rig=common.HostPersistTests("runTest")
        self.rig.setUp()
        self.addCleanup(self.rig.doCleanups)
        self.rig.manifest=manifest(apply_script_sha256="c"*64)
        self.rig.manifest["services"]={name:{} for name in TARGETS}
        (self.rig.media/"manifest.json").write_text(json.dumps(self.rig.manifest))

    def test_host_transfers_applies_pins_and_persists_the_identity_chat_release(self):
        with patch.object(deploy,"validate_identity_chat_source_media",create=True) as validator:
            output=self.rig.run_deploy()
        validator.assert_called_once()
        result=json.loads(output.splitlines()[-1])
        self.assertTrue(result["boot_persisted"])
        self.assertEqual(result["receipt_sha256"],"e"*64)
        self.assertEqual(len(self.rig.calls),5)
        self.assertIn("protected(root.parent",self.rig.calls[0])

    def test_host_six_service_transfer_keeps_proxy_in_the_authenticated_persisted_scope(self):
        self.rig.manifest["include_proxy_server"] = True
        self.rig.manifest["services"]["proxy-server"] = {}
        (self.rig.media/"manifest.json").write_text(json.dumps(self.rig.manifest))
        deploy.validate_persist_scope(self.rig.manifest)
        with patch.object(deploy, "validate_identity_chat_source_media", create=True) as validator:
            output = self.rig.run_deploy()
        validator.assert_called_once()
        result = json.loads(output.splitlines()[-1])
        self.assertTrue(result["boot_persisted"])
        self.assertEqual(result["receipt_sha256"], "e"*64)
        for code in self.rig.calls[2:]: compile(code, "six-service-protected-guest", "exec")
        self.assertIn("include_proxy_server", deploy.persist_guest_code("dev-six-service", "a"*64, "b"*64))
        self.assertIn("include_proxy_server", deploy.identity_chat_rollback_guest_code("dev-six-service", "c"*64))

    def test_identity_chat_deploy_requires_boot_persistence_before_transfer(self):
        self.rig.args.persist_boot=False
        with self.assertRaisesRegex(RuntimeError,"identity-chat.*persist"):
            self.rig.run_deploy()
        self.assertFalse(self.rig.calls)

    def test_identity_chat_rollback_bootstrap_authenticates_receipt_media_and_owner(self):
        code=deploy.identity_chat_rollback_guest_code("dev-identity-test","d"*64)
        self.assertIn("current.json",code)
        self.assertIn("manifest_sha256",code)
        self.assertIn("apply_script_sha256",code)
        self.assertIn("validate_persist_scope",code)
        self.assertIn("--install-owner-uid",code)
        self.assertIn("'-I'",code)
        self.assertNotIn("SUDO_UID=",code)
        compile(code,"identity-chat-rollback-bootstrap","exec")

    def test_identity_chat_rollback_cli_is_separate_from_console_and_se(self):
        args=["deploy_vm_development.py","--repo","/home/dev/reviewed",
              "--rollback-identity-chat-release-id","dev-identity-test","--receipt-sha256","d"*64]
        with patch.object(sys,"argv",args),patch.object(deploy,"release_lock",contextlib.nullcontext), \
                patch.object(deploy,"rollback_recorded") as rollback:
            deploy.main()
        self.assertEqual(rollback.call_args.args[0].rollback_identity_chat_release_id,"dev-identity-test")


class IdentityChatProductionClosureTests(unittest.TestCase):
    def test_pnpm_virtual_store_generated_client_is_flattened_into_the_new_runtime(self):
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            modules=root/"source/node_modules"
            client=modules/".pnpm/client-fixed/node_modules/@prisma/client"
            client.mkdir(parents=True)
            (client/"package.json").write_text('{"version":"6.19.3"}')
            scope=modules/"@prisma"
            scope.mkdir()
            (scope/"client").symlink_to(client,target_is_directory=True)
            generated=client.parent.parent/".prisma/client"
            generated.mkdir(parents=True)
            (generated/"index.js").write_bytes(b"new-virtual-store-client")
            (root/"source/package.json").write_text('{"dependencies":{"@prisma/client":"6.19.3"}}')
            script=root/"closure.js"
            script.write_text(build.PROXY_PRODUCTION_CLOSURE)
            output=root/"output/node_modules"
            subprocess.run(["node",str(script),str(modules),str(output),str(root/"source/package.json")],
                           check=True,capture_output=True,text=True)
            self.assertEqual((output/".prisma/client/index.js").read_bytes(),b"new-virtual-store-client")
            self.assertFalse((output/".pnpm").exists())
            self.assertFalse(any(path.is_symlink() for path in output.rglob("*")))


    def test_closure_executes_with_only_production_dependencies_and_new_generated_client(self):
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            modules=root/"source/node_modules"
            modules.mkdir(parents=True)
            package=dict(dependencies={"prisma":"6.19.3","@prisma/client":"6.19.3","pg":"8.22.0"},
                         devDependencies={"typescript":"5.9.3"})
            (root/"source/package.json").write_text(json.dumps(package))
            fixtures={"prisma":{"version":"6.19.3","dependencies":{"@prisma/engines":"6.19.3"}},
                      "@prisma/engines":{"version":"6.19.3"},
                      "@prisma/client":{"version":"6.19.3"},
                      "pg":{"version":"8.22.0","dependencies":{"pg-protocol":"1.0.0"}},
                      "pg-protocol":{"version":"1.0.0"},
                      "typescript":{"version":"5.9.3"}}
            for name,content in fixtures.items():
                path=modules/name
                path.mkdir(parents=True)
                (path/"package.json").write_text(json.dumps(content))
                (path/"locked-content.js").write_text(name)
            generated=modules/".prisma/client"
            generated.mkdir(parents=True)
            (generated/"index.js").write_bytes(b"new-generated-client")
            script=root/"closure.js"
            script.write_text(build.PROXY_PRODUCTION_CLOSURE)
            output=root/"output/node_modules"
            subprocess.run(["node",str(script),str(modules),str(output),str(root/"source/package.json")],check=True,capture_output=True,text=True)
            self.assertFalse((output/"typescript").exists())
            self.assertTrue((output/"pg-protocol/package.json").is_file())
            self.assertEqual((output/".prisma/client/index.js").read_bytes(),b"new-generated-client")
            self.assertTrue((output/".bin/prisma").stat().st_mode & 0o111)
            self.assertFalse(any(path.is_symlink() for path in output.rglob("*")))
            self.assertIn("exec node", (output/".bin/prisma").read_text())




class ChatPortalSelfServicePreflightTests(unittest.TestCase):
    def test_proxy_trust_is_explicit_exact_and_manifest_approved(self):
        m=manifest(chat_login_proxy_trust=True)
        expected={"JJD_CHAT_LOGIN_TRUSTED_PROXY_HOSTS":"chat-portal-ui,web-console"}
        self.assertEqual(vm.chat_login_proxy_environment(m),expected)
        rows = {name:dict(Config=dict(Env=[])) for name in TARGETS}
        rows["control-plane"]["Config"]["Env"] = ["JJD_INTERNAL_API_SECRET="+"a"*40]
        self.assertEqual(vm.manifest_approved_environment(m, rows)["control-plane"]["JJD_CHAT_LOGIN_TRUSTED_PROXY_HOSTS"],expected["JJD_CHAT_LOGIN_TRUSTED_PROXY_HOSTS"])
        self.assertEqual(vm.chat_login_proxy_environment(manifest()),{})
        for changed in (manifest(chat_login_proxy_trust="true"),manifest(chat_login_proxy_trust=True,identity_chat_only=False)):
            with self.assertRaises(RuntimeError): vm.chat_login_proxy_environment(changed)

    def test_signed_ip_environment_is_purpose_derived_shared_and_kept_private(self):
        import hmac
        m = manifest(chat_login_proxy_trust=True)
        master = "fixture-master-"+"a"*40
        rows = {name:dict(Config=dict(Env=[])) for name in TARGETS}
        rows["control-plane"]["Config"]["Env"] = ["JJD_INTERNAL_API_SECRET="+master]
        signed = vm.login_ip_forward_environment(m, rows)
        expected = hmac.new(master.encode(), b"jjdguard-login-ip-forward-v1", hashlib.sha256).hexdigest()
        self.assertEqual(set(signed), {"control-plane", "web-console", "chat-portal-ui"})
        self.assertTrue(all(v == {"JJD_LOGIN_IP_FORWARD_SECRET":expected} for v in signed.values()))
        self.assertNotEqual(expected, master)
        approved = vm.manifest_approved_environment(m, rows)
        self.assertEqual(approved["web-console"]["JJD_LOGIN_IP_FORWARD_SECRET"], expected)
        self.assertNotIn(expected, json.dumps(m))

    def test_signed_ip_environment_rejects_missing_master_and_partial_or_conflicting_config(self):
        m = manifest(chat_login_proxy_trust=True)
        rows = {name:dict(Config=dict(Env=[])) for name in TARGETS}
        with self.assertRaisesRegex(RuntimeError, "signing"):
            vm.login_ip_forward_environment(m, rows)
        rows["control-plane"]["Config"]["Env"] = ["JJD_INTERNAL_API_SECRET="+"a"*40,
                                                   "JJD_LOGIN_IP_FORWARD_SECRET="+"b"*64]
        with self.assertRaisesRegex(RuntimeError, "signing"):
            vm.login_ip_forward_environment(m, rows)
        for name in ("web-console", "chat-portal-ui"):
            rows[name]["Config"]["Env"] = ["JJD_LOGIN_IP_FORWARD_SECRET="+"b"*64]
        preserved = vm.login_ip_forward_environment(m, rows)
        self.assertTrue(all(v["JJD_LOGIN_IP_FORWARD_SECRET"] == "b"*64 for v in preserved.values()))
        rows["web-console"]["Config"]["Env"] = ["JJD_LOGIN_IP_FORWARD_SECRET="+"c"*64]
        with self.assertRaisesRegex(RuntimeError, "signing"):
            vm.login_ip_forward_environment(m, rows)

    def test_missing_unassigned_department_is_a_read_only_preflight_failure(self):
        queries=[]
        def sql(query):
            queries.append(query)
            return json.dumps(["tenant-needs-default"])
        with self.assertRaisesRegex(RuntimeError,"unassigned department"):
            vm.chat_portal_defaults_preflight(sql)
        self.assertTrue(all("SELECT" in q and "UPDATE" not in q and "INSERT" not in q for q in queries))
        vm.chat_portal_defaults_preflight(lambda _: "[]")

if __name__ == "__main__":
    unittest.main()
