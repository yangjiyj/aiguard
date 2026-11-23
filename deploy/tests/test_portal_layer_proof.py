import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("portal_builder", ROOT/"deploy/release/build_vm_development.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class PortalExtractionPermissionsTests(unittest.TestCase):
    def test_reader_is_restricted_and_only_output_ownership_is_normalized(self):
        with tempfile.TemporaryDirectory() as temporary:
            context = Path(temporary)/"context"
            context.mkdir(mode=0o700)
            captured = []
            def capture(args, **kwargs):
                captured.append(args)
                package = context/"verified-prisma-closure/node_modules/prisma"
                package.mkdir(parents=True)
                (package/"package.json").write_text('{"version":"6.19.3"}')
            with mock.patch.object(builder, "run", side_effect=capture):
                builder.extract_portal_prisma_closure(context, "sha256:fixture", {}, Path(temporary))
            args = captured[0]
            self.assertEqual(args[args.index("--user")+1], "0:0")
            self.assertIn("--read-only", args)
            self.assertIn("--network=none", args)
            self.assertIn("--cap-drop=ALL", args)
            self.assertIn("--security-opt=no-new-privileges", args)
            self.assertEqual({arg for arg in args if arg.startswith("--cap-add=")},
                             {"--cap-add=DAC_OVERRIDE", "--cap-add=CHOWN", "--cap-add=FOWNER"})
            self.assertIn("dst=/source,readonly", " ".join(args))
            self.assertIn("chown -hR "+str(os.getuid())+":"+str(os.getgid())+" /out/node_modules", args[-1])
            self.assertNotIn("chmod", args[-1])
            recipe = builder.portal_dockerfile("old", "pinned", {"Entrypoint":["entrypoint"],"ExposedPorts":{"3100/tcp":{}},"Env":["NODE_ENV=production","npm_config_registry=https://registry.npmjs.org","PRISMA_ENGINES_CHECKSUM_IGNORE_MISSING=1"]}, "portal", [])
            self.assertIn("USER portal", recipe)


class PortalLayerProofTests(unittest.TestCase):
    def setUp(self):
        self.runtime = ["runtime"]
        self.dependency = self.runtime + ["workdir", "user", "prisma", "old-app"]
        self.candidate = self.runtime + ["workdir", "user", "prisma", "new-app"]

    def verified(self, candidate, dependency=None):
        return builder.verify_portal_layers(candidate, dependency or self.dependency, self.runtime,
                                           prisma_closure_verified=True, application_payload_verified=True)

    def test_only_the_exact_last_but_one_dependency_layer_may_be_stable(self):
        proof = self.verified(self.candidate)
        self.assertEqual(proof, {"shared_setup_prefix_layers":3,
                               "prisma_reuse_candidate_index":3, "prisma_reuse_diff_id":"prisma"})

    def test_both_independent_proofs_are_mandatory(self):
        for closure, payload in [(False,False),(True,False),(False,True),(1,True),(True,1)]:
            with self.subTest(closure=closure, payload=payload), self.assertRaises(AssertionError):
                builder.verify_portal_layers(self.candidate, self.dependency, self.runtime,
                                              prisma_closure_verified=closure, application_payload_verified=payload)

    def test_old_application_layer_is_rejected_at_any_position(self):
        for candidate in [self.dependency, self.runtime+["workdir","user","old-app","new-app"],
                          self.runtime+["workdir","user","old-app","prisma","new-app"],
                          self.runtime+["workdir","user","prisma","new-app","old-app"]]:
            with self.subTest(candidate=candidate), self.assertRaises(AssertionError):
                self.verified(candidate)

    def test_injected_old_prisma_layer_before_final_two_is_rejected(self):
        with self.assertRaises(AssertionError):
            self.verified(self.runtime+["workdir","user","prisma","prisma","new-app"])

    def test_common_prefix_cannot_extend_into_dependency_application_layers(self):
        with self.assertRaises(AssertionError):
            self.verified(self.dependency+["new-prisma","new-app"])

    def test_unrelated_prisma_layer_at_other_dependency_index_is_rejected(self):
        with self.assertRaises(AssertionError):
            self.verified(self.runtime+["workdir","user","workdir","new-app"])

    def test_old_app_alias_cannot_be_accepted_as_prisma(self):
        with self.assertRaises(AssertionError):
            self.verified(self.runtime+["workdir","user","old-app","new-app"],
                          self.runtime+["workdir","user","old-app","old-app"])

    def test_pinned_runtime_prefix_is_mandatory(self):
        with self.assertRaises(AssertionError):
            self.verified(["other-runtime"]+self.candidate[1:])


class PortalTreeProofTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.closure = self.root/"closure"
        self.payload = self.root/"payload"
        self.candidate = self.root/"candidate"
        self.closure.mkdir(mode=0o700)
        self.payload.mkdir(mode=0o755)
        package = self.closure/"node_modules/prisma"
        package.mkdir(parents=True)
        (package/"package.json").write_text('{"version":"6.19.3"}')
        (package/"build").mkdir()
        (package/"build/index.js").write_bytes(b"cli")
        (self.closure/"node_modules/.bin").mkdir()
        (self.closure/"node_modules/.bin/prisma").symlink_to("../prisma/build/index.js")
        (self.payload/"server.js").write_bytes(b"fresh-source-server")
        (self.payload/"empty-dir").mkdir()
        shutil.copytree(self.closure, self.candidate, symlinks=True)
        shutil.copytree(self.payload, self.candidate, dirs_exist_ok=True, symlinks=True)
        self.closed = builder.portal_tree_manifest(self.closure)
        self.fresh = builder.portal_tree_manifest(self.payload)

    def verify(self):
        return builder.verify_portal_union(self.candidate, self.closed, self.fresh)

    def test_exact_union_preserves_types_links_modes_and_empty_directories(self):
        self.assertEqual(self.verify(), builder.portal_tree_digest(dict(self.closed, **self.fresh)))
        manifest = builder.portal_tree_manifest(self.candidate)
        self.assertEqual(manifest["node_modules/.bin/prisma"]["kind"], "symlink")
        self.assertEqual(manifest["."]["mode"], 0o755)
        self.assertIn("empty-dir", manifest)

    def test_extra_file_and_missing_empty_directory_are_rejected(self):
        (self.candidate/"old-source.js").write_bytes(b"old")
        with self.assertRaises(AssertionError): self.verify()
        (self.candidate/"old-source.js").unlink()
        (self.candidate/"empty-dir").rmdir()
        with self.assertRaises(AssertionError): self.verify()

    def test_permission_change_at_file_and_root_is_rejected(self):
        (self.candidate/"server.js").chmod(0o777)
        with self.assertRaises(AssertionError): self.verify()
        shutil.copy2(self.payload/"server.js", self.candidate/"server.js")
        self.candidate.chmod(0o777)
        with self.assertRaises(AssertionError): self.verify()

    def test_file_hash_and_file_type_tampering_are_rejected(self):
        (self.candidate/"server.js").write_bytes(b"tampered")
        with self.assertRaises(AssertionError): self.verify()
        (self.candidate/"server.js").unlink()
        (self.candidate/"server.js").mkdir()
        with self.assertRaises(AssertionError): self.verify()

    def test_link_target_change_is_rejected_even_if_target_content_matches(self):
        binary = self.candidate/"node_modules/prisma/build/index.js"
        alternate = binary.with_name("alternate.js")
        shutil.copy2(binary, alternate)
        link = self.candidate/"node_modules/.bin/prisma"
        link.unlink()
        link.symlink_to("../prisma/build/alternate.js")
        with self.assertRaises(AssertionError): self.verify()

    def test_absolute_escaping_and_dangling_links_are_rejected(self):
        link = self.candidate/"node_modules/.bin/prisma"
        link.unlink()
        for target in [str(self.payload/"server.js"), "../../../payload/server.js", "../missing.js"]:
            with self.subTest(target=target):
                link.symlink_to(target)
                with self.assertRaises(AssertionError): self.verify()
                link.unlink()

    def test_root_symlink_is_rejected_before_resolving(self):
        shutil.rmtree(self.candidate)
        self.candidate.symlink_to(self.payload, target_is_directory=True)
        with self.assertRaises(AssertionError):
            builder.portal_tree_manifest(self.candidate)

    def test_special_nodes_are_rejected(self):
        os.mkfifo(self.candidate/"pipe")
        with self.assertRaises(AssertionError): self.verify()


class PortalClosureVersionTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.lock = {"packages":{
            "node_modules/prisma":{"version":"6.19.3","dependencies":{"@prisma/engines":"6.19.3"}},
            "node_modules/@prisma/engines":{"version":"6.19.3","optionalDependencies":{"optional-engine":"1.0.0"}},
            "node_modules/optional-engine":{"version":"1.0.0"}}}
        for name, entry in self.lock["packages"].items():
            path = self.root/name
            path.mkdir(parents=True)
            (path/"package.json").write_text(json.dumps(entry))
        binary = b"frozen-engine"
        (self.root/"node_modules/@prisma/engines/schema-engine").write_bytes(binary)
        self.engines = {"platform":"linux-musl-openssl-3.0.x", "prisma_version":"6.19.3",
                        "manifest":[{"path":"schema-engine", "size":len(binary), "sha256":hashlib.sha256(binary).hexdigest()}]}

    def verify(self):
        return builder.validate_portal_prisma_closure(self.root, self.lock, self.engines)

    def test_recursive_package_versions_and_engines_match_frozen_lock(self):
        self.assertEqual(self.verify(), {"prisma":"6.19.3","@prisma/engines":"6.19.3","optional-engine":"1.0.0"})

    def test_root_or_transitive_dependency_version_drift_is_rejected(self):
        for name in ["prisma", "@prisma/engines", "optional-engine"]:
            with self.subTest(name=name):
                path = self.root/"node_modules"/name/"package.json"
                original = path.read_text()
                changed = json.loads(original); changed["version"] = "9.9.9"
                path.write_text(json.dumps(changed))
                with self.assertRaises(AssertionError): self.verify()
                path.write_text(original)

    def test_missing_transitive_package_and_changed_dependency_graph_are_rejected(self):
        path = self.root/"node_modules/optional-engine/package.json"
        path.unlink()
        with self.assertRaises(AssertionError): self.verify()
        path.write_text('{"version":"1.0.0"}')
        (self.root/"node_modules/prisma/package.json").write_text('{"version":"6.19.3"}')
        with self.assertRaises(AssertionError): self.verify()

    def test_engine_hash_and_engine_release_version_drift_are_rejected(self):
        self.engines["manifest"][0]["sha256"] = "0"*64
        with self.assertRaises(AssertionError): self.verify()
        self.engines["prisma_version"] = "6.18.0"
        with self.assertRaises(AssertionError): self.verify()


if __name__ == "__main__": unittest.main()
