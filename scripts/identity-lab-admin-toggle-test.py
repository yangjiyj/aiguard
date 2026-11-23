#!/usr/bin/env python3
import importlib.util
import pathlib
import unittest


MODULE_PATH = pathlib.Path(__file__).with_name("identity-lab-admin-toggle.py")
SPEC = importlib.util.spec_from_file_location("identity_lab_admin_toggle", MODULE_PATH)
assert SPEC and SPEC.loader
toggle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(toggle)


def component(name: str, component_id: str, enabled: str = "true") -> dict:
    return {
        "id": component_id,
        "name": name,
        "config": {"enabled": [enabled]},
    }


class DirectoryToggleRollbackTest(unittest.TestCase):
    def test_second_update_failure_rolls_back_first_component(self) -> None:
        ldap = component("ldap-federation", "ldap")
        ad = component("ad-federation", "ad")
        state = {"ldap": "true", "ad": "true"}
        put_calls: list[tuple[str, str]] = []
        failed_once = False

        def fake_request(_opener, method, path, _token="", body=None):
            nonlocal failed_once
            if method == "GET" and path.endswith("UserStorageProvider"):
                return 200, [ldap, ad]
            component_id = path.rsplit("/", 1)[-1]
            if method == "PUT":
                desired = body["config"]["enabled"][0]
                put_calls.append((component_id, desired))
                if component_id == "ad" and desired == "false" and not failed_once:
                    failed_once = True
                    raise toggle.ToggleError()
                state[component_id] = desired
                return 204, None
            if method == "GET":
                actual = component(
                    "ldap-federation" if component_id == "ldap" else "ad-federation",
                    component_id,
                    state[component_id],
                )
                return 200, actual
            raise AssertionError((method, path))

        original = toggle.request
        toggle.request = fake_request
        try:
            with self.assertRaises(toggle.ToggleError):
                toggle.toggle_directories(object(), "token", False)
        finally:
            toggle.request = original

        self.assertEqual(state, {"ldap": "true", "ad": "true"})
        self.assertIn(("ldap", "false"), put_calls)
        self.assertIn(("ldap", "true"), put_calls)

    def test_retry_succeeds_after_rolled_back_partial_failure(self) -> None:
        ldap = component("ldap-federation", "ldap")
        ad = component("ad-federation", "ad")
        state = {"ldap": "true", "ad": "true"}

        def fake_request(_opener, method, path, _token="", body=None):
            if method == "GET" and path.endswith("UserStorageProvider"):
                return 200, [ldap, ad]
            component_id = path.rsplit("/", 1)[-1]
            if method == "PUT":
                state[component_id] = body["config"]["enabled"][0]
                return 204, None
            if method == "GET":
                return 200, component("", component_id, state[component_id])
            raise AssertionError((method, path))

        original = toggle.request
        toggle.request = fake_request
        try:
            toggle.toggle_directories(object(), "token", False)
            toggle.toggle_directories(object(), "token", True)
        finally:
            toggle.request = original
        self.assertEqual(state, {"ldap": "true", "ad": "true"})


if __name__ == "__main__":
    unittest.main()
