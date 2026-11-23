#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

python3 - <<'PY'
class Rejected(RuntimeError):
    pass


class FormalRelease:
    mutating = {
        "build_candidate", "start_vm", "promote", "independent_verify",
        "production_upgrade", "production_verify", "edit_source",
    }

    def __init__(self):
        self.state = "frozen"
        self.final_sha = None
        self.candidates = 0
        self.vms = 0
        self.confirmed = False

    def apply(self, event, sha=None):
        if self.state in {"stopped", "complete"}:
            raise Rejected(f"terminal state rejects {event}")
        if self.state == "frozen" and event in self.mutating:
            raise Rejected(f"frozen release rejects {event}")
        if sha is not None and self.final_sha is not None and sha != self.final_sha:
            raise Rejected("final SHA drift")

        if event == "local_gate_pass":
            if self.state != "frozen":
                raise Rejected("local gate is only valid while frozen")
            self.state = "local_passed"
        elif event == "lock_final_sha":
            if self.state != "local_passed" or not sha or len(sha) != 40:
                raise Rejected("final SHA cannot be locked")
            self.final_sha = sha
            self.state = "awaiting_confirmation"
        elif event == "confirm":
            if self.state != "awaiting_confirmation":
                raise Rejected("confirmation is out of order")
            self.confirmed = True
            self.state = "authorized"
        elif event == "build_candidate":
            if self.state != "authorized" or not self.confirmed or sha != self.final_sha:
                raise Rejected("candidate build is not authorized")
            if self.candidates != 0:
                raise Rejected("only one candidate is allowed")
            self.candidates += 1
            self.state = "candidate_ready"
        elif event == "start_vm":
            if self.state != "candidate_ready" or sha != self.final_sha:
                raise Rejected("fresh VM is out of order")
            if self.vms != 0:
                raise Rejected("only one fresh VM is allowed")
            self.vms += 1
            self.state = "vm_running"
        elif event == "vm_fail":
            if self.state != "vm_running":
                raise Rejected("VM failure is out of order")
            self.state = "stopped"
        elif event == "vm_pass":
            if self.state != "vm_running" or sha != self.final_sha:
                raise Rejected("VM pass is not artifact-bound")
            self.state = "accepted"
        elif event == "promote":
            if self.state != "accepted" or sha != self.final_sha:
                raise Rejected("promotion requires accepted final SHA")
            self.state = "promoted"
        elif event == "independent_verify":
            if self.state != "promoted" or sha != self.final_sha:
                raise Rejected("independent verification is out of order")
            self.state = "independently_verified"
        elif event == "production_upgrade":
            if self.state != "independently_verified" or sha != self.final_sha:
                raise Rejected("production upgrade is not authorized")
            self.state = "production_upgraded"
        elif event == "production_verify":
            if self.state != "production_upgraded" or sha != self.final_sha:
                raise Rejected("production verification is out of order")
            self.state = "complete"
        else:
            raise Rejected(f"unknown or forbidden event: {event}")


def rejected(machine, event, sha=None):
    try:
        machine.apply(event, sha)
    except Rejected:
        return
    raise AssertionError(f"event should have been rejected: {event}")


sha = "a" * 40
other = "b" * 40

for forbidden in FormalRelease.mutating:
    rejected(FormalRelease(), forbidden, sha)

happy = FormalRelease()
happy.apply("local_gate_pass")
happy.apply("lock_final_sha", sha)
rejected(happy, "build_candidate", sha)
happy.apply("confirm")
happy.apply("build_candidate", sha)
happy.apply("start_vm", sha)
happy.apply("vm_pass", sha)
happy.apply("promote", sha)
happy.apply("independent_verify", sha)
happy.apply("production_upgrade", sha)
happy.apply("production_verify", sha)
assert happy.state == "complete" and happy.candidates == 1 and happy.vms == 1

drift = FormalRelease()
drift.apply("local_gate_pass")
drift.apply("lock_final_sha", sha)
drift.apply("confirm")
rejected(drift, "build_candidate", other)

failed = FormalRelease()
failed.apply("local_gate_pass")
failed.apply("lock_final_sha", sha)
failed.apply("confirm")
failed.apply("build_candidate", sha)
failed.apply("start_vm", sha)
failed.apply("vm_fail", sha)
for forbidden in ("edit_source", "build_candidate", "start_vm", "promote", "production_upgrade"):
    rejected(failed, forbidden, sha)

early = FormalRelease()
early.apply("local_gate_pass")
early.apply("lock_final_sha", sha)
early.apply("confirm")
early.apply("build_candidate", sha)
rejected(early, "promote", sha)
early.apply("start_vm", sha)
rejected(early, "start_vm", sha)
early.apply("vm_pass", sha)
rejected(early, "production_upgrade", sha)

print("[ok] one-shot formal release policy state machine passed")
PY

gates=(
  deploy/tests/test_bundle_upgrade_switch.sh
  deploy/tests/test_bundle_upgrade_discovery.sh
  deploy/tests/test_customer_installer_contract.sh
  deploy/tests/test_self_extracting_installer.sh
  deploy/tests/test_vm_acceptance_receipt.sh
  deploy/tests/test_offline_promotion.sh
)

for gate in "${gates[@]}"; do
  echo "[gate] $gate"
  bash "$ROOT/$gate"
done

echo '[ok] r12-r20 one-shot local state-machine gate passed'
