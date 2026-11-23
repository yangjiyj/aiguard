"""Mandatory credential grammar gate; keep generated test values out of stdout."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

def main():
    root=Path(__file__).resolve().parents[1]
    artifacts=Path(tempfile.mkdtemp(prefix="jjdguard-credential-gate-"))
    report=artifacts/"junit.xml"
    tests=["tests/test_credential_grammar.py","tests/test_credential_replay.py","tests/test_credential_boundaries.py","tests/test_context_false_positive_regression.py",
           "tests/test_production_prose_replay.py","tests/test_semantic_context_exoneration.py"]
    with (artifacts/"pytest.log").open("w") as log:
        result=subprocess.run([sys.executable,"-m","pytest","-q",*tests,"--junitxml",str(report)],cwd=root,stdout=log,stderr=subprocess.STDOUT)
    summary={"exit_code":result.returncode,"artifacts":str(artifacts)}
    if report.exists():
        suites=ET.parse(report).getroot().findall("testsuite")
        for field in ("tests","failures","errors","skipped"):
            summary[field]=sum(int(s.get(field,"0")) for s in suites)
    print(json.dumps(summary))
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
