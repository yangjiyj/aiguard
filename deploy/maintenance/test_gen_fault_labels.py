import contextlib, importlib.util, io, pathlib, tempfile, unittest

spec = importlib.util.spec_from_file_location("gen_fault_labels", pathlib.Path(__file__).with_name("gen_fault_labels.py"))
gen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen)


class GenFaultLabelsTests(unittest.TestCase):
    def test_regenerating_reproduces_the_committed_go_table(self):
        committed = gen.OUT.read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as tmp:
            gen.OUT = pathlib.Path(tmp) / "fault_grouping.go"
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    gen.main()
                regenerated = gen.OUT.read_text(encoding="utf-8")
            finally:
                gen.OUT = gen.ROOT / "apps/control-plane/internal/alert/fault_grouping.go"
        self.assertEqual(regenerated, committed)

    def test_fault_title_follows_the_console_action_suffix(self):
        console = "    title = `检测运行故障${actionSuffix(pickString(body, 'action'))}`\n"
        self.assertEqual(gen.lift_fault_title(console, "检测运行故障"), "检测运行故障")
        with self.assertRaises(SystemExit):
            gen.lift_fault_title("    title = `运行告警${actionSuffix(x)}`\n", "检测运行故障")


if __name__ == "__main__":
    unittest.main()
