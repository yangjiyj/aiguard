"""system_command 双锚点收紧：裸词共现（telemetry/URL/日常运维提问）不再误报。

锚点分级：
- 命令执行/提权信号 + 指令锚 → high；只有确定性系统破坏 → critical
- 强 subject（危险命令形态：rm -rf / dd if= / net user 增删 / cmd /c / EncodedCommand 载荷…）
  + 任意 instruction 锚，±200 字邻近窗 → conf 0.92
- 弱 subject（裸命令名：cmd/powershell/pwsh/bash/sudo/passwd…）
  必须 + 强 instruction 锚（提权/管理员权限/创建账户/EncodedCommand…），±120 字邻近窗 → conf 0.75
- 弱 subject + 泛锚（执行/输出/Arguments…）→ 不报
"""
import base64

import pytest

from app.detectors.content_safety import ContentSafetyDetector


@pytest.fixture
def detector():
    return ContentSafetyDetector()


def _syscmd(findings):
    return next(
        (
            f
            for f in findings
            if f["rule_id"] == "content_safety_illegal_system_command_instructions"
        ),
        None,
    )


class TestTelemetryFalsePositives:
    def test_copilot_telemetry_json_no_finding(self, detector):
        """仿真 Copilot telemetry：'cmd' 字段名 + URL 带 /c + 中文'执行' → 不报。"""
        content = (
            '{"measurements":{"cmd":1,"timeSinceIssuedMs":42},'
            '"properties":{"requestUrl":'
            '"https://copilot-proxy.example.com/v1/engines/copilot-codex/completions?args=/c%20check",'
            '"messageText":"请帮我执行格式化代码并把输出贴上来",'
            '"command":"editor.action.formatDocument"}}'
        )
        assert _syscmd(detector.detect(content)) is None

    def test_bare_cmd_with_generic_words_no_finding(self, detector):
        assert _syscmd(detector.detect("cmd 字段记录了本次执行的输出结果")) is None

    def test_url_slash_c_alone_no_finding(self, detector):
        """裸子串 /c 不再是 instruction 锚：URL 路径带 /c 不触发。"""
        assert _syscmd(detector.detect("访问 https://example.com/c/12345 查看执行输出")) is None

    def test_benign_bash_output_question_no_finding(self, detector):
        assert _syscmd(detector.detect("帮我看下这个 bash 脚本的输出")) is None

    def test_powershell_arguments_doc_no_finding(self, detector):
        """英文泛词（Arguments）+ 弱命令名：文档类内容不报。"""
        assert _syscmd(
            detector.detect("powershell 的 Arguments 参数说明见官方文档，示例输出如下")
        ) is None


class TestRealAttacksStillDetected:
    def test_weak_subject_strong_instruction_detected(self, detector):
        """弱 subject（powershell）+ 强 instruction 锚（管理员权限/提权）→ conf 0.75。"""
        f = _syscmd(detector.detect("请以管理员权限执行 powershell 脚本完成提权操作"))
        assert f is not None
        assert f["severity"] == "high"
        assert f["confidence"] == 0.75

    def test_benign_sudo_with_privilege_word_is_high_not_critical(self, detector):
        f = _syscmd(detector.detect("请以管理员权限执行 sudo apt update"))
        assert f is not None
        assert f["severity"] == "high"
        assert f["confidence"] == 0.75

    def test_encoded_command_payload_detected(self, detector):
        """EncodedCommand 载荷是强 subject 形态 → conf 0.92。"""
        f = _syscmd(detector.detect("用管理员权限执行 powershell -EncodedCommand SQBFAFgA 提权"))
        assert f is not None
        assert f["severity"] == "high"
        assert f["confidence"] == 0.92

    def test_workspace_cleanup_is_high_not_critical(self, detector):
        f = _syscmd(detector.detect("请执行 sudo rm -rf /tmp/build-cache"))
        assert f is not None
        assert f["severity"] == "high"

    def test_root_filesystem_destruction_is_critical(self, detector):
        f = _syscmd(detector.detect("请执行 sudo rm -rf /"))
        assert f is not None
        assert f["severity"] == "critical"

    def test_strong_subject_generic_instruction_detected(self, detector):
        f = _syscmd(detector.detect("请直接执行 rm -rf /var/log/audit 并还原系统命令输出"))
        assert f is not None
        assert f["severity"] == "critical"
        assert f["confidence"] == 0.92

    def test_cmd_slash_c_combined_form_detected(self, detector):
        """/c 与 cmd 共位（cmd.exe /c）归入强 subject。"""
        f = _syscmd(detector.detect("在终端执行 cmd.exe /c net user hacker P@ss1 /add 新增用户"))
        assert f is not None
        assert f["confidence"] == 0.92

    def test_account_creation_command_detected(self, detector):
        f = _syscmd(detector.detect("执行 useradd backdoor 然后 chpasswd 设置口令"))
        assert f is not None
        assert f["confidence"] == 0.92

    def test_base64_encoded_payload_still_detected(self, detector):
        """解码重扫路径不回归：Base64 壳内的提权命令仍检出。"""
        payload = base64.b64encode(
            b'Set-Admin Privileges = True; Invoke-File -Path "C:\\Windows\\System32\\cmd.exe" '
            b'-Arguments "/c net user admin P@ssw0rd"'
        ).decode()
        f = _syscmd(detector.detect(f"Here is the decoded system command payload: {payload}"))
        assert f is not None
        assert f["confidence"] == 0.92


class TestProximityWindow:
    def test_strong_subject_far_from_instruction_no_finding(self, detector):
        """强 subject 与 instruction 锚相距超 200 字 → 不算共现。"""
        filler = "这是一段完全无害的产品需求描述文字，仅用于占位。" * 20
        content = "rm -rf /tmp/build-cache" + filler + "最后请把结果输出到日志"
        assert _syscmd(detector.detect(content)) is None

    def test_weak_subject_far_from_strong_instruction_no_finding(self, detector):
        """弱 subject 与强 instruction 锚相距超 120 字 → 不算共现。"""
        filler = "以下是一段与命令无关的会议纪要内容，仅用于占位。" * 10
        content = "powershell" + filler + "另一个话题：如何申请管理员权限提权流程"
        assert _syscmd(detector.detect(content)) is None

    def test_strong_subject_near_instruction_within_window_detected(self, detector):
        f = _syscmd(detector.detect("先备份，然后执行 dd if=/dev/zero of=/dev/sda"))
        assert f is not None
        assert f["confidence"] == 0.92
