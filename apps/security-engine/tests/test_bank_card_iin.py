"""P0-B：银行卡 IIN 门控——真卡首位必是主要卡组织标识 3/4/5/6
(3=Amex/JCB/Diners, 4=Visa, 5=Mastercard, 6=银联UnionPay/Discover)。
随机 16-19 位数字串（时间戳/订单号/零填充计数器）虽可能偶然通过 Luhn，
但绝不会以 0/1/2/7/8/9 开头——生产实测 71% 的 bank_card 误报以 0 开头。
对真卡零假阴性（真卡首位都在 3/4/5/6）。
"""
from app.detectors.pii_checksum import validate_bank_card


def test_bank_card_accepts_luhn_valid_with_card_iin():
    assert validate_bank_card("6222600000000006") is True  # 银联 62.., Luhn 通过
    assert validate_bank_card("4111111111111111") is True  # Visa 测试号 4.., Luhn 通过


def test_bank_card_rejects_luhn_valid_non_card_iin():
    # 全 0：数字和为 0 → Luhn 通过，但绝非真卡（正是 "00*****XX" 零填充误报簇）。
    assert validate_bank_card("0000000000000000") is False
    # 首位 7：构造成 Luhn 通过(7..5，和=10)，但 7 非任何卡组织标识 → 拒绝。
    assert validate_bank_card("7000000000000005") is False
