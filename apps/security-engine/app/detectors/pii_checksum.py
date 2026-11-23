"""中国大陆 PII 校验位算法：身份证 GB 11643-1999、银行卡 Luhn。

纯函数，无副作用，不抛异常（非法输入返回 False）。
"""
from __future__ import annotations

import re
from datetime import date

# GB 11643：前 17 位加权因子与对应校验码
_ID_WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
_ID_CHECK = ["1", "0", "X", "9", "8", "7", "6", "5", "4", "3", "2"]
_ID_SHAPE = re.compile(r"[0-9]{17}[0-9Xx]")
# Province-level prefixes, not a current county-code registry: historical
# administrative codes must remain detectable. Residence permits use 81/82/83.
_ID_AREA_PREFIXES = frozenset({
    "11", "12", "13", "14", "15", "21", "22", "23",
    "31", "32", "33", "34", "35", "36", "37",
    "41", "42", "43", "44", "45", "46",
    "50", "51", "52", "53", "54", "61", "62", "63", "64", "65",
    "71", "81", "82", "83",
})


def validate_id_card_cn(number: str) -> bool:
    """Check plausible structure and GB 11643 checksum, not identity existence.

    A valid result does not prove that a county code or identity was issued.
    Birth dates must exist and not be in the future; no inferred age cutoff is
    applied, so historical records remain in scope.
    """
    if not isinstance(number, str) or _ID_SHAPE.fullmatch(number) is None:
        return False
    if number[:2] not in _ID_AREA_PREFIXES or number[14:17] == "000":
        return False
    try:
        birthday = date(int(number[6:10]), int(number[10:12]), int(number[12:14]))
    except ValueError:
        return False
    if birthday > date.today():
        return False
    body = number[:17]
    total = sum(int(body[i]) * _ID_WEIGHTS[i] for i in range(17))
    expected = _ID_CHECK[total % 11]
    return number[17].upper() == expected


def validate_bank_card(number: str) -> bool:
    if not isinstance(number, str) or not number.isascii() or not number.isdigit():
        return False
    if not (12 <= len(number) <= 19):
        return False
    # IIN 门控（P0-B）：真卡首位为主要卡组织标识 3/4/5/6
    # (3=Amex/JCB/Diners, 4=Visa, 5=Mastercard, 6=银联UnionPay/Discover)。
    # 随机 16-19 位数字串（时间戳/订单号/零填充计数器）虽可能偶然通过 Luhn，
    # 但绝不以 0/1/2/7/8/9 开头——据此毙掉绝大多数 bank_card 误报，对真卡零假阴性。
    if number[0] not in "3456":
        return False
    total = 0
    # 从最右侧起，奇数位（1-based）原值，偶数位翻倍后跨位相加
    for idx, ch in enumerate(reversed(number)):
        digit = int(ch)
        if idx % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


# MIIT 号段分配（截至 2024）：第 2 位 3-9，第 3 位按运营商实际启用号段。
# 140-144、154、160/161/163/164/168/169、179、194 未向公众放号，这些数字串是
# 流水号、金额或时间戳，不是手机号。物联网 1440 段不属于个人号码。
_MOBILE_SEGMENT = re.compile(r"1(?:3[0-9]|4[5-9]|5[0-35-9]|6[2567]|7[0-8]|8[0-9]|9[0-35-9])[0-9]{8}")


def validate_phone_cn_segment(number: str) -> bool:
    """Accept only 11-digit numbers whose first three digits are an allocated
    public mobile segment. This is a structural check, not a subscriber check."""
    return bool(_MOBILE_SEGMENT.fullmatch(str(number or "").strip()))
