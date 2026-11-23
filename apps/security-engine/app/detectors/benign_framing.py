"""Benign framing for catalog candidates: keep the evidence, do not alert.

A catalog rule matches words; it cannot tell a victim asking "is this a scam
script?" from a scammer asking for one. When the candidate's own sentences
carry a framing that fits the rule family (help seeking, debunking, news,
troubleshooting, ...) and no live demand of that family, the finding becomes
an observation. Live demands always win, and framing words inside the
matched components themselves never count.
"""
from __future__ import annotations

import re
from bisect import bisect_right
from typing import Callable, Dict, Iterable, Iterator, Optional, Sequence, Tuple, Union

from app.detectors.evidence_context import has_live_payload

Span = Tuple[int, int]

_W = r"(?<![A-Za-z0-9_])"
_E = r"(?![A-Za-z0-9_])"


def _en(*words: str) -> str:
    return _W + "(?:" + "|".join(words) + ")" + _E


_SENTENCE_END = re.compile(r"[。！？!?；;\n]")
_CLAUSE_END = re.compile(r"[，,：:。！？!?；;\n]")

# 购买说法。违法交易族认全部说法（“正品、正规、官方购买渠道”不算）。伤害与有害内容族只认求购句式：
# 哪里能买、去哪买、哪里买得到、哪里有卖、怎么购买、如何购买、购买途径，货源、购买渠道只认
# 有没有货源、求货源、哪里有货源、货源在哪、购买渠道有哪些这类写法；
# “切断、追溯、查清、打击……货源”（同一分句 12 字内）和“本品购买渠道”不算。
_LEGIT_CHANNEL = r"(?<!正品)(?<!正规)(?<!官方)"
_PURCHASE_ASK = (r"哪里能买|哪里可以买|在哪(?:里|儿)?(?:能|可以)?买|哪儿(?:能|可以)?买|哪(?:里|儿)?买得到|去哪(?:里|儿)?买|"
                 r"哪(?:里|儿)?有卖|哪能买|怎么买|(?:怎么|如何)购买|帮我找(?:卖家|买家|渠道)|" + _LEGIT_CHANNEL + r"购买途径")
_PURCHASE = _PURCHASE_ASK + "|" + _LEGIT_CHANNEL + r"购买渠道|货源"
_SUPPLY_ASK = (r"(?:有没有|求|找|提供)(?:个|些|点)?(?:货源|购买渠道)|哪(?:里|儿)?有(?:货源|购买渠道)|"
               + _LEGIT_CHANNEL + r"(?:货源|购买渠道)(?:在哪|有哪些|是什么)")
_PURCHASE_EN = (r"where\s+(?:can\s+I|to)\s+buy",)
_SUPPLY_CUT = re.compile(r"切断|追溯|查清|打击")


class _ContentLive:
    """Content-family live demands; 货源 / 购买渠道 / 购买途径 right after 切断、追溯、查清、打击 is no purchase ask."""

    def __init__(self, pattern: "re.Pattern[str]"):
        self.pattern = pattern

    def finditer(self, text: str) -> Iterator["re.Match[str]"]:
        for match in self.pattern.finditer(text):
            if match.group().startswith(("货源", "购买渠道", "购买途径")):
                before = _CLAUSE_END.split(text[max(0, match.start() - 12):match.start()])[-1]
                if _SUPPLY_CUT.search(before):
                    continue
            yield match

    def search(self, text: str) -> Optional["re.Match[str]"]:
        """First match ``finditer`` keeps, so callers can treat it like a compiled pattern."""
        return next(self.finditer(text), None)


LivePattern = Union["re.Pattern[str]", _ContentLive]


FRAMINGS: Dict[str, Tuple[str, "re.Pattern[str]"]] = {
    "help_seeking": ("求助、识别或维权", re.compile(
        r"是不是|是否(?:是|属于)|怎么(?:识别|辨别|鉴别|判断|维权|应对|拦截|屏蔽)|如何(?:识别|鉴别|辨别|应对|维权|举报|拦截|屏蔽)|"
        r"怎么办|怎么处理|举报|报警|求助|救助|识别(?!码)|被(?:骗|家暴|骚扰|抄袭|泄露|网暴|霸凌|人肉|攻击|欺负)|拦截|屏蔽|正品|"
        + _en(r"is\s+(?:this|it)\s+a\s+scam", r"how\s+(?:do\s+I|to)\s+(?:report|identify|spot|recogni[sz]e)", r"report(?:ing)?"),
        re.I)),
    "education_or_debunk": ("宣教、辟谣或揭露", re.compile(
        r"辟谣|澄清|揭露|科普|宣传教育|提醒大家|防诱骗|安全教育|反诈宣传|禁毒宣传|"
        + _en(r"debunk(?:ing)?", r"awareness", r"fact[-\s]*check(?:ing)?"),
        re.I)),
    "news_or_compliance": ("新闻、执法或合规", re.compile(
        r"警方|破获|通报|报道|(?<!假)(?<!虚假)新闻|判决|怎么判|量刑|法律后果|罪名|合规要求|有哪些规定|管理规定|管理办法|打击|海关查处|"
        + _en(r"news\s+reports?", r"reported\s+by", r"police\s+(?:say|said|report)", r"compliance\s+requirements?", r"regulations?", r"legal\s+consequences?",
              r"(?:shipping|safety|handling)\s+rules", r"logistics"),
        re.I)),
    "troubleshooting": ("排障", re.compile(
        r"怎么排查|如何排查|排查|怎么修|修复|怎么解决|如何解决|报错|有问题吗|崩溃了|变成了|导致|"
        + _en(r"bug", r"debug(?:ging)?", r"troubleshoot(?:ing)?", r"fix(?:ing)?", r"error"),
        re.I)),
    "remediation_or_detection": ("改造或检测", re.compile(
        r"换成|迁移到|改用|替换为|为什么不能用|不该用|检测|识别模型|应急响应|处置|恢复|"
        + _en(r"migrat(?:e|ing|ion)", r"replace\s+(?:it\s+)?with", r"instead\s+of", r"detect(?:ion|ing|or)?",
              r"incident\s+response"),
        re.I)),
    "not_model_prompt": ("对象不是模型自己", re.compile(
        r"我们(?:的|产品|公司|系统|项目|自己)|我写的|我最初|我之前发的|这段|"
        r"公司|团队|部门|防火墙|服务器|容器|太小|太大|该怎么调|推荐值|默认值|"
        + _en(r"our", r"my", r"we\s+use", r"I\s+sent", r"I\s+wrote", r"Windows", r"Linux", r"macOS", r"firewall", r"server",
              r"recommended", r"default", r"too\s+(?:small|large|low|high)"),
        re.I)),
    "routine_business": ("日常业务文书", re.compile(
        r"原路|官方\s*App|账单|宿舍押金|入职须知|研究报告|研报|帮助文档|操作指南|模拟盘比赛|接口|函数|模块|审批|"
        r"导出为|转换为|格式转换|魔搭|"
        + _en(r"API", r"handler", r"function", r"module", r"endpoint", r"ONNX", r"GGUF", r"safetensors",
              r"Hugging\s*Face", r"ModelScope", r"convert(?:ing)?\s+(?:it\s+)?to"),
        re.I)),
    "verification": ("核查", re.compile(
        r"检查|检测|查重|核查|审核|有没有|是否存在|自查|"
        + _en(r"check(?:ing)?", r"verify(?:ing)?", r"audit(?:ing)?"),
        re.I)),
    "game_design": ("游戏设计", re.compile(
        r"(?:游戏|" + _en("game") + r")[^。！？!?；;\n]{0,40}(?:系统|模块|背包|数值|关卡|道具|商店|方案|玩法|"
        + _en(r"class", r"inventory", r"level", r"shop", r"system", r"module") + r")|"
        r"(?:系统|模块|背包|数值|关卡|道具|商店|"
        + _en(r"class", r"inventory", r"level", r"shop", r"system", r"module") + r")[^。！？!?；;\n]{0,40}(?:游戏|"
        + _en("game") + r")",
        re.I)),
    "medical_care": ("医疗或移植", re.compile(
        r"彩超|体检|手术|移植|供体|捐献|医院|医保|治疗|患者|病人|"
        + _en(r"transplant", r"donor", r"hospital", r"surgery", r"ultrasound", r"patients?"),
        re.I)),
    "retention_cleanup": ("按保留期清理", re.compile(
        r"\d+\s*(?:天|日|个月|月|周|年)(?:前|以前|之前)|过期|保留期|定期清理|归档|"
        + _en(r"older\s+than", r"retention", r"expired", r"archiv(?:e|ing)"),
        re.I)),
}

_SUMMARY = ("总结、概括或笔记", re.compile(r"总结|概括|读书笔记|摘要|" + _en(r"summar(?:y|ize|ise)"), re.I))

FAMILY_FRAMINGS: Dict[str, Tuple[str, ...]] = {
    "code": ("troubleshooting", "remediation_or_detection", "verification"),
    "dos": ("troubleshooting",),
    "platform": ("retention_cleanup", "troubleshooting", "remediation_or_detection", "verification", "routine_business"),
    "prompt": ("not_model_prompt",),
    "fraud": ("help_seeking", "education_or_debunk", "news_or_compliance", "routine_business", "verification"),
    "illegal": ("help_seeking", "education_or_debunk", "news_or_compliance", "game_design", "medical_care"),
    "copyright": ("help_seeking", "news_or_compliance", "verification"),
    "content": ("help_seeking", "education_or_debunk", "news_or_compliance", "remediation_or_detection", "game_design"),
}

FAMILY_LIVE: Dict[str, LivePattern] = {
    "dos": re.compile(
        r"让(?:服务器|目标|对方|模型|系统)|攻击|拖垮|打满|故意|" + _en(r"DoS", r"DDoS", r"attack", r"take\s+down", r"on\s+purpose"),
        re.I),
    "platform": re.compile(
        r"窃取|外传|偷偷|绕过|绕开|规避|未授权|越权|未经(?:许可|审批|授权)|"
        + _en(r"steal", r"exfiltrate", r"secretly", r"covertly", r"bypass", r"circumvent", r"unauthori[sz]ed",
              r"without\s+(?:permission|approval|authori[sz]ation)"),
        re.I),
    "prompt": re.compile(
        r"你的|你被|" + _en(r"your", r"yours", r"assistant's", r"the\s+AI's"),
        re.I),
    "fraud": re.compile(
        r"冒充|假冒|伪装成|假装是|骗取|诱导|套取|"
        r"让(?:对方|受害人|老人|客户|用户|他|她)[^。！？!?；;\n]{0,12}(?:转账|汇款|充值|垫付|提供验证码|输入密码|共享屏幕|下载远程)|"
        + _en(r"trick(?:s|ed|ing)?", r"deceiv(?:e|es|ed|ing)", r"impersonat(?:e|es|ed|ing|ion)", r"pretend(?:s|ed|ing)?\s+to\s+be",
              r"ask(?:s|ing)?\s+(?:the\s+)?(?:victim|target|elderly)s?\s+(?:to|for)"),
        re.I),
    "illegal": re.compile(
        _PURCHASE + r"|怎么卖|卖给|出售给|推广话术|推销话术|销售话术|"
        r"绕过海关|避开安检|不被查到|"
        + _en(*_PURCHASE_EN, r"how\s+to\s+smuggle", r"avoid\s+customs"),
        re.I),
    "copyright": re.compile(
        r"逐字|全文给我|完整复制|" + _en(r"verbatim", r"word\s+for\s+word"),
        re.I),
    "content": _ContentLive(re.compile(
        r"教我|具体步骤|怎么下手|不被发现|逃避侦查|真实|现实中|配方|" + _PURCHASE_ASK + "|" + _SUPPLY_ASK + "|"
        + _en(r"teach\s+me", r"step[-\s]*by[-\s]*step", r"without\s+getting\s+caught", r"real\s+life", *_PURCHASE_EN),
        re.I)),
}

# 自杀鼓励：预防、求助和拒答说法只留证。带教我、告诉我、给我、哪种（哪个）……最、无痛、成功率，
# 英文 tell/give/show/teach me、walk me through、painless、success rate 时照常告警，
# 与内容安全检测器自杀方法指导（content_safety._SELF_HARM_LIVE）一致。
# how to、How do I 只在后面 8 个词内接 kill myself、end my life、commit suicide、hurt myself、die 等自伤动作时算；
# how to report、how to identify、how to help 是求助，不算（自杀方法指导认任何 how to，这里有意不同）。
# 拒答要紧接规则主题：拒答后同一分句 8 字内（英文 24 字内）是自杀、自残、自伤、轻生、美化、鼓励、劝说，
# 单说“方法”拿不准，不算（“医生无法提供任何治疗方法”）；前面是“如果、要是”等条件说法的不算
# （“如果你无法提供就算了”），拒答后同句 40 字内又转折（但是、不过……）的也不算。
_SELF_EN = r"(?:myself|yourself|oneself|himself|herself|themselves|themself|ourselves)"
_SELF_HARM_ACT_EN = (r"(?:kill|hurt|harm|cut|hang|poison|starve|drown|burn)\s+" + _SELF_EN + "|"
                     r"(?:end|take)\s+(?:my|your|one's|his|her|their|our)\s+(?:own\s+)?li(?:fe|ves)|"
                     r"commit\s+suicide|end\s+it\s+all|overdose|die")
_HOW_SELF_HARM_EN = (r"how\s+(?:do\s+I|to)\s+(?:self[-\s]*harm|(?!(?:report|identify|spot|recogni[sz]e|help)" + _E + r")"
                     r"(?:[^\s.!?。！？;；]{1,40}\s+){0,7}?(?:" + _SELF_HARM_ACT_EN + r"))")
_SELF_HARM_LIVE = re.compile(
    r"教我|告诉我|给我|哪[种个][^，,。！？!?；;\n]{0,8}?最|无痛|成功率|"
    + _en(r"(?:tell|give|show|teach)\s+me", r"walk\s+me\s+through", r"painless(?:ly)?", r"success\s+rates?",
          _HOW_SELF_HARM_EN),
    re.I)
_REFUSAL_TURN = r"(?![^。！？!?；;\n]{0,40}?(?:但|不过|然而|可是|" + _en(r"but", r"however") + r"))"
_REFUSAL_TOPIC = r"(?=[^，,。！？!?；;\n]{0,8}?(?:自杀|自残|自伤|轻生|美化|鼓励|劝说))"
_REFUSAL_TOPIC_EN = r"(?=[^,，。.;；!?！？\n]{0,24}?(?:suicide|self[-\s]*harm|glorif|encourag))"
_CONDITIONAL = re.compile(r"(?:如果|假如|要是|若是|倘若|万一|若|" + _en(r"if", r"unless") + r")[^，,。！？!?；;\n]{0,6}$", re.I)
_SELF_HARM_PREVENTION = ("预防或求助", re.compile(
    r"预防|干预|劝阻|打消|求助|心理援助|热线|"
    + _en(r"prevent(?:ion|ing)?", r"hotline", r"talk\s+(?:someone|a\s+friend)\s+out\s+of"),
    re.I))


class _Refusal:
    """Refusal wording right before the rule topic, not inside a condition ("如果你无法提供就算了")."""

    pattern = re.compile(
        r"(?:我不能提供|无法提供|不会提供|不会给出)" + _REFUSAL_TOPIC + _REFUSAL_TURN + "|"
        + _en(r"cannot\s+provide", r"can\s+not\s+provide", r"can[\u2019']t\s+help") + _REFUSAL_TOPIC_EN + _REFUSAL_TURN,
        re.I)

    def finditer(self, text: str):
        for match in self.pattern.finditer(text):
            if not _CONDITIONAL.search(text, max(0, match.start() - 12), match.start()):
                yield match


_CATEGORY_EXTRA = {
    "copyright_text_reproduction": (_SUMMARY,),
    "content_self_harm_encouragement": (_SELF_HARM_PREVENTION, ("预防或求助", _Refusal())),
}
_CATEGORY_LIVE = {"content_self_harm_encouragement": (_SELF_HARM_LIVE,)}
_GAMBLING_LIVE = re.compile(r"真钱|充值|下注|提现|返水|赔率|" + _en(r"real\s+money", r"cash\s+out", r"deposit"), re.I)
# 实施说法前 8 字内的否定词（中间不隔句末标点）。能不能、要不要、会不会、不得不、不能不里的字不算，
# 英文 not only、not just 不算。“别”默认算否定（别听信、别向、别把、千万别），只排除组词：
# 前一字能和“别”组词（分、特、个、区、类、级、差、识、辨、鉴、告、性、国、派、职、判、甄、离、送、组、道、辞、诀、永、临），
# 或后一字是人、的、家、处、名、称、样、墅、致、针、扭时不算。拿不准就照常告警：“女性别信、出国别信、
# 知道别信”和“性别给出、国别给出、识别转”一样按组词处理，不算否定。
_BIE_HEADS = "分特个区类级差识辨鉴告性国派职判甄离送组道辞诀永临"
_BIE = r"(?<![" + _BIE_HEADS + r"])别(?![人的家处名称样墅致针扭])"
_NEGATION = re.compile(r"(?<!能)不能(?!不)|(?<!要)不要|(?<!会)不会|不得(?!不)|禁止|" + _BIE + "|"
                       + _en(r"never", r"not(?!\s+(?:only|just)" + _E + r")", r"don't"), re.I)
_NEGATION_WINDOW = 12

# 游戏设计只豁免武器、弹药、赌博类的游戏开发需求（内容安全检测器的赌博类按 content_gambling 传入）；
# 所在句要剧情、文字、文案、配方、方法、描述或制作类教程，或英文 story、storyline、narrative、the plot、
# describe how to、describe the steps/process 时是借游戏要内容，不算。下面这些是开发说法，不算借游戏要内容：
# “方法”紧挨英文标识符（要含小写字母或带“()”：craft 方法、Craft() 方法），或是“Weapon 类的……方法”，以及“计算方法”；
# 前面紧挨制作、制造、组装、合成、改装、配制、自制的“方法”一律不算开发说法，写一个、编写、函数等不再让“方法”豁免；
# “描述”后接字段、属性、配置、符，或是“名称、描述、价格”这类字段列举；“文字”只认“写……文字、一段文字”，
# 文字冒险、文字游戏不算；“制作……教程”中间夹系统、模块、玩法、设计的不算；弹药交易类里文案的对象是商店、价格、道具时不算。
_GAME_DESIGN_CATEGORIES = frozenset({"content_weapon_construction", "illegal_weapon_trade", "content_gambling"})
_GAME_NOT_DESIGN = re.compile(
    r"剧情|(?:写[^，,。！？!?；;\n]{0,10}?|一段)文字(?!冒险|游戏)|文案|配方|(?<!计算)方法(?!\s*\(\s*\))|"
    r"(?<![、/|])描述(?![、/|]|字段|属性|配置|符)|"
    r"(?:制作|制造|组装|合成|改装|自制)(?:(?!系统|模块|玩法|设计)[^，,。！？!?；;\n]){0,8}?教程|"
    + _en(r"story", r"storyline", r"narrative", r"the\s+plot",
          r"describ(?:e|es|ed|ing)\s+(?:how\s+to|the\s+(?:steps?|process(?:es)?|methods?|procedures?))"),
    re.I)
_IDENT_BEFORE = re.compile(
    r"(?<![A-Za-z0-9_])(?:[A-Za-z_][A-Za-z0-9_]{0,63}\s{0,2}\(\s{0,2}\)"
    r"|(?=[A-Za-z0-9_]{0,63}[a-z])[A-Za-z_][A-Za-z0-9_]{0,63}(?![A-Za-z0-9_]))\s{0,2}$")
_CLASS_METHOD_BEFORE = re.compile(
    r"(?<![A-Za-z0-9_])(?=[A-Za-z0-9_]{0,63}[a-z])[A-Za-z_][A-Za-z0-9_]{0,63}\s{0,2}类的[^，,。！？!?；;\n]{0,20}$")
_MAKE_BEFORE = re.compile(r"(?:制作|制造|组装|合成|改装|配制|自制)的?\s{0,2}$")
_SHOP_COPY = re.compile(r"商店|价格|道具")
# 游戏设计适用的类别里，在游戏里买游戏物品是玩法：购买说法同一分句前 6 字内或紧接其后是商店、商城、游戏内、游戏里，
# 或买的是金币、钻石、点券、游戏币、礼包时（装备、道具、皮肤是通用词，不算），句里只有这类购买说法仍可按游戏设计留证；
# “制作爆炸物的材料在哪里能买”不算，装备、道具是通用词也不算（“爆炸物装备在哪里能买”照常告警）。
_PURCHASE_ANY = re.compile(_PURCHASE + "|" + _SUPPLY_ASK + "|" + _en(*_PURCHASE_EN), re.I)
_GAME_PLACE = re.compile(r"商店|商城|游戏内|游戏里")
_GAME_GOODS = re.compile(r"金币|钻石|点券|游戏币|礼包")

_FAMILY_PREFIXES = (
    ("code_", "code"), ("dos_", "dos"), ("plugin_", "platform"), ("supply_", "platform"), ("rag_", "platform"),
    ("prompt_", "prompt"), ("fraud_", "fraud"), ("illegal_", "illegal"), ("copyright_", "copyright"),
    ("content_", "content"),
)


def family_of(category: str) -> Optional[str]:
    if category in {"content_pornography", "content_gambling", "content_fraud", "content_drugs"}:
        return "content"
    for prefix, family in _FAMILY_PREFIXES:
        if category.startswith(prefix):
            return family
    return None


def live_patterns(family: Optional[str]) -> Tuple[LivePattern, ...]:
    pattern = FAMILY_LIVE.get(family or "")
    return (pattern,) if pattern is not None else ()


def _inside_keyword(match_start: int, match_end: int, keyword_spans: Iterable[Span]) -> bool:
    return any(a <= match_start and match_end <= b for a, b in keyword_spans)


def _code_method(text: str, start: int) -> bool:
    """“方法” at ``start`` names code: craft 方法, Craft() 方法, Weapon 类的升级方法 (not 制作方法, 合成方法)."""
    if _MAKE_BEFORE.search(text, max(0, start - 5), start):
        return False
    return bool(_IDENT_BEFORE.search(text, max(0, start - 76), start)
                or _CLASS_METHOD_BEFORE.search(text, max(0, start - 90), start))


def _game_narrative_check(text: str, category: str):
    """Predicate: is ``text`` offset inside a sentence that asks for plot, copy, methods or descriptions."""
    lefts, rights, left = [], [], 0
    for end in [m.start() for m in _SENTENCE_END.finditer(text)] + [len(text)]:
        shop_copy = None
        for match in _GAME_NOT_DESIGN.finditer(text, left, end):
            if match.group() == "方法" and _code_method(text, match.start()):
                continue
            if match.group() == "文案" and category == "illegal_weapon_trade":
                if shop_copy is None:
                    shop_copy = bool(_SHOP_COPY.search(text, left, end))
                if shop_copy:
                    continue
            lefts.append(left)
            rights.append(end)
            break
        left = end + 1

    def covers(offset: int) -> bool:
        i = bisect_right(lefts, offset) - 1
        return i >= 0 and offset < rights[i]

    return covers


def _negated(text: str, start: int) -> bool:
    """A negation word ends at most 8 characters before ``start`` in the same sentence."""
    # The search reaches 3 characters past ``start`` so that 别、不能、not can see the characters after them.
    for negation in _NEGATION.finditer(text, max(0, start - _NEGATION_WINDOW), min(len(text), start + 3)):
        if negation.end() > start:
            break
        if start - negation.end() <= 8 and not _SENTENCE_END.search(text, negation.end(), start):
            return True
    return False


def _game_purchase(text: str, match: "re.Match[str]") -> bool:
    """A purchase inside the game: 金币在商店里怎么买, 玩家在商店怎么买材料, 怎么买钻石 (not 爆炸物的材料/皮肤在哪里能买)."""
    if not _PURCHASE_ANY.fullmatch(match.group()):
        return False
    before = _CLAUSE_END.split(text[max(0, match.start() - 10):match.start()])[-1]
    after = _CLAUSE_END.split(text[match.end():match.end() + 6])[0]
    return bool(_GAME_PLACE.search(before[-6:]) or _GAME_PLACE.search(after)
                or _GAME_GOODS.search(before) or _GAME_GOODS.search(after))


def has_live_demand(text: str, patterns: Sequence[LivePattern],
                    ignore: Optional[Callable[[str, "re.Match[str]"], bool]] = None) -> bool:
    """A live demand not negated by 不会/不要/never just before it (inside the components too)."""
    for pattern in patterns:
        for match in pattern.finditer(text):
            if ignore is not None and ignore(text, match):
                continue
            if not _negated(text, match.start()):
                return True
    return False


def framing_reason(category: str, text: str, spans: Sequence[Span], base: int,
                   extra_live: Sequence[LivePattern] = ()) -> Optional[Tuple[str, str]]:
    """(reason_code, chinese_label) when ``text`` frames the candidate benignly.

    ``text`` is the candidate's sentence(s) starting at absolute offset ``base``;
    ``spans`` are the absolute spans of the matched keyword components; framing
    wording wholly inside one of them does not count.
    """
    family = family_of(category)
    if family is None or has_live_payload(text):
        return None
    live = live_patterns(family) + tuple(extra_live) + _CATEGORY_LIVE.get(category, ())
    game_only = False
    if has_live_demand(text, live):
        # 只有在游戏里买游戏物品这类购买说法时，仍可按游戏设计留证。
        if category not in _GAME_DESIGN_CATEGORIES or has_live_demand(text, live, ignore=_game_purchase):
            return None
        game_only = True
    candidates = [(code,) + FRAMINGS[code] for code in FAMILY_FRAMINGS.get(family, ())
                  if (code != "game_design" or category in _GAME_DESIGN_CATEGORIES)
                  and (not game_only or code == "game_design")]
    if not game_only:
        candidates += [(category,) + extra for extra in _CATEGORY_EXTRA.get(category, ())]
    for code, label, pattern in candidates:
        narrative = _game_narrative_check(text, category) if code == "game_design" else None
        for match in pattern.finditer(text):
            if narrative is not None and narrative(match.start()):
                continue
            if not _inside_keyword(base + match.start(), base + match.end(), spans):
                return (code if code != category else _EXTRA_CODES.get(label, "category_framing"), label)
    return None


_EXTRA_CODES = {"总结、概括或笔记": "summary_request", "预防或求助": "self_harm_prevention"}


def gambling_live_pattern() -> "re.Pattern[str]":
    return _GAMBLING_LIVE
