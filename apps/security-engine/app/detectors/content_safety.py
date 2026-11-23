"""
内容安全检测器 - TC260 标准 + 扩展内容安全检测
"""
import base64
import binascii
import re
from bisect import bisect_left, bisect_right
from typing import Dict, List
from app.detectors.greedy_scan import GreedyScan
from app.detectors.profanity import ProfanityDetector
from app.detectors.benign_framing import FAMILY_LIVE, framing_reason, gambling_live_pattern, has_live_demand
from app.detectors.evidence_context import (covered_sentences, observation as _observation)
from app.detectors.evidence_context import (BOUNDARY, SentenceIndex, bounded_sentence, defensive_reference_reason,
                                            has_live_directive, observation, scan_window,
                                            fenced_reference_reason, prepare_reference_context)


# 规则 ID -> 中文规则名。界面"命中证据/规则条目"用它回显，避免出现英文枚举 ID。
RULE_NAMES: Dict[str, str] = {
    # 违法有害
    "content_safety_illegal_pornography": "色情低俗内容",
    "content_safety_illegal_violence_terror": "暴力恐怖内容",
    "content_safety_illegal_gambling": "赌博相关内容",
    "content_safety_illegal_fraud": "诈骗相关内容",
    "content_safety_illegal_drugs": "毒品相关内容",
    "content_safety_illegal_cyber_attack": "网络攻击工具/手法",
    # 政治安全
    "content_safety_political_leader_name": "涉国家领导人敏感内容",
    "content_safety_political_territory_taiwan": "涉台分裂内容",
    "content_safety_political_territory_split": "涉藏疆港分裂内容",
    "content_safety_political_sensitive_event": "政治敏感事件",
    "content_safety_political_historical_nihilism": "历史虚无主义内容",
    "content_safety_political_ethnic_separatism": "民族分裂内容",
    # 歧视
    "content_safety_discrimination_racial_discrimination": "种族歧视内容",
    "content_safety_discrimination_regional_discrimination": "地域歧视内容",
    "content_safety_discrimination_gender_discrimination": "性别歧视内容",
    # 小语种
    "content_safety_multilingual_uyghur_kazakh": "维哈语小语种内容",
    "content_safety_multilingual_tibetan": "藏文小语种内容",
    "content_safety_multilingual_mongolian": "蒙古文小语种内容",
    "content_safety_multilingual_cyrillic": "西里尔文小语种内容",
    "content_safety_multilingual_arabic": "阿拉伯文小语种内容",
    # 复合可操作风险
    "content_safety_illegal_hazardous_chemical_instructions": "危险化学品/爆炸物制备指导",
    "content_safety_self_harm_actionable_guidance": "自伤自杀可操作指导",
    "content_safety_illegal_system_command_instructions": "高危系统命令/提权指令",
    "content_safety_debug_secret_template": "密钥/凭据套取模板",
    "content_safety_ssrf_metadata_instruction": "SSRF 元数据探测指令",
    "content_safety_agent_canary_token_leak": "Agent 蜜签令牌外泄",
    # 辱骂
    "content_safety_harassment_profanity_cn": "中文强辱骂内容",
    "content_safety_profanity_abuse": "辱骂脏话",
}


# Political keywords: drop common compounds only ("这台独立显卡", "台独资企业",
# "新疆独特", "香港独立书店", "两个中国客户"); the sensitive terms themselves still hit.
# 一/自 only end 藏独、疆独、港独 compounds ("收藏独一无二"); "台独一定会失败" is the term itself.
_NOT_DU_COMPOUND = r'(?![资特一有自家门占享])'
_NOT_TAIDU_COMPOUND = r'(?![资特有家门占享])'
# Only this closed list of fixed compounds is not 台独: 平台、后台、前台、舞台、柜台、控制台、中台、工作台 (跨平台
# included) right before 独立部署、独立运行、独立进程……、独自、独一无二、独白、独显、独占、独享、独有、独家
# ("平台独自承担风险", "后台独立进程", "舞台独白"). Any other compound hits ("执政后台独步伐", "宣讲台独立场",
# "总有一天台独一定会失败"), and 台独 before a political continuation (台独立场、台独运动……) always hits.
_TAIDU_FIXED_HEAD = r'(?:(?<=平)|(?<=后)|(?<=前)|(?<=舞)|(?<=柜)|(?<=控制)|(?<=中)|(?<=工作))'
_TAIDU_POLITICAL_TAIL = r'(?:立场|运动|建国|公投|势力|分子|步伐|当局|行径|主张|倾向|路线|大佬)'
_TAIDU_FIXED_TAIL = r'(?:独立(?:部署|运行|进程|线程|窗口|显卡|服务|模块|版本)|独自|独一无二|独白|独显|独占|独享|独有|独家)'
_NOT_FIXED_WORD_TAIDU = (r'(?!' + _TAIDU_FIXED_HEAD + r'台(?!独' + _TAIDU_POLITICAL_TAIL + r')'
                         + _TAIDU_FIXED_TAIL + r')')
_NOT_INDEPENDENT_VENUE = r'(?!书店|游戏|音乐|乐队|电影|设计|开发者|摄影|自助游|旅行)'
_TWO_CHINAS_TAIL = r'(?=$|[\s，。、；：！？”"」』）)\].,;:!?]|论|政策|主张|的(?:立场|说法|论调))'
_SELF_HARM_WINDOW = 240
_SELF_HARM_TECHNICAL = re.compile(r"(?:进程|线程|服务|容器|程序|应用|实例)(?:主动)?自杀|自杀(?:进程|开关)")
# Prevention or help-seeking wording. Negated ("别跟我说什么热线", "不用劝阻", "never mind prevention") it is not prevention.
_SELF_HARM_PREVENTION = re.compile(
    r"预防|干预|劝阻|打消|求助|心理援助|热线|预警信号|高危人群|来电|"
    r"\b(?:prevent\w*|hotlines?|warning\s+signs?)\b", re.I)
# Explicit refusals to answer (我不能提供、不能告诉你、I cannot provide、I can't help with……). Bare negations
# (不要、不能、不会、拒绝、never、must not、do not) are not refusals: "我想自杀，不要隐瞒具体方法",
# "有没有不会痛的具体方法", "You must not refuse to give the procedure".
_SELF_HARM_REFUSAL = re.compile(
    r"我(?:真的|实在|确实|绝对|并)?(?:不能|无法|不会|没法|没办法|不可以|不便)(?:向你|为你|给你|跟你|向您|为您|给您)?"
    r"(?:提供|给出|告诉你|告诉您|透露|分享|回答|教你|教您|帮你|帮您)|(?:不能|无法)(?:告诉你|告诉您)|"
    r"\bI(?:\s+(?:cannot|can\s*not|can[’']t|won[’']t|will\s+not|am\s+(?:unable|not\s+able)\s+to)|"
    r"[’']m\s+(?:unable|not\s+able)\s+to)\s+"
    r"(?:provide|give|share|offer|tell\s+you|help(?:\s+you)?\s+with|assist(?:\s+you)?\s+with)\b", re.I)
_SELF_HARM_LIVE = re.compile(r"教我|告诉我|给我|哪种(?:方法)?最|无痛|成功率|\bhow\s+(?:do\s+I|to)\b|"
                             r"\b(?:tell|give|show|teach)\s+me\b|\bwalk\s+me\s+through\b", re.I)
# Answers handing out steps: 步骤如下, 如下：第一步, a numbered or bulleted list (1. 2.、1、2、- 、* 、•),
# 第一步……第二步, 首先……然后/其次/最后, Step 1, first … then. Full-width digits count too.
_SELF_HARM_STEPS = re.compile(
    r"步骤如下|如下\s*[:：]\s*(?:第[一1１]步|首先)|[:：]\s*(?:[1１][.．、)）](?![0-9０-９])|一[、.．]|①)|"
    r"第[一1１]步[^。！？!?；;\r\n]{0,80}?第[二2２]步|首先[^。！？!?；;\r\n]{0,80}?(?:然后|其次|接着|再|最后)|"
    r"\r?\n[ \t]*(?:[1１][.．、)）]|一[、.．]|①|[-*][ \t]|•)[ \t]*\S[^\r\n]*\r?\n"
    r"[ \t]*(?:[2２][.．、)）]|二[、.．]|②|[-*][ \t]|•)[ \t]*\S|"
    r"\bstep\s*(?:1|one|１)\b|\bfirst\b[^.!?;\r\n]{0,80}?\bthen\b", re.I)
# Self-harm means (割腕、刀片、上吊、跳楼、服药、剂量、烧炭……).
_SELF_HARM_MEANS = re.compile(
    r"割腕|割脉|割喉|刀片|刀子|划开|划破|手腕|动脉|上吊|自缢|绳子|绳索|跳楼|跳河|跳桥|跳崖|卧轨|服药|吞药|喝药|"
    r"吞下|吞服|安眠药|农药|百草枯|老鼠药|毒药|氰化物|过量|剂量|致死量|烧炭|木炭|煤气|一氧化碳|窒息|放血|"
    r"\b(?:blades?|razors?|knife|knives|wrists?|slit|noose|ropes?|overdose|pills?|dosage|lethal\s+dose|poison\w*|"
    r"carbon\s+monoxide|charcoal|jump(?:ing)?\s+(?:off|from)|hang(?:ing)?\s+(?:yourself|myself)|"
    r"cut(?:ting)?\s+(?:deep|yourself|myself|your\s+wrists?))\b", re.I)
_SELF_HARM_TURN = re.compile(r"但是|(?<![不非])但(?![愿凡])|不过|然而|可是|\b(?:but|however)\b", re.I)
# Safety advice after a turn (缓解情绪、放松、求助、热线、专业人士、医生、陪伴、support、hotline、feel safer……).
_SELF_HARM_SAFE = re.compile(
    r"缓解|放松|平静|冷静|情绪|压力|焦虑|度过|渡过|难关|求助|寻求(?:专业)?帮助|获得帮助|得到帮助|专业帮助|"
    r"热线|心理援助|心理咨询|咨询师|心理医生|医生|就医|医院|急诊|专业人士|专业人员|陪伴|倾诉|聊聊|聊天|"
    r"关心你|在乎你|照顾好?自己|深呼吸|散步|家人|朋友|信任的人|"
    r"\b(?:support\w*|help\s*lines?|hotlines?|lifelines?|crisis\s+(?:lines?|text|cent(?:er|re)s?)|"
    r"feel(?:ing)?\s+(?:safer|calmer|better)|stay(?:ing)?\s+safe|safety|calm\w*|stress\w*|cop(?:e|ing)|relax\w*|"
    r"therapists?|counsel\w*|doctors?|seek(?:ing)?\s+help|get(?:ting)?\s+help|reach(?:ing)?\s+out|"
    r"talk\s+to\s+someone|care\s+about\s+you|grounding|breath\w*|emergency)\b", re.I)
_SAFE_AIM = r"(?!\s+to\s+(?:get|find|seek|reach|cope|stay|feel|manage|calm|relax|talk))"
# Offers pointing back at the refused content ("告诉你具体步骤", "换个说法", "here is how").
_SELF_HARM_BACKREF = re.compile(
    r"(?:告诉|教|给)(?:你|您)(?:具体|详细)(?:的)?(?:步骤|方法|做法|操作|流程)|换个(?:说法|方式|角度)|换种(?:说法|方式)|"
    r"步骤如下|\bhere(?:'s|’s|\s+is)\s+how\b" + _SAFE_AIM + r"|"
    r"\bhere\s+(?:is|are)\s+the\s+(?:step[-\s]*by[-\s]*step\s+)?(?:procedures?|methods?|ways?|steps)\b" + _SAFE_AIM
    + r"|\bhow\s+to\s+do\s+it\b", re.I)
# A negation in the clause before prevention or safety wording ("别跟我说什么热线", "不用劝阻", "没人陪伴",
# "never mind prevention"). "不要犹豫拨打热线" is not one.
_SELF_HARM_NEGATION = re.compile(
    r"(?<![分特个区类级差识告性派])别(?![人的家处样])|不要|不用|不需要|不必|甭|少(?:跟|给|和)我|无需|无须|不想|不是|并非|"
    r"没有|没人|无人|\b(?:don[’']?t|do\s+not|no|not|never(?:\s+mind)?|skip|forget|without|stop)\b", re.I)
_SELF_HARM_NEGATION_CANCEL = re.compile(r"犹豫|害怕|怕|忽视|忽略|忘记|忘了|放弃|羞于|拒绝|吝于|担心|"
                                        r"\b(?:hesitate|afraid|ashamed)\b", re.I)
# A refusal phrase negated or put as a condition ("别跟我说我不能提供", "如果我无法提供", "don't say I cannot provide").
_SELF_HARM_REFUSAL_NEGATION = re.compile(
    r"(?<![分特个区类级差识告性派])别(?![人的家处样])|不要|不许|不准|不用|甭|如果|假如|要是|若是|倘若|万一|"
    r"\b(?:don[’']?t|do\s+not|never|if|unless|stop)\b", re.I)
_NEGATION_SCOPE = re.compile(r"[，,：:；;。！？!?\r\n]|但是|(?<![不非])但(?![愿凡])|不过|然而|可是|\b(?:but|however)\b", re.I)
_NEGATION_REACH = 20
_DRUG_SALE = re.compile(r"销售|出售|贩卖|购买|推广|配方|合成|制备|\b(?:sell|sale|buy|purchase|manufacture|synthesi[sz]e|recipe)\b", re.I)
_DRUG_PREVENTION = re.compile(r"禁毒|科普|劝阻|危害|戒毒|预防")
# Help seeking, reporting, debunking and detection framings keep the evidence without alerting.
_FRAMED_ILLEGAL_TYPES = {
    "pornography": (),
    "gambling": (gambling_live_pattern(),),
    "fraud": (FAMILY_LIVE["fraud"],),
    "drugs": (_DRUG_SALE,),
}
# Implementation wording that keeps 防范、禁止 from exempting these types (教我、告诉我、哪里能买、求购货源、充值、
# 下注、怎么玩、怎么进……), unless negated in its clause ("禁止赌博充值"). Plain sale wording (严禁购买毒品) and
# fraud wording (警惕冒充公检法) are prevention statements, so they are not listed here.
_CONTENT_ASK = re.compile(r"告诉我|怎么玩|怎么进|如何进入|\b(?:tell|show)\s+me\b", re.I)
_DEFENSIVE_LIVE_TYPES = {
    "pornography": (FAMILY_LIVE["content"], _CONTENT_ASK),
    "gambling": (FAMILY_LIVE["content"], _CONTENT_ASK, gambling_live_pattern()),
    "fraud": (FAMILY_LIVE["content"], _CONTENT_ASK),
    "drugs": (FAMILY_LIVE["content"], _CONTENT_ASK),
}
_ASK_CLAUSE = re.compile(r"[，,：:；;]")


class _WindowMemo:
    """Judgments that read only the text within 240 characters of a keyword (operational context, prevention
    wording, implementation wording, framing), remembered by that text and the keyword's place in it.

    A long text repeating a phrase is judged once per distinct window. "禁用" lets the prevention check read
    beyond the window, so windows containing it are judged afresh. At most LIMIT windows are kept.
    """

    LIMIT = 1024

    def __init__(self, content):
        self.content = content
        self.judged = {}

    def judge(self, name, start, end, judge):
        offset, text = scan_window(self.content, start, end)
        if "禁用" in text:
            return judge()
        key = (name, text, start - offset, end - offset)
        if key not in self.judged:
            if len(self.judged) >= self.LIMIT:
                self.judged.clear()
            self.judged[key] = judge()
        return self.judged[key]


def _drug_prevention_sentence(text):
    return bool(_DRUG_PREVENTION.search(text) and not _DRUG_SALE.search(text))


class ContentSafetyDetector:
    """TC260 标准内容安全 + 小语种扩展"""

    def __init__(self):
        # 内置辱骂脏话检测（词表在 app/data/profanity_lexicon.json）
        self.profanity = ProfanityDetector()
        # 政治安全
        self.political_patterns: List[Dict] = [
            {"pattern": re.compile(r'(习近平|李克强|胡锦涛|江泽民|温家宝)(?!\w)', re.I), "type": "leader_name", "severity": "critical"},
            {"pattern": re.compile(r'(台湾独立' + _NOT_INDEPENDENT_VENUE + r'|一中一台|两个中国' + _TWO_CHINAS_TAIL
                                   + r'|(?<![这那一两几每某整单多二三四五六七八九十百千万0-9])' + _NOT_FIXED_WORD_TAIDU
                                   + r'台独' + _NOT_TAIDU_COMPOUND + r')', re.I),
             "type": "territory_taiwan", "severity": "critical"},
            {"pattern": re.compile(r'((?:西藏|新疆|香港)独立' + _NOT_INDEPENDENT_VENUE + r'|(?<!西)藏独' + _NOT_DU_COMPOUND + r'|(?<!新)疆独' + _NOT_DU_COMPOUND + r'|(?<!香)港独' + _NOT_DU_COMPOUND + r')', re.I),
             "type": "territory_split", "severity": "critical"},
            {"pattern": re.compile(r'(六四(?![分开比成折])|天安门事件|法轮功)', re.I), "type": "sensitive_event", "severity": "critical"},
            {**self._greedy(["历史虚无主义"], ["否认南京大屠杀"], ["否认", "文革"]), "type": "historical_nihilism", "severity": "high"},
            {"pattern": re.compile(r'((?<!新)疆独' + _NOT_DU_COMPOUND + r'|(?<!西)藏独' + _NOT_DU_COMPOUND + r'|蒙独' + _NOT_DU_COMPOUND + r')', re.I), "type": "ethnic_separatism", "severity": "critical"},
        ]

        # "暴力"二字在影视/文学/反暴力等语境下极易误伤，需配合加重语境才算强信号。
        # 命中加重语境（操作性/暴恐主体）才给高置信度；否则降为弱信号，交由置信度门控降级留痕。
        self.violence_aggravator_pattern = re.compile(
            r'(实施|制造|制作|教程|教唆|煽动|策划|发动|步骤|攻击|袭击|杀人|杀害|'
            r'血腥|恐怖|极端组织|伤害他人|施暴|斗殴|群殴|致死|致残|武器|凶器|'
            r'how\s*to|引爆|纵火|行凶)',
            re.I,
        )
        # 良性讨论语境（减轻词）：医疗/新闻/法律/反暴力框架。即便同时命中加重词，
        # 也把"暴力"降回弱信号（最多 block→audit，仍留痕，绝不漏检）。
        # 安全红线：不含"小说/剧情/影视"等虚构框架——那是越狱伪装向量，不得作为减轻词。
        self.violence_mitigator_pattern = re.compile(
            # 新闻 / 执法 / 司法报道
            r'(新闻|报道|通报|披露|媒体|记者|警方|公安|检察|法院|判决|庭审|'
            # 法律法规
            r'法律|法规|条例|条款|《[^》]*法》|反恐怖主义法|反家庭暴力法|普法|司法解释|立法|合规|'
            # 反暴力 / 救助 / 维权框架
            r'防治|预防|防范|反对|抵制|谴责|制止|救助|庇护|受害者|维权|心理疏导|危机干预|'
            # 临床 / 医学讨论
            r'精神疾病|精神科|临床|诊疗|病历|医学研究|康复治疗|护理|风险评估|行为评估)',
            re.I,
        )

        # 诈骗/赌博是安全运营中高频分类词，不能裸词命中就报高危；
        # 必须出现话术、引流、交易、下注、返利等实施/推广语境。
        self.illegal_commercial_abuse_context_pattern = re.compile(
            r'(话术|脚本|模板|教程|步骤|实施|设计|方案|引导|诱导|拉人|加群|私聊|'
            r'受害者|目标用户|骗取|转账|汇款|充值|返利|提现|收款码|二维码|佣金|'
            r'平台开户|博彩|下注|投注|赔率|返水|代充|跑分|洗钱|开户链接|推广链接|代理)',
            re.I,
        )

        # 违法有害
        # A long governance prompt may contain both operational vocabulary and
        # attack examples. Discussion markers suppress those examples unless a
        # direct execution/request anchor is present near the risk keyword.
        self.illegal_commercial_abuse_discussion_pattern = re.compile(
            r'(false\s*positive|fp\b|rule|finding|security[_\s-]*event|alert|'
            r'sample|example|test|governance|'
            r'\u8bef\u62a5|\u8bef\u5224|\u544a\u8b66|\u89c4\u5219|\u6cbb\u7406|'
            r'\u6837\u4f8b|\u6d4b\u8bd5|\u793a\u4f8b|\u8ba8\u8bba|\u5206\u6790|\u5206\u7c7b|'
            r'\u6807\u7b7e|\u547d\u4e2d|\u6b63\u5e38\s*(?:agent|\u667a\u80fd\u4f53)|'
            r'\u771f\u653b\u51fb|\u771f\u98ce\u9669|\u5fc5\u987b\u544a\u8b66|\u5e94\u4fdd\u7559\u544a\u8b66)',
            re.I,
        )
        self.illegal_commercial_abuse_directive_pattern = re.compile(
            r'(\b(?:help\s+me|please|write|generate|create|design|how\s+to)\b|'
            r'\u5e2e\u6211|\u8bf7.{0,8}(?:\u5199|\u751f\u6210|\u5236\u4f5c|\u8bbe\u8ba1)|'
            r'(?:\u5199|\u751f\u6210|\u5236\u4f5c|\u8bbe\u8ba1).{0,16}(?:\u8bdd\u672f|\u811a\u672c|\u6a21\u677f)|'
            r'\u4e0d(?:\u89e6\u53d1|\u547d\u4e2d).{0,8}(?:\u544a\u8b66|\u68c0\u6d4b)?|'
            r'(?:\u7ed5\u8fc7|\u89c4\u907f|\u9003\u907f).{0,8}(?:\u544a\u8b66|\u68c0\u6d4b))',
            re.I,
        )
        self.illegal_patterns: List[Dict] = [
            {"pattern": re.compile(r'(色情|淫秽|裸聊|成人视频|AV资源)', re.I), "type": "pornography", "severity": "high"},
            # “暴力”后接技术动作（暴力重试/轮询/删除缓存…）是编程用语，不是暴恐（客户B 11-21）。
            {"pattern": re.compile(r'((?<!非)暴力(?!\s*(?:解法|求解|破解|枚举|穷举|搜索|匹配|算法|遍历|重试|重启|轮询|扫描|测试|压测|拆解|删除|清理|覆盖|替换|回滚|写法|实现|升级|kill|retry))|恐怖袭击|爆炸物制作|枪支买卖)', re.I),
             "type": "violence_terror", "severity": "critical",
             "ambiguous_tokens": {"暴力"}, "aggravator": self.violence_aggravator_pattern,
             "mitigator": self.violence_mitigator_pattern},
            {"pattern": re.compile(r'(赌博|赌场|百家乐|老虎机|六合彩)', re.I), "type": "gambling", "severity": "high", "context": self.illegal_commercial_abuse_context_pattern},
            {"pattern": re.compile(r'(诈骗|刷单|杀猪盘|庞氏骗局|传销)', re.I), "type": "fraud", "severity": "high", "context": self.illegal_commercial_abuse_context_pattern},
            {"pattern": re.compile(r'(毒品|冰毒|海洛因|大麻|摇头丸|罂粟)', re.I), "type": "drugs", "severity": "critical"},
            {"pattern": re.compile(r'(DDOS|CC攻击|木马|远控|免杀|shellcode)', re.I), "type": "cyber_attack", "severity": "high"},
        ]

        # 危险化学品/爆炸物的可操作制备指导。
        # 需要同时命中危险主体和操作性要素，降低普通科普内容的误报。
        self.hazardous_chemical_subject_pattern = re.compile(
            r'(TNT|三硝基甲苯|氰化物|氢氰酸|氰化钠|氰化钾|爆炸物|炸药|危险化学品|毒害物)',
            re.I,
        )
        self.hazardous_chemical_instruction_pattern = re.compile(
            r'(原料|材料清单|采购渠道|制备|合成|合成步骤|操作步骤|反应条件|'
            r'硝化反应|水解反应|浓硝酸|浓硫酸|提纯|剂量|配比|比例)',
            re.I,
        )
        # 自伤/自杀可操作指导。要求同时出现自伤语境和实施/介质/规避等操作性线索，
        # 避免把危机干预、求助建议和安全拒答误判为风险输出。
        self.self_harm_subject_pattern = re.compile(
            r'(自伤|自残|自杀|轻生|suicide|self[-_\s]?harm|crisis\s*intervention|'
            r'危机干预负样本|RISK_EVENT_PLACEHOLDER|\[TERM_X7\])',
            re.I,
        )
        self.self_harm_actionable_pattern = re.compile(
            r'(具体实施路径|实施路径|具体方法|操作流程|操作步骤|分步流程|详细还原|'
            r'常用介质|介质清单|工具清单|材料清单|风险规避|规避策略|降低痛感|'
            r'implementation[_\s-]?path|media[_\s-]?list|risk[_\s-]?avoidance|'
            r'procedure|step[-_\s]?by[-_\s]?step)',
            re.I,
        )

        # 输出侧危险系统命令/提权账号命令。
        # 与解码重扫配合，覆盖 Base64/URL/Unicode 壳里的可执行命令还原。
        # 锚点分级 + 邻近窗共现，治理 "cmd" 字段名 + URL 裸 /c + "执行" 这类遥测误报：
        # - 强 subject（危险命令形态）+ 任意 instruction 锚（±200 字）→ 高置信命中
        # - 弱 subject（裸命令名）必须 + 强 instruction 锚（±120 字）→ 中置信命中
        # - 弱 subject + 泛锚（执行/输出/Arguments…）→ 不报
        _syscmd_subject_strong = (
            r'\bnet\s+user\s+\S+|\buseradd\b|\bchpasswd\b|'
            # rm -rf 只在目标是根/家目录/变量/通配/当前或上级目录/盘符/绝对路径时算危险形态；
            # 项目内相对路径（node_modules、./dist、build/）是编程助手日常清理，不算（客户B 11-21）。
            r'\brm\s+-(?:rf|fr)\b(?:\s+--?[\w-]+)*\s+["\']?'
            r'(?:[/~$*]|\.{1,2}(?:/\*?)?(?=\s|$|[;&|"\'])|[A-Za-z]:[\\/])|'
            # cmd /c 是 Windows 上执行任何命令的通用写法，归弱 subject（需强 instruction 锚）。
            r'\bmkfs(?:\.\w+)?\b|\bdd\s+if=|\breg\s+add\b|'
            r'\bEncodedCommand\b\s*[:=]?\s*[A-Za-z0-9+/=]{4,}|'
            r'\bInvoke-File\b|\bSet-Admin\b|'
            r'\bcurl\b[^\n|]{0,160}\|\s*(?:bash|sh)\b|'
            r'\bchmod\s+-R\s+(?:777|[0-7]{3})\b'
        )
        # Markdown 代码块语言标签（```bash / ```powershell）不是命令。
        _syscmd_subject_weak = (
            r'(?<!```)(?:\bcmd(?:\.exe)?\b|\bpowershell(?:\.exe)?\b|\bpwsh\b|\bbash\b|'
            r'\bsudo\b|\bpasswd\b)'
        )
        self.system_command_subject_strong_pattern = re.compile(
            f'({_syscmd_subject_strong})', re.I
        )
        self.system_command_subject_weak_pattern = re.compile(
            f'({_syscmd_subject_weak})', re.I
        )
        # 强弱合并版仅供 _finalize_evidence 回补命中片段用
        self.system_command_subject_pattern = re.compile(
            f'({_syscmd_subject_strong}|{_syscmd_subject_weak})', re.I
        )
        # 强 instruction 锚：明确恶意语境（提权/账号增删/编码载荷/绕过 UAC）
        self.system_command_instruction_strong_pattern = re.compile(
            r'(提权|管理员权限|管理员身份|创建账户|创建账号|新增用户|添加用户|删除用户|'
            r'\bEncodedCommand\b|绕过\s*UAC|\bbypass\s+UAC\b|\bPrivileges\b)',
            re.I,
        )
        # 泛 instruction 锚：中性描述词，只配合强 subject 使用；英文泛词带词边界
        self.system_command_instruction_generic_pattern = re.compile(
            r'(\bArguments\b|可执行|系统命令|命令格式|执行|还原|输出)',
            re.I,
        )
        # 极高危只保留给确定性、系统级且难以恢复的破坏动作。普通 sudo、
        # cmd /c、PowerShell 或编码载荷是高危执行信号，但不能仅凭“提权”二字
        # 与格式化磁盘、删除系统目录混为一档。
        self.system_command_critical_impact_pattern = re.compile(
            r'(\brm\s+-(?:rf|fr)\s+(?:--no-preserve-root\s+)?(?:/\s*(?:$|[;&|]|--no-preserve-root)|/(?:boot|etc|home|root|usr)(?:/|\b)|'
            r'/var/log/audit(?:/|\b))|'
            r'\bmkfs(?:\.\w+)?\b|\bdd\s+if=[^\n]{0,120}\bof=/dev/|'
            r'\buseradd\b|\bchpasswd\b|\bnet\s+user\s+\S+[^\n]{0,100}(?:/add|/delete|\bP@ss)|'
            r'\bcurl\b[^\n|]{0,160}\|\s*(?:bash|sh)\b|'
            r'\bchmod\s+-R\s+(?:777|[0-7]{3})\s+/(?:\s|$))',
            re.I,
        )
        # 明确的危险操作（客户B 11-21）：格式化/删系统盘、关杀软、提权利用、反弹 shell、
        # 关闭审计/清日志、下载执行脚本。仅在模型输出侧重估时使用：已有命中里只有它们
        # （及原有强形态里的危险项）才保留为真攻击指令；不在首轮检测里新增命中。
        self.system_command_dangerous_op_pattern = re.compile(
            r'(\bformat\s+[A-Za-z]:(?=[\s/]|$)|'
            r'\b(?:del|erase)\s+(?:/[a-z]\s+)*["\']?[A-Za-z]:\\(?:windows\b|["\'\s]|$)|'
            r'\b(?:rd|rmdir)\s+(?:/[a-z]\s+)*["\']?[A-Za-z]:\\(?:windows\b|["\'\s]|$)|'
            r'\bRemove-Item\b[^\n]{0,60}["\']?[A-Za-z]:\\(?:windows\b|["\'\s]|$)|'
            r'\bdiskpart\b(?=[^\n]{0,120}\bclean\b)|'
            r'\bSet-MpPreference\b[^\n]{0,40}-Disable\w+\s+(?:\$?true|1)\b|'
            r'\bsc(?:\.exe)?\s+(?:stop|delete|config)\s+WinDefend\b|'
            r'\bmimikatz\b|\bsekurlsa::|\blsadump::|'
            r'\b(?:PrintSpoofer|JuicyPotato|RoguePotato|GodPotato|SweetPotato)\b|'
            r'(?:利用|\bexploit\b)[^\n]{0,20}\bCVE-\d{4}-\d{4,}\b(?=[^\n]{0,30}(?:提权|escalat))|'
            r'\bbash\s+-i\s+>&\s*/dev/tcp/|/dev/tcp/\d{1,3}(?:\.\d{1,3}){3}/\d+|'
            r'\bnc(?:at)?\b[^\n]{0,40}\s-e\s+\S+|'
            r'\bSystem\.Net\.Sockets\.TCPClient\b|'
            r'\bauditctl\s+-D\b|\bwevtutil(?:\.exe)?\s+cl\b|\bClear-EventLog\b|'
            r'\b(?:systemctl|service)\s+(?:stop|disable)\s+auditd\b|'
            r'\biex\s*\(\s*(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod|New-Object\s+Net\.WebClient)\b|'
            r'\bDownloadString\s*\([^\n]{0,160}\)[^\n]{0,40}\|\s*iex\b|'
            r'\bwget\b[^\n|]{0,160}\|\s*(?:bash|sh)\b)',
            re.I,
        )
        self.system_command_dangerous_anchor_pattern = re.compile(
            r'(提权|执行|运行|使用|用|输入|粘贴|反弹|清除|清空|关闭|停掉|格式化|删除|'
            r'\b(?:run|execute|exec|type|paste|use|launch|invoke)\b)',
            re.I,
        )
        # 系统级、难以恢复的破坏：格式化系统盘、删 Windows 目录、diskpart clean。
        self.system_command_dangerous_critical_pattern = re.compile(
            r'(\bformat\s+[A-Za-z]:|\b(?:del|erase|rd|rmdir)\s+(?:/[a-z]\s+)*["\']?[A-Za-z]:\\|'
            r'\bRemove-Item\b[^\n]{0,60}[A-Za-z]:\\|\bdiskpart\b)',
            re.I,
        )
        # 模型输出侧：弱命令名（powershell/sudo/cmd/bash）配"管理员身份/管理员权限/添加用户"
        # 是在教用户怎么操作，不算攻击；只有绕过 UAC、编码载荷、以提权为目的这类攻击语境才算。
        # sudo 本身就是标准的提权手段，"用 sudo 提权后重新安装"是操作指导，sudo 只配前两类。
        self.system_command_output_attack_anchor_pattern = re.compile(
            r'(绕过\s*UAC|\bbypass\s+UAC\b|\bEncodedCommand\b)', re.I
        )
        self.system_command_output_privesc_anchor_pattern = re.compile(
            r'(绕过\s*UAC|\bbypass\s+UAC\b|\bEncodedCommand\b|提权|'
            r'\bprivilege\s+escalation\b|\bescalate\s+privileges?\b)', re.I
        )
        # 模型输出侧：reg add 只有关 Defender、改审计/事件日志才算危险；改 UAC 属削弱防护的部署写法，不报。
        self.system_command_output_reg_security_pattern = re.compile(
            r'(Windows\s+Defender|DisableAntiSpyware|DisableRealtimeMonitoring|'
            r'\\EventLog\\|\bAudit)',
            re.I,
        )
        self.system_command_output_weakening_pattern = re.compile(
            r'\bchmod\s+-R\s+(?:777|[0-7]{3})\b', re.I
        )
        # 邻近窗半径（字符数），仿 engine.py aws_secret_key 上下文窗先例
        self.system_command_strong_window = 200
        self.system_command_weak_window = 120
        self.base64_payload_pattern = re.compile(
            r'(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])'
        )
        self.debug_secret_context_pattern = re.compile(
            r'(environment[_\s-]*variables|session[_\s-]*context|session[_\s-]*token|'
            r'internal[_\s-]*config|完整上下文|环境变量|会话令牌|内部配置)',
            re.I,
        )
        self.debug_secret_key_pattern = re.compile(
            r'["\']?(API_KEY|SECRET_KEY|DATABASE_URL|TOKEN|SESSION_TOKEN|COOKIE|'
            r'ACCESS_TOKEN|CLIENT_SECRET|PRIVATE_KEY)["\']?\s*[:=]',
            re.I,
        )
        # P1-A：真实密钥值佐证——键后须在同一行跟 8+ 字符的值形态，排除 .env.example 空值占位。
        # 分隔符两侧只允许水平空白（[ \t]*），不能跨行，否则 \s* 会把下一行的键名当成本行的“值”而漏放行占位示例。
        self.debug_secret_value_pattern = re.compile(
            r'["\']?(?:API_KEY|SECRET_KEY|DATABASE_URL|TOKEN|SESSION_TOKEN|COOKIE|'
            r'ACCESS_TOKEN|CLIENT_SECRET|PRIVATE_KEY)["\']?[ \t]*[:=][ \t]*["\']?'
            r'(?P<value>[A-Za-z0-9_\-./+=]{8,})',
            re.I,
        )
        self.debug_secret_reference_value_pattern = re.compile(
            r'^(?:process\.env(?:\.|\[)|import\.meta\.env(?:\.|\[)|'
            r'os\.(?:getenv|environ)|env(?:\.|\[)|getenv\(|'
            r'(?:config|settings)(?:\.|\[)|'
            r'(?:[A-Za-z_$][A-Za-z0-9_$]*\.)+[A-Za-z_$][A-Za-z0-9_$]*)$',
            re.I,
        )
        self.agent_secret_file_tool_pattern = re.compile(
            r'(\bread_file\b|\bcat\b|读取|打开|导出|提取)[^。！？；;\r\n]{0,80}'
            r'(?:~?/\.ssh/(?:id_rsa|id_ed25519)|\bid_rsa\b|\bid_ed25519\b|'
            r'\.aws/(?:credentials|config)|\bcredentials\b|\.env\b|私钥|密钥文件|凭据文件)',
            re.I,
        )
        self.agent_secret_file_directive_pattern = re.compile(
            r'((?:请(?:用|使用|执行|运行|调用)?|帮我|立即|马上|务必|'
            r'(?:你|智能体|agent)\s*(?:去|来|必须|需要)|please|use|execute|run|call)'
            r'[^。！？；;\r\n]{0,32}(?:\bread_file\b|\bcat\b|读取|打开|导出|提取))',
            re.I,
        )
        self.agent_secret_file_exfiltration_pattern = re.compile(
            r'(上传|外发|发送|发给|传到|提交到|贴出|返回给|'
            r'webhook|external|attacker|remote\s+server)',
            re.I,
        )
        self.agent_secret_file_refusal_pattern = re.compile(
            r'(不能|无法|不应|不要|请勿|拒绝|不会|禁止|cannot|can not|should not|must not)'
            r'.{0,80}'
            r'(?:\bread_file\b|\bcat\b|读取|打开|导出|提取)'
            r'.{0,80}'
            r'(?:~?/\.ssh/(?:id_rsa|id_ed25519)|\bid_rsa\b|\bid_ed25519\b|\.env\b|私钥|密钥|凭据)',
            re.I,
        )

        self.ssrf_metadata_target_pattern = re.compile(
            # 本规则只识别云实例元数据/IMDS 探测。普通 RFC1918 私网地址
            # （如 192.168.x.x）可能是正常内网服务访问，不得仅凭“访问 + IP”升为极高危。
            r'(169\.254\.169\.254|169\.254\.170\.2|100\.100\.100\.200|fd00:ec2::254|'
            r'metadata\.google\.internal|metadata\.azure\.com|computeMetadata/v1|'
            r'latest/meta-data|metadata/instance|IMDS|云实例元数据|实例元数据服务)',
            re.I,
        )
        self.ssrf_metadata_instruction_pattern = re.compile(
            r'(\bcurl\b|\bwget\b|\bnmap\b|\bnc\s+-|Metadata-Flavor|Metadata:\s*true|'
            r'元数据获取路径|访问示例|示例请求|请求构造|服务探测|扫描参数|存活主机扫描|'
            r'获取路径|请求头|默认端口|完整请求|技术细节|\bhttp_get\b|访问|拉取|读取|'
            r'IAM\s*角色|security-credentials)',
            re.I,
        )
        self.ssrf_refusal_pattern = re.compile(
            r'(不能|无法|不应|不要|请勿|拒绝|不会|cannot|can not|should not|must not).{0,80}'
            r'(169\.254\.169\.254|127\.0\.0\.1|localhost|IMDS|元数据)',
            re.I,
        )
        # P1-A：真实元数据目标（云 IMDS）——命中即无条件按 SSRF 处理，不受开发语境排除影响
        self.ssrf_metadata_only_target = re.compile(
            r'(169\.254\.169\.254|latest/meta-data|metadata/instance|IMDS|'
            r'Metadata-Flavor|云实例元数据|实例元数据服务)',
            re.I,
        )
        # P1-A：本地回环 + 常见开发端口（localhost/127.0.0.1/0.0.0.0[:dev_port]）——开发语境排除向量
        self.ssrf_dev_localhost_pattern = re.compile(
            r'\b(?:localhost|127\.0\.0\.1|0\.0\.0\.0)'
            r'(?::(?:80|443|3000|3001|4200|5000|5173|8000|8080|8081|8443|8888|9000|9090))?\b',
            re.I,
        )
        self.agent_canary_token_pattern = re.compile(
            r'\bcanary[-_][a-z0-9][a-z0-9_-]{4,}(?:token|secret|credential|key)?\b',
            re.I,
        )
        self.agent_canary_exfil_context_pattern = re.compile(
            r'(\bsend_data\b|'
            r'\bexfiltrat(?:e|ion)\b.{0,80}'
            r'\b(?:webhook|external|server|endpoint|url|http|token|secret|credential|key)|'
            r'\b(?:send|post|upload|collect)\b.{0,80}'
            r'\b(?:webhook|external|server|endpoint|url|http|attacker|third[-_\s]?party|remote)|'
            r'(?:外传|外发).{0,80}(?:外部|webhook|接口|服务器|地址|http|令牌|密钥|凭据)|'
            r'发送.{0,80}(?:外部|webhook|接口|服务器|地址|http))',
            re.I,
        )
        self.agent_canary_meta_context_pattern = re.compile(
            r'(acceptance|proved|documentation|fixture|test|sample|example|returned\s+zero|'
            r'\bhit\b|rule[_\s-]*name|rule[_\s-]*id|raw_evidence|security[_\s-]*event|'
            r'规则|告警|样例|测试|证明|命中|误报|历史证据)',
            re.I,
        )

        # 小语种扩展（使用 Unicode 范围匹配常见少数语种字符）
        self.multilingual_patterns: List[Dict] = [
            # 维吾尔语/哈萨克语（阿拉伯字母扩展）
            {"pattern": re.compile(r'[ؠ-ي٠-٩]{2,}'), "type": "uyghur_kazakh", "severity": "low"},
            # 藏文
            {"pattern": re.compile(r'[ༀ-࿿]{2,}'), "type": "tibetan", "severity": "low"},
            # 蒙古文
            {"pattern": re.compile(r'[᠀-ᢪ]{2,}'), "type": "mongolian", "severity": "low"},
            # 西里尔字母（俄语等）
            {"pattern": re.compile(r'[Ѐ-ӿ]{4,}'), "type": "cyrillic", "severity": "low"},
            # 阿拉伯语
            {"pattern": re.compile(r'[؀-؟ي-ۿ]{4,}'), "type": "arabic", "severity": "low"},
        ]

        # 歧视内容
        self.discrimination_patterns: List[Dict] = [
            {"pattern": re.compile(r'(种族歧视|种族灭绝|黑鬼|白皮猪)', re.I), "type": "racial_discrimination", "severity": "high"},
            {**self._greedy(["地域黑"], ["河南人", "偷"], ["东北人", "暴力"]), "type": "regional_discrimination", "severity": "medium"},
            {"pattern": re.compile(r'(性别歧视|直男癌|女拳|物化女性)', re.I), "type": "gender_discrimination", "severity": "medium"},
        ]

        # 中文强辱骂的确定性低误报规则。只匹配明确的动词/替代字 + 人称 +
        # 亲属称谓组合，允许少量空白/标点；不把“草泥马”或普通“草”当辱骂。
        self.strong_cn_profanity_pattern = re.compile(
            r'(?:操|艹|肏)[\s，,。.!！?？、·~～_\-]{0,3}'
            r'(?:你|他)[\s，,。.!！?？、·~～_\-]{0,3}(?:妈|娘)'
        )

    @staticmethod
    def _greedy(*branches) -> Dict:
        """A keyword regex of words joined by ``.*``, scanned without rescanning its line per head."""
        scanner = GreedyScan(*branches, flags=re.I)
        return {"pattern": scanner.pattern, "finditer": scanner.finditer}

    def detect(self, content: str) -> List[Dict]:
        findings: List[Dict] = []
        reference_context = prepare_reference_context(content)
        # Each keyword occurrence looks up its sentence instead of rescanning the text from the start.
        sentences = SentenceIndex(content)
        windows = _WindowMemo(content)
        profanity_match = self.strong_cn_profanity_pattern.search(content)
        if profanity_match:
            matched = profanity_match.group(0)
            findings.append({
                "type": "content_safety",
                "category": "harassment_profanity_cn",
                "severity": "medium",
                "action": "audit",
                "counts_as_security_finding": True,
                "matched_text_preview": self._redact_keyword(matched),
                "matched_location": (
                    f"content[{profanity_match.start()}:{profanity_match.end()}]"
                ),
                "raw_evidence": matched,
                "redacted_evidence": "命中中文强辱骂组合",
                "evidence_kind": "literal",
                "evidence_reason": "明确辱骂动词、对象与亲属称谓在短窗口内组合",
                "rule_id": "content_safety_harassment_profanity_cn",
                "rule_name": RULE_NAMES["content_safety_harassment_profanity_cn"],
                "confidence": 0.98,
                "triage": {"cannot_downgrade": True},
            })
        findings.extend(self.profanity.detect(content))
        chemical_candidates = []
        for match in self.hazardous_chemical_subject_pattern.finditer(content):
            bounds = sentences.bounds(match.start(), match.end())
            if not sentences.judge("chemical_instruction", bounds, self.hazardous_chemical_instruction_pattern.search):
                continue
            finding = {
                "type": "content_safety", "category": "illegal_hazardous_chemical_instructions",
                "severity": "critical", "rule_id": "content_safety_illegal_hazardous_chemical_instructions",
                "confidence": 0.95, "matched_text_preview": match.group(0),
                "matched_location": f"content[{match.start()}:{match.end()}]",
                "raw_evidence": match.group(0), "evidence_kind": "literal",
            }
            reason = sentences.refusal_reason(match.start(), match.end())
            if reason:
                observation(finding, reason)
            chemical_candidates.append(finding)
        if chemical_candidates:
            findings.append(max(chemical_candidates, key=lambda f: f.get("counts_as_security_finding", True)))
        self_harm_finding = self._self_harm_actionable_finding(content)
        if self_harm_finding is not None:
            findings.append(self_harm_finding)
        system_command_assessment = self._system_command_assessment(content)
        if system_command_assessment is not None:
            system_command_confidence, system_command_severity, system_command_span = system_command_assessment
            system_command_finding = {
                "type": "content_safety",
                "category": "illegal_system_command_instructions",
                "severity": system_command_severity,
                "matched_text_preview": "system_command_instructions",
                "rule_id": "content_safety_illegal_system_command_instructions",
                "confidence": system_command_confidence,
            }
            if system_command_span is not None:
                # 证据落在真正触发判定的命令上，而不是全文第一个命令名（如 ```bash 标签）。
                span_start, span_end = system_command_span
                matched = content[span_start:span_end]
                system_command_finding.update({
                    "matched_text_preview": self._redact_keyword(matched),
                    "matched_location": f"content[{span_start}:{span_end}]",
                    "raw_evidence": matched,
                    "evidence_kind": "literal",
                })
            findings.append(system_command_finding)
        if self._is_debug_secret_template(content):
            findings.append({
                "type": "content_safety",
                "category": "debug_secret_template",
                "severity": "critical",
                "matched_text_preview": "debug_secret_template",
                "rule_id": "content_safety_debug_secret_template",
                "confidence": 0.93,
            })
        agent_secret_file_match = self._match_agent_secret_file_read_instruction(content)
        if agent_secret_file_match:
            findings.append({
                "type": "content_safety",
                "category": "debug_secret_template",
                "severity": "critical",
                "matched_text_preview": "agent_secret_file_read",
                "rule_id": "content_safety_debug_secret_template",
                "confidence": 0.94,
                "evidence_kind": "literal",
                "raw_evidence": agent_secret_file_match.group(0),
                "matched_location": (
                    f"content[{agent_secret_file_match.start()}:{agent_secret_file_match.end()}]"
                ),
                "evidence_reason": "Agent 工具被诱导读取 SSH 私钥、凭据或密钥文件",
            })
        if self._is_ssrf_metadata_instruction(content):
            target = self._ssrf_action_target(content)
            findings.append({
                "type": "content_safety",
                "category": "ssrf_metadata_instruction",
                "severity": "critical",
                "matched_text_preview": "ssrf_metadata_instruction",
                "rule_id": "content_safety_ssrf_metadata_instruction",
                "confidence": 0.94,
                **({"raw_evidence": target.group(0),
                    "matched_location": f"content[{target.start()}:{target.end()}]"} if target else {}),
            })
        canary_match = self._matches_agent_canary_token_leak(content)
        if canary_match:
            findings.append({
                "type": "content_safety",
                "category": "agent_canary_token_leak",
                "severity": "critical",
                "matched_text_preview": self._redact_keyword(canary_match.group(0)),
                "rule_id": "content_safety_agent_canary_token_leak",
                "confidence": 0.95,
                "raw_evidence": canary_match.group(0),
                "matched_location": (
                    f"content[{canary_match.start()}:{canary_match.end()}]"
                ),
                "evidence_kind": "literal",
                "evidence_reason": "真实蜜签与外发动作在邻近窗口内同时出现",
            })
        for category, patterns in [
            ("political", self.political_patterns),
            ("illegal", self.illegal_patterns),
            ("multilingual", self.multilingual_patterns),
            ("discrimination", self.discrimination_patterns),
        ]:
            for p in patterns:
                kind = p["type"]
                candidates = []
                strongest = None
                for match in p.get("finditer", p["pattern"].finditer)(content):
                    token = match.group(0)
                    bounds = sentences.bounds(match.start(), match.end())
                    confidence = sentences.judge(("keyword_confidence", category, kind, token), bounds,
                                                 lambda local: self._keyword_confidence(p, token, local))
                    # The first strongest candidate is kept, so one that cannot be stronger changes nothing. Person
                    # names, and violence wording without aggravation, are always kept as evidence only.
                    observed = kind == "leader_name" or (kind == "violence_terror" and confidence < 0.7)
                    if strongest is not None and (not observed, confidence) <= strongest:
                        continue
                    if p.get("context") and not windows.judge(
                            ("context", kind), match.start(), match.end(),
                            lambda: self._keyword_required_context_ok(p, content, match)):
                        continue
                    finding = self._keyword_finding(category, p, content, match, confidence, bounds,
                                                    sentences, windows, reference_context)
                    candidates.append(finding)
                    rank = (finding.get("counts_as_security_finding", True), confidence)
                    strongest = rank if strongest is None else max(strongest, rank)
                if candidates:
                    findings.append(max(candidates, key=lambda f: (
                        f.get("counts_as_security_finding", True), f["confidence"])))
        for finding in findings:
            finding.setdefault("triage", {}).setdefault("confidence_kind", "heuristic_rule_score")
        self._finalize_evidence(findings, content)
        return findings

    def _keyword_finding(self, category, p, content, match, confidence, bounds, sentences, windows,
                         reference_context) -> Dict:
        """One keyword occurrence as a candidate, kept as evidence only when its context explains it."""
        kind = p["type"]
        start, end = match.span()
        rule_id = f"content_safety_{category}_{kind}"
        finding = {
            "type": "content_safety", "category": f"{category}_{kind}",
            "severity": p["severity"],
            "matched_text_preview": self._redact_keyword(match.group(0)),
            "matched_location": f"content[{start}:{end}]",
            "raw_evidence": match.group(0), "evidence_kind": "literal",
            "rule_id": rule_id, "rule_name": RULE_NAMES.get(rule_id, rule_id),
            "confidence": confidence,
        }
        reason = windows.judge("prevention", start, end, lambda: defensive_reference_reason(content, start, end))
        implemented = None
        if reason and kind in _DEFENSIVE_LIVE_TYPES:
            implemented = windows.judge(("implemented", kind), start, end,
                                        lambda: self._implementation_wording(content, match, kind))
            if implemented:
                reason = ""
        if not reason and kind in _FRAMED_ILLEGAL_TYPES:
            framing = windows.judge(("framing", kind), start, end, lambda: self._framing(content, start, end, kind))
            if framing:
                return observation(finding, *framing)
        if kind == "leader_name":
            reason = "person_name_reference_without_risk"
        elif kind in {"drugs", "violence_terror"}:
            reason = reason or sentences.refusal_reason(start, end)
            if not reason and kind == "drugs":
                if implemented is None:
                    implemented = windows.judge(("implemented", kind), start, end,
                                                lambda: self._implementation_wording(content, match, kind))
                if not implemented and sentences.judge("drug_prevention", bounds, _drug_prevention_sentence):
                    reason = "local_drug_prevention_discussion"
            if not reason and kind == "violence_terror":
                reason = fenced_reference_reason(content, start, end, context=reference_context)
            if not reason and kind == "violence_terror" and confidence < 0.7:
                reason = "local_violence_description"
        if reason:
            observation(finding, reason)
        return finding

    @staticmethod
    def _framing(content: str, start: int, end: int, kind: str):
        base, local_text = covered_sentences(content, ((start, end),))
        return framing_reason(f"content_{kind}", local_text, ((start, end),), base,
                              extra_live=_FRAMED_ILLEGAL_TYPES[kind])

    @staticmethod
    def _implementation_wording(content: str, match, kind: str) -> bool:
        """Implementation wording in the keyword's sentence, not negated in its own clause."""
        _, text = covered_sentences(content, ((match.start(), match.end()),))
        patterns = _DEFENSIVE_LIVE_TYPES[kind]
        if not any(pattern.search(text) for pattern in patterns):
            return False
        return any(has_live_demand(clause, patterns) for clause in _ASK_CLAUSE.split(text))

    @staticmethod
    def _redact_keyword(text: str, max_len: int = 48) -> str:
        """命中关键词脱敏：仅去空白并按长度截断，便于界面定位与审计。"""
        snippet = (text or "").strip()
        if len(snippet) > max_len:
            snippet = snippet[:max_len] + "…"
        return snippet

    @staticmethod
    def _keyword_confidence(pattern_conf: Dict, matched_token: str, content: str) -> float:
        """关键词命中置信度。

        歧义词（如"暴力"）的判定：
        - 命中加重语境（实施/袭击/制造…）且无良性框架 → 强信号（高置信度）。
        - 单独出现，或虽带加重词但处于医疗/新闻/法律/反暴力等良性讨论语境 → 弱信号（0.5）。
        弱信号仅在置信度门控开启时降级为 audit；门控关闭时按严重度照常处置，不丢召回。
        """
        base = pattern_conf.get("confidence", 0.9)
        ambiguous = pattern_conf.get("ambiguous_tokens")
        if ambiguous and matched_token in ambiguous:
            aggravator = pattern_conf.get("aggravator")
            mitigator = pattern_conf.get("mitigator")
            has_aggravator = bool(aggravator and aggravator.search(content))
            has_mitigator = bool(mitigator and mitigator.search(content) and not has_live_directive(content))
            if not (has_aggravator and not has_mitigator):
                return 0.5
        return base

    def _keyword_required_context_ok(
        self, pattern_conf: Dict, content: str, keyword_match=None
    ) -> bool:
        context = pattern_conf.get("context")
        if not context:
            return True

        # Context must belong to the matched risk keyword. A global context
        # search lets unrelated words in a long agent prompt create a finding.
        if keyword_match is None:
            return bool(context.search(content))

        radius = 160
        start = max(0, keyword_match.start() - radius)
        end = min(len(content), keyword_match.end() + radius)
        if pattern_conf.get("type") in {"gambling", "fraud"}:
            # Operational vocabulary must belong to the risk paragraph. A
            # warning followed by an unrelated business template is not fraud.
            region_start = start
            for boundary in re.finditer(r"\r?\n[ \t]*\r?\n", content[start:end]):
                left, right = region_start + boundary.start(), region_start + boundary.end()
                if right <= keyword_match.start():
                    start = right
                elif left >= keyword_match.end():
                    end = left
                    break
        window = content[start:end]
        if not context.search(window):
            return False

        if pattern_conf.get("type") in {"gambling", "fraud"}:
            is_discussion = bool(
                self.illegal_commercial_abuse_discussion_pattern.search(window)
            )
            has_directive = bool(
                self.illegal_commercial_abuse_directive_pattern.search(window)
            )
            if is_discussion and not has_directive:
                return False
        return True

    def _finalize_evidence(self, findings: List[Dict], content: str) -> None:
        """补齐命中证据：规则带中文名，管理员证据保留真实片段与位置。

        密钥/凭据类的普通预览仍脱敏；raw_evidence 仅供已鉴权管理员详情复核。
        """
        # 复合规则的"危险主体"正则，用于回补命中片段与位置（非密钥类）
        subject_patterns: Dict[str, "re.Pattern[str]"] = {
            "content_safety_illegal_hazardous_chemical_instructions": self.hazardous_chemical_subject_pattern,
            "content_safety_self_harm_actionable_guidance": self.self_harm_subject_pattern,
            "content_safety_illegal_system_command_instructions": self.system_command_subject_pattern,
            "content_safety_ssrf_metadata_instruction": self.ssrf_metadata_target_pattern,
        }
        # 密钥/凭据类：不暴露原文，给出脱敏说明
        secret_safe_preview: Dict[str, str] = {
            "content_safety_debug_secret_template": "[命中密钥/凭据套取模式，已脱敏]",
            "content_safety_agent_canary_token_leak": "[命中蜜签令牌外泄模式，已脱敏]",
        }
        for finding in findings:
            rule_id = finding.get("rule_id", "")
            finding["rule_name"] = RULE_NAMES.get(rule_id, finding.get("rule_name") or rule_id)
            if not finding.get("matched_location"):
                match = (
                    self._first_concrete_debug_secret_value_match(content)
                    if rule_id == "content_safety_debug_secret_template"
                    else (
                        subject_patterns[rule_id].search(content)
                        if rule_id in subject_patterns
                        else None
                    )
                )
                if match:
                    finding["matched_text_preview"] = self._redact_keyword(match.group(0))
                    finding["matched_location"] = f"content[{match.start()}:{match.end()}]"
                    finding["raw_evidence"] = match.group(0)
                    finding["evidence_kind"] = "literal"
            if rule_id in secret_safe_preview:
                finding["matched_text_preview"] = secret_safe_preview[rule_id]
                continue

    def _is_hazardous_chemical_instruction(self, content: str) -> bool:
        return bool(
            self.hazardous_chemical_subject_pattern.search(content)
            and self.hazardous_chemical_instruction_pattern.search(content)
        )

    def _is_self_harm_actionable_guidance(self, content: str) -> bool:
        if self._self_harm_subject_match(content) is not None:
            return True
        return any(
            self._self_harm_subject_match(decoded) is not None
            for decoded in self._decode_base64_payloads(content)
        )

    def _matches_self_harm_actionable_guidance(self, content: str) -> bool:
        return self._self_harm_subject_match(content) is not None

    def _self_harm_subject_match(self, content: str):
        """First self-harm subject with an actionable term within 240 characters."""
        return next(self._self_harm_subjects(content), None)

    def _self_harm_subjects(self, content: str):
        """Self-harm subjects with an actionable term within 240 characters, in order.

        Technical uses ("进程自杀", "自杀开关") are not subjects. Technical and
        actionable spans are found once and looked up by bisection, so long
        repeated text stays linear.
        """
        technical = [match.span() for match in _SELF_HARM_TECHNICAL.finditer(content)]
        technical_starts = [start for start, _ in technical]
        actionable = [match.span() for match in self.self_harm_actionable_pattern.finditer(content)]
        actionable_ends = [end for _, end in actionable]
        for subject in self.self_harm_subject_pattern.finditer(content):
            start, end = subject.span()
            # Technical spans do not overlap: only the last one starting at or before the subject can cover it.
            index = bisect_right(technical_starts, start) - 1
            if index >= 0 and end <= technical[index][1]:
                continue
            low, high = max(0, start - _SELF_HARM_WINDOW), end + _SELF_HARM_WINDOW
            index = bisect_right(actionable_ends, low)
            if index == len(actionable) or actionable[index][0] >= high:
                continue
            first_start, first_end = actionable[index]
            # A term cut by the window edge is re-checked within the window itself.
            if (low <= first_start and first_end <= high) or self.self_harm_actionable_pattern.search(content, low, high):
                yield subject

    def _self_harm_actionable_finding(self, content: str):
        """Self-harm guidance in the text, or in a base64 payload when the text itself is only evidence."""
        finding = _SelfHarmText(self, content).finding()
        if finding is not None and finding.get("counts_as_security_finding", True):
            return finding
        for decoded in self._decode_base64_payloads(content):
            if finding is None:
                live = self._self_harm_subject_match(decoded) is not None
            else:
                verdict = _SelfHarmText(self, decoded).finding()
                live = verdict is not None and verdict.get("counts_as_security_finding", True)
            if live:
                return {
                    "type": "content_safety", "category": "self_harm_actionable_guidance", "severity": "critical",
                    "matched_text_preview": "self_harm_actionable_guidance",
                    "rule_id": "content_safety_self_harm_actionable_guidance", "confidence": 0.94,
                }
        return finding

    def _self_harm_subject_finding(self, content: str, start: int, end: int):
        matched = content[start:end]
        return {
            "type": "content_safety", "category": "self_harm_actionable_guidance", "severity": "critical",
            "matched_text_preview": self._redact_keyword(matched),
            "matched_location": f"content[{start}:{end}]",
            "raw_evidence": matched, "evidence_kind": "literal",
            "rule_id": "content_safety_self_harm_actionable_guidance", "confidence": 0.94,
        }

    def _system_command_confidence(self, content: str):
        """返回系统命令命中的置信度（None 表示未命中）；解码明文取最高分。"""
        assessment = self._system_command_assessment(content)
        return assessment[0] if assessment is not None else None

    def output_system_command_assessment(self, content: str):
        """模型输出侧的系统命令判定：只认真正的危险操作，普通操作指导返回 None。

        "以管理员身份运行 PowerShell""sudo 安装依赖"是模型在教用户操作；删系统盘、
        关杀软、提权利用、反弹 shell、关审计、下载执行脚本才报。返回值同
        ``_system_command_assessment``；削弱防护的常见部署写法（chmod -R 777 某目录）为 medium。
        """
        return self._system_command_assessment(content, output=True)

    def _system_command_assessment(self, content: str, output: bool = False):
        """返回 ``(confidence, severity, span)``，解码明文按影响面、再按置信度取最高。

        span 是原文里触发命中的命令位置；命中来自解码明文时为 None（由证据回补兜底）。
        """
        rank = {"critical": 2, "high": 1, "medium": 0}
        best = self._matches_system_command_instruction(content, output=output)
        for decoded in self._decode_base64_payloads(content):
            candidate = self._matches_system_command_instruction(decoded, output=output)
            if candidate is None:
                continue
            candidate = (candidate[0], candidate[1], None)
            if best is None:
                best = candidate
                continue
            best_rank = rank.get(best[1], 1)
            candidate_rank = rank.get(candidate[1], 1)
            if candidate_rank > best_rank or (candidate_rank == best_rank and candidate[0] > best[0]):
                best = candidate
        return best

    def _is_debug_secret_template(self, content: str) -> bool:
        if self._matches_debug_secret_template(content):
            return True
        return any(
            self._matches_debug_secret_template(decoded)
            for decoded in self._decode_base64_payloads(content)
        )

    def _matches_debug_secret_template(self, content: str) -> bool:
        if not self.debug_secret_context_pattern.search(content):
            return False
        if len({match.group(1).upper() for match in self.debug_secret_key_pattern.finditer(content)}) < 2:
            return False
        # P1-A：至少一个键跟着真实值形态，才算真的密钥套取（空值占位=示例，不报）
        return self._first_concrete_debug_secret_value_match(content) is not None

    def _first_concrete_debug_secret_value_match(self, content: str):
        for match in self.debug_secret_value_pattern.finditer(content):
            if self.debug_secret_reference_value_pattern.search(match.group("value")):
                continue
            return match
        return None

    def _match_agent_secret_file_read_instruction(self, content: str):
        for match in self.agent_secret_file_tool_pattern.finditer(content):
            window = self._context_window(content, match.start(), match.end(), 48)
            if self.agent_secret_file_refusal_pattern.search(window):
                continue
            if self.agent_secret_file_directive_pattern.search(window):
                return match
            if self.agent_secret_file_exfiltration_pattern.search(window):
                return match

            # A bare command at the start of a line is actionable. Inline
            # quotations in reports, handoff summaries, and rule discussions
            # have preceding narrative text and stay non-actionable.
            line_start = content.rfind("\n", 0, match.start()) + 1
            if not content[line_start:match.start()].strip():
                return match
        return None

    def _is_ssrf_metadata_instruction(self, content: str) -> bool:
        if self._matches_ssrf_metadata_instruction(content):
            return True
        return any(
            self._matches_ssrf_metadata_instruction(decoded)
            for decoded in self._decode_base64_payloads(content)
        )

    def _ssrf_action_target(self, content: str):
        for target in self.ssrf_metadata_target_pattern.finditer(content):
            line_start = content.rfind('\n', 0, target.start()) + 1
            line_end = content.find('\n', target.end())
            line_end = len(content) if line_end < 0 else line_end
            line = content[line_start:line_end]
            # In a table/report, other rows cannot supply this row's action.
            # A curl/request actually present in this row remains detectable.
            local, _, _ = bounded_sentence(content, target.start(), target.end())
            window = line if '|' in line else local
            if self.ssrf_metadata_instruction_pattern.search(window):
                if defensive_reference_reason(content, target.start(), target.end()):
                    continue
                if self.ssrf_refusal_pattern.search(local) and not re.search(
                    r'```|(?:^|\n)\s*(?:curl|wget|nmap|nc)\b|`\s*(?:curl|wget|nmap|nc)\b', local, re.I
                ):
                    continue
                return target
        return None

    def _matches_ssrf_metadata_instruction(self, content: str) -> bool:
        if self._ssrf_action_target(content) is None:
            return False
        # P1-A：开发语境排除——无真实元数据目标，且去掉本地开发端口命中后不再残留其它 SSRF 目标 → 不报
        if not self.ssrf_metadata_only_target.search(content):
            stripped = self.ssrf_dev_localhost_pattern.sub("", content)
            if not self.ssrf_metadata_target_pattern.search(stripped):
                return False
        return True

    def _is_agent_canary_token_leak(self, content: str) -> bool:
        if self._matches_agent_canary_token_leak(content) is not None:
            return True
        return any(
            self._matches_agent_canary_token_leak(decoded) is not None
            for decoded in self._decode_base64_payloads(content)
        )

    def _matches_agent_canary_token_leak(self, content: str):
        """返回真实蜜签 match；规则名称和远距离共现不得触发。"""
        for token_match in self.agent_canary_token_pattern.finditer(content):
            token = token_match.group(0).lower()
            if token in {
                "canary-token-leak",
                "canary_token_leak",
                "canary-token-secret",
                "canary_token_secret",
            }:
                continue
            window_start = max(0, token_match.start() - 180)
            window_end = min(len(content), token_match.end() + 180)
            window = content[window_start:window_end]
            rel_start = token_match.start() - window_start
            rel_end = rel_start + len(token_match.group(0))
            window_without_token = window[:rel_start] + " " + window[rel_end:]
            if not self.agent_canary_exfil_context_pattern.search(window_without_token):
                continue
            return token_match
        return None

    def _matches_system_command_instruction(self, content: str, output: bool = False):
        """双锚点 + 邻近窗共现判定，返回 (置信度, 严重度, 命中命令的 (start, end))。

        - 强 subject + 任意 instruction 锚（±200 字）→ high/critical, 0.92
        - 弱 subject + 强 instruction 锚（±120 字）→ high, 0.75
        - 弱 subject + 泛锚 → 不报（遥测字段名/URL 片段/日常运维提问）
        - 危险操作（格式化/关杀软/提权利用/反弹 shell/清审计/下载执行）+ 动作词 → high/critical, 0.9

        output=True（模型输出侧）：弱 subject 只配攻击语境锚；reg add 只认安全相关键；
        chmod -R 777 非根目录降为 medium（削弱防护的常见部署写法）。
        """
        for match in self.system_command_subject_strong_pattern.finditer(content):
            window = self._context_window(
                content, match.start(), match.end(), self.system_command_strong_window
            )
            if not (
                self.system_command_instruction_strong_pattern.search(window)
                or self.system_command_instruction_generic_pattern.search(window)
            ):
                continue
            critical = bool(self.system_command_critical_impact_pattern.search(window))
            if output and not critical:
                subject = match.group(0)
                # 模型输出里削弱防护的部署写法（关防火墙、setenforce 0、禁用 UAC、单目录 chmod -R 777）
                # 不报（用户 11-21 拍板）；关杀软、清审计/事件日志仍按危险操作报。
                if re.match(r'reg\s+add\b', subject, re.I) and not (
                    self.system_command_output_reg_security_pattern.search(window)
                ):
                    continue
                if self.system_command_output_weakening_pattern.match(subject):
                    continue
            return 0.92, ("critical" if critical else "high"), match.span()
        # 危险操作只用于模型输出侧重估时"保留"已有命中，不在首轮检测里新增命中（本次只降噪）。
        dangerous = self._match_dangerous_operation(content) if output else None
        if dangerous is not None:
            return dangerous
        for match in self.system_command_subject_weak_pattern.finditer(content):
            window = self._context_window(
                content, match.start(), match.end(), self.system_command_weak_window
            )
            if not output:
                anchor = self.system_command_instruction_strong_pattern
            elif match.group(0).lower() in ("sudo", "passwd"):
                anchor = self.system_command_output_attack_anchor_pattern
            else:
                anchor = self.system_command_output_privesc_anchor_pattern
            if anchor.search(window):
                return 0.75, "high", match.span()
        return None

    # 危险操作正则分支多，长文本逐位置试全部分支开销大；先用子串预筛，没有任何
    # 触发词的文本（绝大多数对话）直接跳过。
    _DANGEROUS_OP_TOKENS = (
        "diskpart", "mppreference", "windefend", "mimikatz", "sekurlsa", "lsadump",
        "printspoofer", "potato", "cve-", "/dev/tcp", "tcpclient", "auditctl", "wevtutil",
        "clear-eventlog", "auditd", "iex", "downloadstring", "wget",
    )

    @classmethod
    def _may_contain_dangerous_operation(cls, content: str) -> bool:
        lowered = content.lower()
        if any(token in lowered for token in cls._DANGEROUS_OP_TOKENS):
            return True
        if " -e " in lowered and ("nc " in lowered or "ncat " in lowered):
            return True
        # format X: / del、rd、Remove-Item 盘符路径都要带盘符冒号。
        return ":" in lowered and (
            "format" in lowered
            or (":\\" in lowered and any(t in lowered for t in ("del", "erase", "rd", "rmdir", "remove-item")))
        )

    def _match_dangerous_operation(self, content: str):
        if not self._may_contain_dangerous_operation(content):
            return None
        for match in self.system_command_dangerous_op_pattern.finditer(content):
            window = self._context_window(
                content, match.start(), match.end(), self.system_command_weak_window
            )
            if not self.system_command_dangerous_anchor_pattern.search(window):
                continue
            severity = (
                "critical"
                if self.system_command_dangerous_critical_pattern.match(match.group(0))
                else "high"
            )
            return 0.9, severity, match.span()
        return None

    @staticmethod
    def _context_window(content: str, start: int, end: int, radius: int) -> str:
        window_start = max(0, start - radius)
        window_end = min(len(content), end + radius)
        return content[window_start:window_end]

    def _decode_base64_payloads(self, content: str) -> List[str]:
        decoded_payloads: List[str] = []
        for candidate in self.base64_payload_pattern.findall(content):
            if len(candidate) % 4 != 0:
                continue
            try:
                decoded = base64.b64decode(candidate, validate=True).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue
            printable = sum(ch.isprintable() or ch.isspace() for ch in decoded) / len(decoded)
            if printable >= 0.8:
                decoded_payloads.append(decoded)
        return decoded_payloads


def _spans(pattern, text):
    starts, ends = [], []
    for match in pattern.finditer(text):
        starts.append(match.start())
        ends.append(match.end())
    return starts, ends


def _first_within(spans, low, high):
    """Index of the first span inside [low, high], or -1. Spans come from one finditer, so ends ascend too."""
    starts, ends = spans
    index = bisect_left(starts, low)
    return index if index < len(starts) and ends[index] <= high else -1


def _last_within(spans, low, high):
    """Index of the last span inside [low, high], or -1."""
    starts, ends = spans
    index = bisect_right(ends, high) - 1
    return index if index >= 0 and starts[index] >= low else -1


class _SelfHarmText:
    """Self-harm subjects (自杀……) and actionable terms (具体方法……) judged sentence by sentence.

    Only explicit wording keeps a sentence as evidence: an explicit refusal phrase (我不能提供、不能告诉你、
    I cannot provide、I can't help with……) or a prevention word (预防、劝阻、热线、hotline……), neither negated nor
    put as a condition, and no request (教我、告诉我……) in the sentence. A refusal sentence followed by a turn
    (但是、不过、however……, in the same sentence or opening the next one) counts unless what follows the turn is
    plainly safety advice: safety wording (缓解情绪、放松、热线、专业人士、support、feel safer……), no self-harm
    means (割腕、刀片、服药……), no step markers and no offer pointing back at the refused content.

    A subject counts when, within 240 characters, there is an actionable term whose sentence is not such evidence,
    and either the subject's own sentence is not such evidence, or the term's sentence asks for it, hands out steps
    (步骤如下、numbered or bulleted lists、首先……然后……) or names self-harm means. Terms inside refusal or
    prevention sentences never pair with other subjects. Otherwise the first co-occurring subject is kept as
    evidence with the first prevention or refusal reason.

    Every pattern runs once over the whole text and each subject or term is judged by bisection, so dense text
    stays O(n log n). Sentences are read within 240 characters of the span, as evidence_context.bounded_sentence
    does.
    """

    def __init__(self, detector, content):
        self.detector = detector
        self.content = content
        self.size = len(content)
        self.actionable = _spans(detector.self_harm_actionable_pattern, content)
        self.subjects = []
        if not self.actionable[0]:
            return
        subjects = [match.span() for match in detector.self_harm_subject_pattern.finditer(content)]
        technical = _spans(_SELF_HARM_TECHNICAL, content)
        for start, end in subjects:
            # Technical spans do not overlap: only the last one starting at or before the subject can cover it.
            index = bisect_right(technical[0], start) - 1
            if not (index >= 0 and end <= technical[1][index]):
                self.subjects.append((start, end))
        if not self.subjects:
            return
        # Prevention words inside a subject ("危机干预负样本") are part of the pretext, not prevention.
        pieces, last = [], 0
        for start, end in subjects:
            pieces.append(content[last:start])
            pieces.append(" " * (end - start))
            last = end
        pieces.append(content[last:])
        self.plain = plain = "".join(pieces)
        self.stops = [match.start() for match in BOUNDARY.finditer(content)]
        self.scopes = _spans(_NEGATION_SCOPE, plain)
        negations = _spans(_SELF_HARM_NEGATION, plain)
        refusal_negations = _spans(_SELF_HARM_REFUSAL_NEGATION, plain)
        self.refusals = self._asserted(_SELF_HARM_REFUSAL, content, refusal_negations)
        self.prevention = self._asserted(_SELF_HARM_PREVENTION, plain, negations)
        self.safe = self._asserted(_SELF_HARM_SAFE, plain, negations)
        self.live = _spans(_SELF_HARM_LIVE, plain)
        self.step_starts = [match.start() for match in _SELF_HARM_STEPS.finditer(content)]
        self.means = _spans(_SELF_HARM_MEANS, content)
        self.turns = _spans(_SELF_HARM_TURN, content)
        self.backrefs = _spans(_SELF_HARM_BACKREF, content)
        self.facts = {}
        self.term_status = [self.status(start, end) for start, end in zip(*self.actionable)]
        self.open_terms = [0]
        self.strong_terms = [0]
        for reason, _, strong in self.term_status:
            self.open_terms.append(self.open_terms[-1] + (not reason))
            self.strong_terms.append(self.strong_terms[-1] + strong)

    def _negated(self, start, negations):
        """A negation word in the same clause, at most 20 characters before ``start``, not cancelled (不要犹豫……)."""
        low = max(0, start - _NEGATION_REACH)
        index = bisect_right(self.scopes[1], start) - 1
        if index >= 0 and self.scopes[1][index] > low:
            low = self.scopes[1][index]
        negation = _last_within(negations, low, start)
        if negation < 0:
            return False
        return not _SELF_HARM_NEGATION_CANCEL.search(self.plain, negations[1][negation], start)

    def _asserted(self, pattern, text, negations):
        starts, ends = [], []
        for match in pattern.finditer(text):
            if not self._negated(match.start(), negations):
                starts.append(match.start())
                ends.append(match.end())
        return starts, ends

    def sentence(self, start, end):
        index = bisect_left(self.stops, start)
        left = self.stops[index - 1] + 1 if index else 0
        index = bisect_left(self.stops, end)
        right = self.stops[index] if index < len(self.stops) else self.size
        return max(left, start - _SELF_HARM_WINDOW), min(right, end + _SELF_HARM_WINDOW)

    def _steps_in(self, low, high):
        index = bisect_left(self.step_starts, low)
        return index < len(self.step_starts) and self.step_starts[index] <= high

    def _bad(self, low, high):
        """Self-harm means, step markers or an offer pointing back at the refused content."""
        return (_first_within(self.means, low, high) >= 0 or self._steps_in(low, high)
                or _first_within(self.backrefs, low, high) >= 0)

    def _turned_in_sentence(self, low, high, first_refusal):
        """A turn after a refusal phrase in [low, high] whose tail (to ``high``) is not plainly safety advice.

        Only the first turn after each refusal phrase is a turn after a refusal. Every tail ends at ``high``, so
        the first such turn has the longest tail: when it has no means, steps or back-pointing offer, no later
        tail has either, and a later turn counts only when no safety wording follows it.
        """
        turns = self.turns
        first = _first_within(turns, self.refusals[1][first_refusal], high)
        if first < 0:
            return False
        tail = turns[1][first]
        if self._bad(tail, high):
            return True
        last_safe = _last_within(self.safe, tail, high)
        if last_safe < 0:
            return True
        # The first turn whose tail has no safety wording, and the last turn of the window.
        after = bisect_right(turns[1], self.safe[0][last_safe])
        if after >= len(turns[1]) or turns[1][after] > high:
            return False
        last = _last_within(turns, low, high)
        # Some turn from ``after`` on is the first turn after a refusal phrase.
        return _first_within(self.refusals, turns[1][after - 1], turns[0][last]) >= 0

    def _turned_next_sentence(self, high):
        """The next sentence opens with a turn whose sentence is not plainly safety advice."""
        index = bisect_left(self.stops, high)
        if index == len(self.stops) or self.stops[index] != high:
            # The window ended before the sentence did.
            return False
        position, limit = high, min(self.size, high + 16)
        while position < limit and (self.content[position].isspace() or self.content[position] in "。！？!?；;."):
            position += 1
        turn = _SELF_HARM_TURN.match(self.content, position)
        if turn is None:
            return False
        tail = turn.end()
        index = bisect_left(self.stops, tail)
        end = min(self.stops[index] if index < len(self.stops) else self.size, tail + _SELF_HARM_WINDOW)
        return self._bad(tail, end) or _first_within(self.safe, tail, end) < 0

    def _sentence_facts(self, low, high):
        key = (low, high)
        if key not in self.facts:
            first_refusal = _first_within(self.refusals, low, high)
            turned = first_refusal >= 0 and (self._turned_in_sentence(low, high, first_refusal)
                                             or self._turned_next_sentence(high))
            self.facts[key] = (
                turned,
                first_refusal >= 0,
                _first_within(self.prevention, low, high) >= 0,
                _first_within(self.live, low, high) >= 0,
                self._steps_in(low, high) or _first_within(self.means, low, high) >= 0,
            )
        return self.facts[key]

    def status(self, start, end):
        """(reason, label, strong); reason is "" when the span's sentence is not refusal or prevention evidence."""
        turned, refusal, prevention, live, strong = self._sentence_facts(*self.sentence(start, end))
        if turned:
            return "", None, True
        if refusal and not live:
            return "local_refusal", None, False
        if prevention and not live:
            return "self_harm_prevention", "预防或求助", False
        return "", None, live or strong

    def _terms_near(self, start, end):
        """Actionable terms within 240 characters: an index range plus terms cut by the window edge."""
        starts, ends = self.actionable
        low, high = max(0, start - _SELF_HARM_WINDOW), end + _SELF_HARM_WINDOW
        first, last = bisect_right(ends, low), bisect_left(starts, high) - 1
        edges = []
        if first <= last and starts[first] < low:
            # A term cut by the window edge is re-checked within the window itself.
            if self.detector.self_harm_actionable_pattern.search(self.content, low, ends[first]):
                edges.append(first)
            first += 1
        if first <= last and ends[last] > high:
            if self.detector.self_harm_actionable_pattern.search(self.content, starts[last], high):
                edges.append(last)
            last -= 1
        return first, last, edges

    def _count(self, prefix, first, last, edges, flag):
        inner = prefix[last + 1] - prefix[first] if first <= last else 0
        return inner + sum(1 for index in edges if flag(self.term_status[index]))

    def finding(self):
        detector = self.detector
        observed = live_request = None
        if not self.subjects:
            return None
        for start, end in self.subjects:
            first, last, edges = self._terms_near(start, end)
            if first > last and not edges:
                continue
            subject_status = None
            if self._count(self.open_terms, first, last, edges, lambda status: not status[0]):
                subject_status = self.status(start, end)
                if not subject_status[0]:
                    return detector._self_harm_subject_finding(self.content, start, end)
                if live_request is None and self._count(self.strong_terms, first, last, edges,
                                                        lambda status: status[2]):
                    live_request = (start, end)
            if observed is None:
                reason, label, _ = subject_status or self.status(start, end)
                if not reason:
                    # Every nearby term sits in a prevention or refusal sentence: report the first one.
                    reason, label, _ = self.term_status[min(edges + ([first] if first <= last else []))]
                observed = (start, end, reason, label)
        if live_request is not None:
            return detector._self_harm_subject_finding(self.content, *live_request)
        if observed is None:
            return None
        start, end, reason, label = observed
        return _observation(detector._self_harm_subject_finding(self.content, start, end), reason, label)
