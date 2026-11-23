package repository

import "sort"

type policyCapabilityBindingSeed struct {
	RuleType             string
	Name                 string
	PolicyCode           string
	CapabilityCategories []string
	BindingMode          string
}

type DefaultRuntimePolicyContract struct {
	RuleType             string
	Name                 string
	PolicyCode           string
	Action               string
	CapabilityCategories []string
	BindingMode          string
}

// exactPolicyCapabilityBindings contains only findings that can independently
// express the named policy. Broad, operational and derived signals are
// intentionally absent. Keep this list in exact lockstep with the baseline,
// runtime, and forward capability migrations.
var exactPolicyCapabilityBindings = []policyCapabilityBindingSeed{
	{"prompt_injection", "经典注入指令检测", "builtin.prompt_injection.8894ce9a632bada9", []string{"keyword_classic_injection", "keyword_classic_injection_en"}, "any"},
	{"prompt_injection", "角色扮演注入检测", "builtin.prompt_injection.7396b867d7156f96", []string{"keyword_roleplay", "keyword_roleplay_en", "semantic_roleplay"}, "any"},
	{"prompt_injection", "否定式注入", "builtin.prompt_injection.1ac9559c46501ff8", []string{"semantic_negation_bypass"}, "any"},
	{"prompt_injection", "假设场景绕过", "builtin.prompt_injection.fec82263fa576a55", []string{"semantic_hypothetical_bypass"}, "any"},
	{"prompt_injection", "系统提示覆写检测", "builtin.prompt_injection.594c6d42965bb1d1", []string{"semantic_instruction_override"}, "any"},
	{"prompt_injection", "Base64 编码注入", "builtin.prompt_injection.f4809d017dfbf3a6", []string{"encoding_base64"}, "any"},
	{"prompt_injection", "Hex 编码注入", "builtin.prompt_injection.ac6042efdf14b49c", []string{"encoding_hex_escape"}, "any"},
	{"prompt_injection", "Unicode 编码绕过", "builtin.prompt_injection.8a4cfd4d54e80e99", []string{"encoding_unicode_escape"}, "any"},
	{"prompt_injection", "零宽字符注入", "builtin.prompt_injection.ba9bbb9f63e7b514", []string{"zero_width_char"}, "any"},
	{"prompt_injection", "逐步诱导检测", "builtin.prompt_injection.6e0c3ca0b2eaf8a8", []string{"semantic_step_by_step_bypass"}, "any"},
	{"prompt_injection", "翻译绕过", "builtin.prompt_injection.752acd8e33f82f2d", []string{"semantic_translation_bypass"}, "any"},
	{"prompt_injection", "模板填充注入", "builtin.prompt_injection.bfbe6a1eccdb32ef", []string{"structured_template_injection"}, "any"},

	{"content_safety", "敏感政治事件", "builtin.content_safety.d6d189ffdd19c725", []string{"political_sensitive_event"}, "any"},
	{"content_safety", "领土主权检测", "builtin.content_safety.aeeb1eb209b9046e", []string{"political_territory_taiwan", "political_territory_split"}, "any"},
	{"content_safety", "历史虚无主义", "builtin.content_safety.295e1c9330cfd201", []string{"political_historical_nihilism"}, "any"},
	{"content_safety", "色情低俗内容", "builtin.content_safety.58663e6bd52f1ade", []string{"illegal_pornography"}, "any"},
	{"content_safety", "暴力恐怖内容", "builtin.content_safety.a33fdb67d98f1e9d", []string{"illegal_violence_terror"}, "any"},
	{"content_safety", "自杀方法指导", "builtin.content_safety.50e1338e3f0a2d02", []string{"self_harm_actionable_guidance"}, "any"},
	{"content_safety", "赌博/诈骗内容", "builtin.content_safety.3b524e3893a7da4f", []string{"illegal_gambling", "illegal_fraud"}, "any"},

	{"agent_detect", "Claude Code 管控", "builtin.agent_detect.f93768ab6617606e", []string{"agent_claude_code"}, "any"},
	{"agent_detect", "Cursor IDE 管控", "builtin.agent_detect.b620fc06d06c1fc7", []string{"agent_cursor"}, "any"},
	{"agent_detect", "GitHub Copilot 管控", "builtin.agent_detect.12438c4c568f8c24", []string{"agent_github_copilot"}, "any"},
	{"agent_detect", "Cline/Roo Code 管控", "builtin.agent_detect.60879276c451279a", []string{"agent_cline"}, "any"},
	{"agent_detect", "Windsurf/Cascade 管控", "builtin.agent_detect.c1896e0995119428", []string{"agent_windsurf"}, "any"},
	{"agent_detect", "Continue.dev 管控", "builtin.agent_detect.1d449b7a84677bb2", []string{"agent_continue_dev"}, "any"},
	{"agent_detect", "OpenAI Codex CLI 检测", "builtin.agent_detect.223c40ba05f83647", []string{"agent_openai_codex"}, "any"},
	{"agent_detect", "Aider 检测", "builtin.agent_detect.008356aa358e9978", []string{"agent_aider"}, "any"},
	{"agent_detect", "Amazon Q Developer 检测", "builtin.agent_detect.a5d24299196cf4f3", []string{"agent_amazon_q_developer"}, "any"},
	{"agent_detect", "Google Gemini Code Assist", "builtin.agent_detect.f539af0c43cb3787", []string{"agent_gemini_code_assist"}, "any"},
	{"agent_detect", "Tabnine 检测", "builtin.agent_detect.6cada6a14d0a4263", []string{"agent_tabnine"}, "any"},
	{"agent_detect", "Sourcegraph Cody 检测", "builtin.agent_detect.79ae5816a3bf3ee5", []string{"agent_sourcegraph_cody"}, "any"},
	{"agent_detect", "Replit AI 检测", "builtin.agent_detect.3aa45df74b2de7a8", []string{"agent_replit_ai"}, "any"},
	{"agent_detect", "CodeRabbit 检测", "builtin.agent_detect.c1759598ed72a0d2", []string{"agent_coderabbit"}, "any"},
	{"agent_detect", "AutoGPT/BabyAGI 检测", "builtin.agent_detect.c124e717941b210c", []string{"agent_autogpt_babyagi"}, "any"},
	{"agent_detect", "LangChain/LlamaIndex SDK", "builtin.agent_detect.364d6d282e3fd912", []string{"agent_langchain_llamaindex"}, "any"},
	{"agent_detect", "CrewAI/AutoGen 检测", "builtin.agent_detect.5a691bbd627d263a", []string{"agent_crewai_autogen"}, "any"},
	{"agent_detect", "Dify/Coze 平台检测", "builtin.agent_detect.6f490afdd7023369", []string{"agent_dify_coze"}, "any"},

	{"data_leak", "手机号检测", "builtin.data_leak.e5821efde7585cbb", []string{"phone_cn"}, "any"},
	{"data_leak", "身份证号检测", "builtin.data_leak.ee20059e4c9fbf2f", []string{"id_card_cn"}, "any"},
	{"data_leak", "银行卡号检测", "builtin.data_leak.a3048f2177b99395", []string{"bank_card_cn"}, "any"},
	{"data_leak", "邮箱地址检测", "builtin.data_leak.261854a33ac6da17", []string{"email"}, "any"},
	{"data_leak", "API Key 检测", "builtin.data_leak.aa4bbf915707ff15", []string{"generic_api_key", "openai_key", "anthropic_key", "github_token"}, "any"},
	{"data_leak", "JWT/Token 检测", "builtin.data_leak.87358f1a6d000590", []string{"jwt_token"}, "any"},
	{"data_leak", "证书/私钥检测", "builtin.data_leak.a0891acf6ebc39c0", []string{"ssh_private_key"}, "any"},
	{"data_leak", "SSH 密钥检测", "builtin.data_leak.db6cefda8798cab2", []string{"openssh_private_key"}, "any"},
	{"data_leak", "数据库连接串检测", "builtin.data_leak.67728f5a17e4a70a", []string{"code_leak_database_url"}, "any"},
	{"data_leak", "涉密文件标记检测", "builtin.data_leak.17723b156cfa7533", []string{"classified_classified_cn", "classified_classified_en"}, "any"},
	{"data_leak", "护照号检测", "builtin.data_leak.2348426d637af519", []string{"passport_cn"}, "any"},
	{"data_leak", "港澳台证件检测", "builtin.data_leak.63ae19f7cd1834bf", []string{"hk_macao_taiwan_id"}, "any"},
	{"data_leak", "军官证检测", "builtin.data_leak.9a6811b786b7618f", []string{"officer_id_cn"}, "any"},
	{"data_leak", "驾驶证检测", "builtin.data_leak.86c5bbeff12d7c44", []string{"driver_license_cn"}, "any"},
	{"data_leak", "社保卡号检测", "builtin.data_leak.e18afae0f9594164", []string{"social_security_cn"}, "any"},
	{"data_leak", "家庭地址检测", "builtin.data_leak.aa6a72765f3d1d2b", []string{"home_address_cn"}, "any"},
	{"data_leak", "IP 地址检测", "builtin.data_leak.0cce2cce8b7bc217", []string{"ip_address"}, "any"},
	{"data_leak", "出生日期检测", "builtin.data_leak.b37eae3f56e3d8f4", []string{"birth_date"}, "any"},
	{"data_leak", "通信记录检测", "builtin.data_leak.3512cd70e182c979", []string{"communication_record"}, "any"},
	{"data_leak", "位置/GPS 数据", "builtin.data_leak.a9ac5ee3d220e157", []string{"gps_location"}, "any"},
	{"data_leak", "密码明文检测", "builtin.data_leak.98cc238bfbf6babb", []string{"plain_password", "code_leak_password_in_code"}, "any"},
	{"data_leak", "AWS/GCP 凭据检测", "builtin.data_leak.4cf7caaec6252ac7", []string{"cloud_credential", "aws_access_key", "aws_secret_key", "code_leak_cloud_credential"}, "any"},
	{"data_leak", "信用卡CVV检测", "builtin.data_leak.afa8b93679b66cb2", []string{"credit_card_cvv"}, "any"},
	{"data_leak", "银行流水检测", "builtin.data_leak.d85734a727cce7b8", []string{"bank_statement"}, "any"},
	{"data_leak", "保险信息检测", "builtin.data_leak.7399a414eb30dbb9", []string{"insurance_info"}, "any"},
	{"data_leak", "医疗记录检测", "builtin.data_leak.cd7cd3f962c8a7c1", []string{"medical_record"}, "any"},
	{"data_leak", "基因数据检测", "builtin.data_leak.f21dc3ac3d94c0f3", []string{"genetic_data"}, "any"},
	{"data_leak", "生物特征检测", "builtin.data_leak.65f151cdf48b5404", []string{"biometric_data"}, "any"},
	{"data_leak", "内部项目代号检测", "builtin.data_leak.e40d55f61d111133", []string{"internal_project_code"}, "any"},
	{"data_leak", "敏感代码片段检测", "builtin.data_leak.85d7d239c670bab5", []string{"sensitive_code"}, "any"},
	{"data_leak", "教育背景检测", "builtin.data_leak.55e2d913ee8746b4", []string{"education_background"}, "any"},
	{"data_leak", "犯罪记录检测", "builtin.data_leak.1a873ce1a4f5e91e", []string{"criminal_record"}, "any"},
	{"code_security", "SQL 注入代码生成", "builtin.code_security.d82567ae4c6cba2a", []string{"code_sql_injection_generation"}, "any"},
	{"code_security", "LDAP 注入代码", "builtin.code_security.c0bf948ca3c9ebe2", []string{"code_ldap_injection_generation"}, "any"},
	{"code_security", "NoSQL 注入代码", "builtin.code_security.2da958a010ca4303", []string{"code_nosql_injection_generation"}, "any"},
	{"code_security", "SSRF 代码生成", "builtin.code_security.eea7475d95f58dd5", []string{"code_ssrf_generation"}, "any"},
	{"code_security", "XML 外部实体注入", "builtin.code_security.d6121b4e9c6b3639", []string{"code_xxe_generation"}, "any"},
	{"code_security", "XSS 代码生成", "builtin.code_security.46a74885f15123bb", []string{"code_xss_generation"}, "any"},
	{"code_security", "不安全的文件处理", "builtin.code_security.0234e3099d41f98b", []string{"code_unsafe_file_handling"}, "any"},
	{"code_security", "不安全的随机数", "builtin.code_security.3e1454b49ab95b46", []string{"code_insecure_random"}, "any"},
	{"code_security", "内存溢出代码", "builtin.code_security.d4bd0d8e0c6c9857", []string{"code_memory_overflow_generation"}, "any"},
	{"code_security", "反序列化漏洞代码", "builtin.code_security.83c72801873c89c6", []string{"code_insecure_deserialization"}, "any"},
	{"code_security", "命令注入代码生成", "builtin.code_security.2e8190e3871e45d6", []string{"code_command_injection_generation"}, "any"},
	{"code_security", "弱加密代码生成", "builtin.code_security.829c9fe3cbc3a792", []string{"code_weak_crypto_generation"}, "any"},
	{"code_security", "日志注入代码", "builtin.code_security.be648ff0048d7877", []string{"code_log_injection_generation"}, "any"},
	{"code_security", "权限绕过代码", "builtin.code_security.4f2a28590d7747f6", []string{"code_auth_bypass_generation"}, "any"},
	{"code_security", "模板注入代码", "builtin.code_security.3f67649cc24121a3", []string{"code_template_injection_generation"}, "any"},
	{"code_security", "硬编码凭据示例", "builtin.code_security.9640acf0d1083905", []string{"code_hardcoded_credential_generation", "code_leak_password_in_code"}, "any"},
	{"code_security", "路径遍历代码生成", "builtin.code_security.389ee9cb3cb7c789", []string{"code_path_traversal_generation"}, "any"},
	{"fraud_detect", "假冒公检法话术", "builtin.fraud_detect.eafd99decc56bca2", []string{"fraud_law_enforcement_impersonation"}, "any"},
	{"fraud_detect", "假冒银行通知", "builtin.fraud_detect.6ff312032520747d", []string{"fraud_bank_notice"}, "any"},
	{"fraud_detect", "冒充客服话术", "builtin.fraud_detect.9dbfbdb60934fd8e", []string{"fraud_customer_service_impersonation"}, "any"},
	{"fraud_detect", "冒充领导诈骗", "builtin.fraud_detect.eadf367494293780", []string{"fraud_executive_impersonation"}, "any"},
	{"fraud_detect", "刷单诈骗话术", "builtin.fraud_detect.9414bd270d35d512", []string{"fraud_task_scam"}, "any"},
	{"fraud_detect", "加密货币骗局", "builtin.fraud_detect.7e0c55725773bdb8", []string{"fraud_crypto_scam"}, "any"},
	{"fraud_detect", "庞氏骗局话术", "builtin.fraud_detect.c99081d7ce4ae6de", []string{"fraud_ponzi_scheme"}, "any"},
	{"fraud_detect", "杀猪盘话术", "builtin.fraud_detect.5b7e940a2a8800b2", []string{"fraud_pig_butchering"}, "any"},
	{"fraud_detect", "虚假中奖信息", "builtin.fraud_detect.e6509942afa78488", []string{"fraud_fake_prize"}, "any"},
	{"fraud_detect", "虚假众筹文案", "builtin.fraud_detect.5924fd3912c0e21c", []string{"fraud_crowdfunding"}, "any"},
	{"fraud_detect", "虚假投资平台", "builtin.fraud_detect.e8c52e0bae177488", []string{"fraud_fake_investment_platform"}, "any"},
	{"fraud_detect", "虚假投资话术", "builtin.fraud_detect.85094af4238a5149", []string{"fraud_investment_pitch"}, "any"},
	{"fraud_detect", "虚假招聘诈骗", "builtin.fraud_detect.193da7504db91d7c", []string{"fraud_recruitment"}, "any"},
	{"fraud_detect", "虚假购物网站", "builtin.fraud_detect.5fdc9f9c064a22a1", []string{"fraud_fake_shop"}, "any"},
	{"fraud_detect", "虚假贷款推广", "builtin.fraud_detect.98e22b1a3a71ca52", []string{"fraud_loan"}, "any"},
	{"fraud_detect", "退款诈骗话术", "builtin.fraud_detect.8515194cb5e180de", []string{"fraud_refund"}, "any"},
	{"fraud_detect", "钓鱼邮件生成", "builtin.fraud_detect.31114886164ee6ac", []string{"fraud_phishing_email"}, "any"},
	{"illegal_trade", "人体器官交易", "builtin.illegal_trade.2baa4f43c99678c0", []string{"illegal_organ_trade"}, "any"},
	{"illegal_trade", "人口贩卖内容", "builtin.illegal_trade.b42c9e2d1d6a1cdb", []string{"illegal_human_trafficking"}, "any"},
	{"illegal_trade", "假冒证件制作", "builtin.illegal_trade.41681caad5e30153", []string{"illegal_forged_document"}, "any"},
	{"illegal_trade", "假货制造指导", "builtin.illegal_trade.17afa89cca4e8954", []string{"illegal_counterfeit_goods"}, "any"},
	{"illegal_trade", "处方药违规销售", "builtin.illegal_trade.3a11e5702d46e089", []string{"illegal_prescription_drug_trade"}, "any"},
	{"illegal_trade", "毒品交易引导", "builtin.illegal_trade.103b0604b9ae8e51", []string{"illegal_drug_trade"}, "any"},
	{"illegal_trade", "走私方法咨询", "builtin.illegal_trade.5ed755f877e035f9", []string{"illegal_smuggling"}, "any"},
	{"illegal_trade", "违禁品交易引导", "builtin.illegal_trade.36d483957d6bc246", []string{"illegal_contraband_trade"}, "any"},
	{"illegal_trade", "野生动物交易", "builtin.illegal_trade.3f55b904e1900e0d", []string{"illegal_wildlife_trade"}, "any"},
	{"illegal_trade", "非法武器交易", "builtin.illegal_trade.b5eab46d920f0a59", []string{"illegal_weapon_trade"}, "any"},
	{"illegal_trade", "黑市交易引导", "builtin.illegal_trade.4f6d018cc6d7ee00", []string{"illegal_black_market"}, "any"},
	{"prompt_injection", "ASCII 艺术注入", "builtin.prompt_injection.c2cc41c645d6e802", []string{"injection_ascii_art"}, "any"},
	{"prompt_injection", "Base32/Base16 编码注入", "builtin.prompt_injection.9f67a6da54bce276", []string{"injection_base32_base16"}, "any"},
	{"prompt_injection", "Emoji 编码注入", "builtin.prompt_injection.467da79f0b886cd8", []string{"injection_emoji_encoding"}, "any"},
	{"prompt_injection", "JSON/XML 结构注入", "builtin.prompt_injection.7264c727a4fc2ed4", []string{"injection_structured_json_xml"}, "any"},
	{"prompt_injection", "Markdown 渲染注入", "builtin.prompt_injection.75f29627a37e0d01", []string{"injection_markdown_rendering"}, "any"},
	{"prompt_injection", "Payload 拆分注入", "builtin.prompt_injection.4326456f74d43796", []string{"injection_payload_splitting"}, "any"},
	{"prompt_injection", "ROT13/Atbash 编码绕过", "builtin.prompt_injection.4b465e70a6377330", []string{"injection_rot13_atbash"}, "any"},
	{"prompt_injection", "Token 走私攻击", "builtin.prompt_injection.f28adec4733f37d1", []string{"injection_token_smuggling"}, "any"},
	{"prompt_injection", "URL 编码绕过", "builtin.prompt_injection.57767f0750a92dfa", []string{"injection_url_encoding"}, "any"},
	{"prompt_injection", "上下文截断攻击", "builtin.prompt_injection.ba9a8699a54af996", []string{"injection_context_truncation"}, "any"},
	{"prompt_injection", "二进制/八进制编码注入", "builtin.prompt_injection.5ab93c096487f735", []string{"injection_binary_octal"}, "any"},
	{"prompt_injection", "伪代码注入", "builtin.prompt_injection.90eebdc9900c34be", []string{"injection_pseudocode"}, "any"},
	{"prompt_injection", "分隔符混淆攻击", "builtin.prompt_injection.d2484f0152f1f577", []string{"injection_delimiter_confusion"}, "any"},
	{"prompt_injection", "双重编码检测", "builtin.prompt_injection.4fb2be0130d3f3f1", []string{"injection_double_encoding"}, "any"},
	{"prompt_injection", "同形字符替换", "builtin.prompt_injection.3c2c8a296f39670e", []string{"injection_homoglyph"}, "any"},
	{"prompt_injection", "对抗性后缀攻击", "builtin.prompt_injection.73644306e4dfbcf4", []string{"injection_adversarial_suffix"}, "any"},
	{"prompt_injection", "自定义编码/莫尔斯电码", "builtin.prompt_injection.b167772e4c27e54b", []string{"injection_morse_custom_encoding"}, "any"},
	{"copyright_protect", "专利内容复制", "builtin.copyright_protect.9c0b04a17d008a0c", []string{"copyright_patent_copy"}, "any"},
	{"copyright_protect", "侵权图像描述", "builtin.copyright_protect.7123a899c2158bdb", []string{"copyright_image_reproduction"}, "any"},
	{"copyright_protect", "受保护角色再现", "builtin.copyright_protect.36cd5135e9429132", []string{"copyright_character_reproduction"}, "any"},
	{"copyright_protect", "受版权文本生成", "builtin.copyright_protect.8459d0184254fe69", []string{"copyright_text_reproduction"}, "any"},
	{"copyright_protect", "商业机密提取", "builtin.copyright_protect.1107170cb2c8407a", []string{"copyright_trade_secret_extraction"}, "any"},
	{"copyright_protect", "学术论文盗用", "builtin.copyright_protect.d971cfcccc10c312", []string{"copyright_academic_plagiarism"}, "any"},
	{"copyright_protect", "开源许可绕过", "builtin.copyright_protect.e3ded2f4e7620f42", []string{"copyright_license_bypass"}, "any"},
	{"copyright_protect", "歌词批量导出", "builtin.copyright_protect.a77b346995352c2b", []string{"copyright_lyrics_bulk_export"}, "any"},
	{"copyright_protect", "盗版内容提取", "builtin.copyright_protect.5bc4433e74d45c13", []string{"copyright_pirated_content_extraction"}, "any"},
	{"plugin_security", "MCP 权限绕过", "builtin.plugin_security.450758fa39c93507", []string{"plugin_mcp_permission_bypass"}, "any"},
	{"plugin_security", "工具拒绝执行", "builtin.plugin_security.1024164507834300", []string{"plugin_tool_denial"}, "any"},
	{"plugin_security", "工具日志篡改", "builtin.plugin_security.b5f7907c68e5bf34", []string{"plugin_log_tampering"}, "any"},
	{"plugin_security", "工具窃取数据", "builtin.plugin_security.1aa5c9889e5f4e27", []string{"plugin_data_theft"}, "any"},
	{"plugin_security", "恶意插件安装", "builtin.plugin_security.7f715200f0fa437d", []string{"plugin_malicious_install"}, "any"},
	{"plugin_security", "插件数据泄露", "builtin.plugin_security.0e486a2f5576a9b0", []string{"plugin_data_leak"}, "any"},
	{"plugin_security", "插件权限提升", "builtin.plugin_security.ba997217f9b54e40", []string{"plugin_privilege_escalation"}, "any"},
	{"plugin_security", "插件链式攻击", "builtin.plugin_security.fb49d223f677b0ac", []string{"plugin_chain_attack"}, "any"},
	{"plugin_security", "文件系统越权", "builtin.plugin_security.e9d082e3a9566521", []string{"plugin_filesystem_overreach"}, "any"},
	{"plugin_security", "未授权工具调用", "builtin.plugin_security.5c66059903fe2cab", []string{"plugin_unauthorized_tool_call"}, "any"},
	{"plugin_security", "网络请求伪造", "builtin.plugin_security.2932cca214e98d4e", []string{"plugin_network_request_forgery"}, "any"},
	{"content_safety", "人肉搜索指导", "builtin.content_safety.93a1f2312c974373", []string{"content_doxxing_guidance"}, "any"},
	{"content_safety", "人身攻击指导", "builtin.content_safety.94c8f6138ae0a180", []string{"content_personal_assault_guidance"}, "any"},
	{"content_safety", "仇恨言论", "builtin.content_safety.130064bdc1ae51ab", []string{"content_hate_incitement"}, "any"},
	{"content_safety", "医疗欺诈内容", "builtin.content_safety.f658a2f524585da0", []string{"content_medical_fraud"}, "any"},
	{"content_safety", "家庭暴力内容", "builtin.content_safety.e741adeb0f05ae95", []string{"content_domestic_violence"}, "any"},
	{"content_safety", "性暴力内容", "builtin.content_safety.94cbba62575e32f9", []string{"content_sexual_violence"}, "any"},
	{"content_safety", "恐怖主义宣传", "builtin.content_safety.3f07c132c798a867", []string{"content_terrorism_propaganda"}, "any"},
	{"content_safety", "未成年人保护", "builtin.content_safety.972bcf8de3b4d32d", []string{"content_minor_exploitation"}, "any"},
	{"content_safety", "校园暴力内容", "builtin.content_safety.167af81998f1d9d8", []string{"content_school_bullying"}, "any"},
	{"content_safety", "武器制作指导", "builtin.content_safety.2e163d09b9155752", []string{"content_weapon_construction"}, "any"},
	{"content_safety", "歧视内容", "builtin.content_safety.741b4225c2f0b108", []string{"content_discrimination"}, "any"},
	{"content_safety", "毒品制作指导", "builtin.content_safety.2e7c3d1811c916b4", []string{"content_drug_manufacturing"}, "any"},
	{"content_safety", "煽动颠覆内容", "builtin.content_safety.84b78c69bd854278", []string{"content_subversion_incitement"}, "any"},
	{"content_safety", "环境污染指导", "builtin.content_safety.66f2bb762e173339", []string{"content_pollution_guidance"}, "any"},
	{"content_safety", "网络攻击教程", "builtin.content_safety.fc486a78d9176d14", []string{"content_cyberattack_tutorial"}, "any"},
	{"content_safety", "网络暴力内容", "builtin.content_safety.c529368da553e93d", []string{"content_online_mob_attack"}, "any"},
	{"content_safety", "自残/自杀内容", "builtin.content_safety.8b77e51268536ced", []string{"content_self_harm_encouragement"}, "any"},
	{"content_safety", "药品滥用指导", "builtin.content_safety.bb6ee23a359ce52e", []string{"content_prescription_abuse"}, "any"},
	{"content_safety", "虐待动物内容", "builtin.content_safety.4e2d6940ae0c8718", []string{"content_animal_abuse"}, "any"},
	{"content_safety", "虚假信息/谣言", "builtin.content_safety.948316474cf587e1", []string{"content_harmful_rumor_creation"}, "any"},
	{"content_safety", "违禁品检测", "builtin.content_safety.37e8337d76413856", []string{"content_contraband_guidance"}, "any"},
	{"content_safety", "邪教宣传内容", "builtin.content_safety.430e892402c08738", []string{"content_cult_recruitment"}, "any"},
	{"content_safety", "食品安全违规", "builtin.content_safety.9b130d27ba058baf", []string{"content_food_safety_violation"}, "any"},
	{"content_safety", "骚扰/霸凌内容", "builtin.content_safety.dc547e0b41610cca", []string{"content_harassment_bullying"}, "any"},
	{"content_safety", "辱骂脏话", "builtin.content_safety.ffbbdfb2e823022d", []string{"content_profanity_abuse", "harassment_profanity_cn"}, "any"},
	{"rag_security", "RAG 数据泄露", "builtin.rag_security.467a622e0be8d906", []string{"rag_sensitive_data_exfiltration"}, "any"},
	{"rag_security", "RAG 缓存投毒", "builtin.rag_security.74a9f1e667ced7cf", []string{"rag_cache_poisoning"}, "any"},
	{"rag_security", "向量嵌入操纵", "builtin.rag_security.13154dbf8dc32f3f", []string{"rag_embedding_manipulation"}, "any"},
	{"rag_security", "外部知识投毒", "builtin.rag_security.af8adaef83896e2d", []string{"rag_external_knowledge_poisoning"}, "any"},
	{"rag_security", "文档源欺骗", "builtin.rag_security.659584df2cd2be3d", []string{"rag_document_source_spoofing"}, "any"},
	{"rag_security", "检索上下文劫持", "builtin.rag_security.d42179890c2b8967", []string{"rag_context_hijacking"}, "any"},
	{"rag_security", "检索结果篡改", "builtin.rag_security.08b9b614ab365989", []string{"rag_result_tampering"}, "any"},
	{"rag_security", "知识库越权查询", "builtin.rag_security.0c2992f0a6665641", []string{"rag_unauthorized_knowledge_query"}, "any"},
	{"rag_security", "虚假文档引用", "builtin.rag_security.1723128d6f171f69", []string{"rag_fake_citation"}, "any"},
	{"supply_chain", "合规标签绕过", "builtin.supply_chain.91151fe7a133df12", []string{"supply_compliance_label_bypass"}, "any"},
	{"supply_chain", "影子模型使用", "builtin.supply_chain.9e3f687b97ec8ae3", []string{"supply_shadow_model_use"}, "any"},
	{"supply_chain", "恶意模型加载", "builtin.supply_chain.26bc51020d532aaf", []string{"supply_malicious_model_load"}, "any"},
	{"supply_chain", "未授权模型调用", "builtin.supply_chain.98c244cb0345cb0d", []string{"supply_unauthorized_model_call"}, "any"},
	{"supply_chain", "模型权重窃取", "builtin.supply_chain.dd2a34c2c0d63125", []string{"supply_model_weight_theft"}, "any"},
	{"supply_chain", "模型版本漏洞探测", "builtin.supply_chain.e88a49da94a0a712", []string{"supply_model_version_vulnerability_probe"}, "any"},
	{"supply_chain", "模型行为探测", "builtin.supply_chain.cc3faf3e41ecaaa8", []string{"supply_model_behavior_probe"}, "any"},
	{"supply_chain", "第三方依赖漏洞", "builtin.supply_chain.575265dc58c794c7", []string{"supply_dependency_vulnerability"}, "any"},
	{"prompt_injection", "Few-shot 攻击检测", "builtin.prompt_injection.344b93890cdccc3e", []string{"injection_few_shot_attack"}, "any"},
	{"prompt_injection", "协作借口绕过", "builtin.prompt_injection.13c78c8cb376da98", []string{"injection_collaboration_pretext"}, "any"},
	{"prompt_injection", "学术研究借口", "builtin.prompt_injection.51e37afc89cb1115", []string{"injection_academic_pretext"}, "any"},
	{"prompt_injection", "对比示例攻击", "builtin.prompt_injection.af7e6ee3195516c6", []string{"injection_comparison_pretext"}, "any"},
	{"prompt_injection", "情感操控诱导", "builtin.prompt_injection.b322a14e01c1d5d5", []string{"injection_emotional_manipulation"}, "any"},
	{"prompt_injection", "技术支持冒充", "builtin.prompt_injection.d29c0062c05c6a04", []string{"injection_tech_support_impersonation"}, "any"},
	{"prompt_injection", "排列组合注入", "builtin.prompt_injection.7730b3cbd5246f1f", []string{"injection_permutation_flood"}, "any"},
	{"prompt_injection", "术语混淆绕过", "builtin.prompt_injection.c171230d59d1a27a", []string{"injection_terminology_obfuscation"}, "any"},
	{"prompt_injection", "权威引用伪造", "builtin.prompt_injection.90324ca72fb4d87a", []string{"injection_forged_authority"}, "any"},
	{"prompt_injection", "法律威胁诱导", "builtin.prompt_injection.5ce853ec8c7904ab", []string{"injection_legal_threat"}, "any"},
	{"prompt_injection", "特权提升检测", "builtin.prompt_injection.5e084cbc6cb3c32d", []string{"injection_privilege_escalation"}, "any"},
	{"prompt_injection", "紧急语气绕过", "builtin.prompt_injection.b2a9904f92b79552", []string{"injection_urgency_coercion"}, "any"},
	{"prompt_injection", "虚假安全警报", "builtin.prompt_injection.ba1fbb4a4032dc78", []string{"injection_fake_security_alert"}, "any"},
	{"prompt_injection", "逻辑谜题绕过", "builtin.prompt_injection.8c29ec75bf9c8cc1", []string{"injection_logic_puzzle_pretext"}, "any"},
	{"prompt_injection", "道德困境诱导", "builtin.prompt_injection.a74e7f1501822fc1", []string{"injection_moral_dilemma"}, "any"},
	{"prompt_injection", "道德权威施压", "builtin.prompt_injection.4a2869c6bcc5351c", []string{"injection_moral_authority"}, "any"},
	{"agent_detect", "API 直接调用检测", "builtin.agent_detect.e2d7dcc63727dab9", []string{"agent_direct_api_call"}, "any"},
	{"agent_detect", "Session 超长检测", "builtin.agent_detect.3b83737794508b03", []string{"agent_long_session"}, "any"},
	{"agent_detect", "格式化响应提取", "builtin.agent_detect.b9cbfe2be43132d0", []string{"agent_formatted_response_extraction"}, "any"},
	{"agent_detect", "高危工具调用检测", "builtin.agent_detect.2451a4aa92aae6c4", []string{"high_risk_action"}, "any"},
	{"prompt_injection", "GIF/图像隐写注入", "builtin.prompt_injection.839171ac2965425a", []string{"injection_image_steganography"}, "any"},
	{"prompt_injection", "多模态输入注入", "builtin.prompt_injection.15004e1e3fd53f86", []string{"injection_multimodal_hidden_instruction"}, "any"},
	{"content_safety", "领导人负面讨论", "builtin.content_safety.f1252b5fafaca83a", []string{"content_leader_defamation"}, "any"},
	{"content_safety", "民族宗教问题", "builtin.content_safety.b0fa6eb641e7f1c5", []string{"content_ethnic_religious_conflict"}, "any"},

	{"prompt_leak", "系统提示提取检测", "builtin.prompt_leak.00e21ecc7d791885", []string{"keyword_system_prompt_leak_en"}, "any"},
	{"prompt_leak", "API 参数探测", "builtin.prompt_leak.c584e35e5a105858", []string{"prompt_probe_api_parameters"}, "any"},
	{"prompt_leak", "Base64 提示提取", "builtin.prompt_leak.4e51f1e57aa519c0", []string{"prompt_leak_base64"}, "any"},
	{"prompt_leak", "元指令泄露检测", "builtin.prompt_leak.4b4745b0d80aa02a", []string{"prompt_leak_meta_instructions"}, "any"},
	{"prompt_leak", "内部指令查询", "builtin.prompt_leak.2dd388f0575b616c", []string{"prompt_leak_internal_rules"}, "any"},
	{"prompt_leak", "分隔符探测攻击", "builtin.prompt_leak.ebfe1cb42be3b070", []string{"prompt_leak_delimiter_probe"}, "any"},
	{"prompt_leak", "初始指令泄露检测", "builtin.prompt_leak.67489bdeaea0573a", []string{"prompt_leak_initial_instructions"}, "any"},
	{"prompt_leak", "多语言提示提取", "builtin.prompt_leak.0fae073315d29973", []string{"prompt_leak_multilingual"}, "any"},
	{"prompt_leak", "提示词反转攻击", "builtin.prompt_leak.4fb9d9df2042df28", []string{"prompt_leak_reverse_induction"}, "any"},
	{"prompt_leak", "提示词重构攻击", "builtin.prompt_leak.0dae0c3ea88dad80", []string{"prompt_leak_reconstruction"}, "any"},
	{"prompt_leak", "格式化导出要求", "builtin.prompt_leak.81c61518cc032dbd", []string{"prompt_leak_formatted_export"}, "any"},
	{"prompt_leak", "渐进式提示提取", "builtin.prompt_leak.801e45f28d7a1758", []string{"prompt_leak_progressive"}, "any"},
	{"prompt_leak", "系统配置探测", "builtin.prompt_leak.7e8a7b334134633b", []string{"prompt_probe_system_configuration"}, "any"},
	{"prompt_leak", "编码方式提取", "builtin.prompt_leak.aa2cf7f9df399747", []string{"prompt_leak_encoded_export"}, "any"},
	{"prompt_leak", "角色反转提取", "builtin.prompt_leak.adaf812b35c328aa", []string{"prompt_leak_role_reversal"}, "any"},
	{"dos_protection", "大文件处理攻击", "builtin.dos_protection.1c7e9f9970f83177", []string{"file_oversized"}, "any"},
	{"dos_protection", "指数膨胀请求", "builtin.dos_protection.4f43236bc20250dc", []string{"dos_exponential_expansion"}, "any"},
	{"dos_protection", "无限循环指令", "builtin.dos_protection.762fbe86a6615238", []string{"dos_infinite_loop_instruction"}, "any"},
	{"dos_protection", "正则回溯攻击", "builtin.dos_protection.c49a1dd5605cb6d1", []string{"dos_regex_backtracking"}, "any"},
	{"dos_protection", "深层嵌套展开", "builtin.dos_protection.5f096e00aa599617", []string{"dos_deep_nesting"}, "any"},
	{"dos_protection", "资源耗尽指令", "builtin.dos_protection.4290e5f12c4f81a4", []string{"dos_resource_exhaustion_instruction"}, "any"},
	{"dos_protection", "超长上下文消耗", "builtin.dos_protection.26b5a56593b2a884", []string{"dos_long_context_generation"}, "any"},
	{"dos_protection", "递归函数调用", "builtin.dos_protection.6e61ea7c8d2d9a07", []string{"dos_unbounded_recursion"}, "any"},
	{"dos_protection", "递归展开攻击", "builtin.dos_protection.6f6907dfdbc2ee17", []string{"dos_recursive_expansion"}, "any"},
}

var retiredDefaultPolicyCodes = map[string]string{
	"builtin.agent_detect.53e522e6a7b8dac2":     "duplicates GitHub Copilot governance without a distinct runtime identity",
	"builtin.agent_detect.967c7b3cfd32049a":     "requires cross-request proxy identity state",
	"builtin.agent_detect.25c6ba2e41db01e3":     "requires cross-request source-to-identity correlation",
	"builtin.agent_detect.68cabce575a7dafa":     "requires a tenant geolocation baseline",
	"builtin.agent_detect.baf350658bb917ff":     "requires tenant working-hours configuration and request history",
	"builtin.agent_detect.4011bbc60f4c286d":     "requires cross-request batch correlation",
	"builtin.agent_detect.1ec9fa7c05668d6e":     "requires a trusted device fingerprint not present in the engine contract",
	"builtin.agent_detect.6bb38a327f4ddadd":     "belongs to gateway rate-limit enforcement",
	"builtin.content_safety.3cc66da68952eebe":   "requires a tenant-maintained sensitive person and organization dictionary",
	"builtin.dos_protection.1d26c44f7b71efac":   "belongs to gateway concurrency enforcement",
	"builtin.dos_protection.e669fe2aeef676da":   "requires cross-request request-digest state",
	"builtin.prompt_injection.c2bd08c27cf70ea1": "requires conversation-level multi-turn state",
	"builtin.prompt_injection.f45dc17b1e6725b7": "a low-resource language alone does not prove injection intent",
	"builtin.prompt_injection.cbadb8fba1cbd3ce": "mixed language alone does not prove injection intent",
	"builtin.prompt_injection.69e7baa759b6c503": "requires conversation-level progressive-intent state",
}

func isRetiredDefaultPolicy(policyCode string) bool {
	_, retired := retiredDefaultPolicyCodes[policyCode]
	return retired
}

// defaultPolicyCode is a compatibility lookup for callers that start from the
// current display name. Seeding and capability binding use the literal code on
// each policy definition and never derive identity from this lookup.
func defaultPolicyCode(ruleType, canonicalName string) string {
	for _, policy := range defaultSubRules[ruleType] {
		if policy.Name == canonicalName {
			return policy.PolicyCode
		}
	}
	return ""
}

func exactCapabilityBindingForPolicy(policyCode string) (policyCapabilityBindingSeed, bool) {
	for _, binding := range exactPolicyCapabilityBindings {
		if binding.PolicyCode == policyCode {
			return binding, true
		}
	}
	return policyCapabilityBindingSeed{}, false
}

// DefaultPolicyCapabilityCategories returns the stable capability dependencies
// required when seeding a new tenant's built-in policy catalog.
func DefaultPolicyCapabilityCategories() []string {
	seen := make(map[string]struct{})
	for _, binding := range exactPolicyCapabilityBindings {
		for _, category := range binding.CapabilityCategories {
			seen[category] = struct{}{}
		}
	}
	categories := make([]string, 0, len(seen))
	for category := range seen {
		categories = append(categories, category)
	}
	sort.Strings(categories)
	return categories
}

// DefaultPolicyExactBindingCount is the number of shipped policies with an
// independently attributable capability binding.
func DefaultPolicyExactBindingCount() int {
	return len(exactPolicyCapabilityBindings)
}

// DefaultPolicyCapabilityBindingCount counts policy-to-capability edges. It is
// intentionally larger than the policy count when one policy has alternatives.
func DefaultPolicyCapabilityBindingCount() int {
	count := 0
	for _, binding := range exactPolicyCapabilityBindings {
		count += len(binding.CapabilityCategories)
	}
	return count
}

// DefaultRuntimePolicyContracts returns a defensive copy of the audited,
// executable built-in policy contracts. Management-only catalog entries are
// intentionally excluded until they have an independently attributable detector.
func DefaultRuntimePolicyContracts() []DefaultRuntimePolicyContract {
	contracts := make([]DefaultRuntimePolicyContract, 0, len(exactPolicyCapabilityBindings))
	for _, binding := range exactPolicyCapabilityBindings {
		action := ""
		for _, policy := range defaultSubRules[binding.RuleType] {
			if policy.PolicyCode == binding.PolicyCode {
				action = policy.Action
				break
			}
		}
		contracts = append(contracts, DefaultRuntimePolicyContract{
			RuleType: binding.RuleType, Name: binding.Name, PolicyCode: binding.PolicyCode,
			Action: action, CapabilityCategories: append([]string(nil), binding.CapabilityCategories...),
			BindingMode: binding.BindingMode,
		})
	}
	sort.Slice(contracts, func(i, j int) bool {
		return contracts[i].PolicyCode < contracts[j].PolicyCode
	})
	return contracts
}
