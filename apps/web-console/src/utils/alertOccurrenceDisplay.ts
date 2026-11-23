import { getRiskCategoryLabel } from './risk'

// The general risk dictionary deliberately groups data classes for overview
// charts. An individual finding must retain the specific kind of data/risk.
const FINDING_CATEGORY_LABELS: Record<string, string> = {
  plain_password: '疑似明文密码', code_leak_password_in_code: '代码中的凭据候选', code_leak_database_url: '含凭据的连接串候选',
  pii_email: '邮箱地址', pii_phone: '手机号', pii_idcard: '身份证号', pii_id_card: '身份证号',
  pii_bankcard: '银行卡号', pii_passport: '护照号码',
  aws_secret_key: 'AWS Secret Key 泄露', aws_access_key: 'AWS Access Key 泄露',
  github_token: 'GitHub Token 泄露', openai_key: '疑似 OpenAI 密钥',
  jwt_token: 'JWT 令牌泄露', ssh_private_key: 'SSH 私钥泄露', generic_api_key: 'API 密钥泄露',
  config_file: '配置文件外泄', env_file: '环境变量文件外泄',
  medical_record_id: '病历 / 就诊号码', medical_insurance_id: '医保号码',
  medical_dicom_accession: '医学影像检查号', medical_dicom_uid: '医学影像标识',
  medical_diagnosis: '医疗诊断信息', medical_device_serial: '医疗设备序列号',
  finance_account: '金融账户', finance_txn: '金融交易信息', finance_uscc: '统一社会信用代码',
}

export const getFindingCategoryLabel = (category?: string) => {
  if (!category || category === 'unknown') return '未分类'
  if (FINDING_CATEGORY_LABELS[category]) return FINDING_CATEGORY_LABELS[category]
  const label = getRiskCategoryLabel(category)
  return label === '其他风险' ? `其他风险（${category}）` : label
}

export const credentialAssessment = (item: {
  category: string; validation_status?: string; credential_validity?: string;
  model_review_status?: string; confidence_kind?: string; risk_basis?: string;
}) => {
  const credentials = item.category.startsWith('code_leak_') || ['plain_password','openai_key','anthropic_key','generic_api_key','github_token','aws_access_key','aws_secret_key','jwt_token'].includes(item.category)
  if (!credentials) return null
  const validation = item.validation_status === 'literal_candidate' ? '已提取字面值，待核验' : item.validation_status === 'format_match' ? '符合凭据格式，待核验' : '历史规则命中，未记录值验证状态'
  const review = item.model_review_status === 'completed' ? '已记录模型复核，请核对意见' : item.model_review_status === 'incomplete' ? '模型复核未完成' : item.model_review_status === 'not_requested' ? '未进行模型复核' : '未记录模型复核状态'
  return { validation, review, validity: item.credential_validity === 'valid' ? '已验证有效' : '未验证凭据有效性', confidence: item.confidence_kind === 'heuristic_rule_score' ? '规则评分，不是泄露概率' : '未记录评分依据' }
}
