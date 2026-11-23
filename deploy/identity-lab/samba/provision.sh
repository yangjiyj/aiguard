#!/usr/bin/env bash
# Samba AD provisioning — identity-lab（仅隔离测试，不可用于生产）
# 在 nowsci/samba-domain 容器首次启动后由 ProvisionStep 调用，
# 创建：1 个独立域用户、1 个禁用用户、2 个组（迁移源/目标），
# 与 OpenLDAP 用户主体不重叠（验收点：AD 用户走 account-login 而非冒充 LDAP 用户）。
#
# 真实 DomainPass 由 deploy/identity-lab/.env.example 注入（绝不入库）。
# 本脚本只做容器内幂等 ProvisionStep：用户/组已存在则跳过。
set -eu

# 域管理员 DN 由 nowsci/samba-domain 提供；密码从环境变量取，不硬编码。
ADMIN_PASS=${SMB_DOMAIN_PASS:?SMB_DOMAIN_PASS required (from .env.example)}
AD_BOB_PASSWORD=${AD_BOB_PASSWORD:?AD_BOB_PASSWORD required (from Compose env)}
AD_DISABLED_PASSWORD=${AD_DISABLED_PASSWORD:?AD_DISABLED_PASSWORD required (from Compose env)}
DOMAIN_DN=${SMB_DOMAIN_DN:-DC=ad,DC=jjdguard-lab,DC=test}
DOMAIN=${SMB_DOMAIN_NAME:-ad.jjdguard-lab.test}

# samba-tool 在容器内 /usr/bin/samba-tool；以域管理员身份做幂等操作。
SAMBATOOL=(samba-tool)

# 1. 在职用户 ad-bob（运维部，映射 lab-ops-model；与 LDAP 独立）。
if ! "${SAMBATOOL[@]}" user list 2>/dev/null | grep -qx ad-bob; then
  "${SAMBATOOL[@]}" user create ad-bob "$AD_BOB_PASSWORD" \
    --given-name=AD --surname=Bob \
    --mail-address=ad-bob@ad.jjdguard-lab.test
fi

# Expose a controlled department attribute for the AD federation mapper.
AD_BOB_DN="CN=AD Bob,CN=Users,$DOMAIN_DN"
if ! ldbsearch -H /var/lib/samba/private/sam.ldb -b "$AD_BOB_DN" -s base department 2>/dev/null | grep -Fxq 'department: operations'; then
  ldbmodify -H /var/lib/samba/private/sam.ldb <<EOF
dn: $AD_BOB_DN
changetype: modify
replace: department
department: operations
EOF
fi

# 2. 禁用用户 ad-disabled（验收点 9：禁用目录用户登录失败）。
if ! "${SAMBATOOL[@]}" user list 2>/dev/null | grep -qx ad-disabled; then
  "${SAMBATOOL[@]}" user create ad-disabled "$AD_DISABLED_PASSWORD" \
    --given-name=AD --surname=Disabled \
    --mail-address=ad-disabled@ad.jjdguard-lab.test
  "${SAMBATOOL[@]}" user disable ad-disabled
fi

# 3. 组 dept-research-ad（迁移源，对应 lab-research-model）。
if ! "${SAMBATOOL[@]}" group list 2>/dev/null | grep -qx dept-research-ad; then
  "${SAMBATOOL[@]}" group add dept-research-ad
  "${SAMBATOOL[@]}" group addmembers dept-research-ad ad-bob
fi

# 4. 组 dept-marketing-ad（迁移目标，对应 lab-marketing-model；验证旧权限撤销）。
if ! "${SAMBATOOL[@]}" group list 2>/dev/null | grep -qx dept-marketing-ad; then
  "${SAMBATOOL[@]}" group add dept-marketing-ad
fi

echo "Samba AD provisioning complete: domain=${DOMAIN}"
