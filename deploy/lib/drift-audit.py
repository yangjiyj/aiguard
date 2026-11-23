#!/usr/bin/env python3
"""drift-audit — 比对"正在运行的部署" vs "离线包应产出的东西",照出移植掉队。

四维:①镜像(运行容器image vs :latest;latest vs 源码git改动日期)②ENV(容器env名 vs 离线compose声明,
找"运行态有、包没声明"的危险漏配)③迁移(schema_migrations vs migrations文件)④服务集。
发现结构性漂移 → 退出码 2(可当发货前门禁)。纯只读。

用法: python3 deploy/lib/drift-audit.py
PROJECT 默认自动探测:离线包装出来的部署,compose 项目名是包目录名
(如 jjdguard-2.1-offline-full-chat-amd64-20260814-000211),不是 docker-compose。
写死默认值会让 [C]/[D] 在每个客户现场都误报"8 个服务没在跑、库读不到",
假红比不报更坏——它教人无视门禁。所以按 compose 标签挑命中服务最多的项目。
环境变量(PROJECT 可覆盖探测结果): PROJECT=<compose项目名>  OFFLINE_COMPOSE=deploy/docker-compose/docker-compose.offline.yml
  MIGRATIONS_DIR=deploy/migrations  PG_CONTAINER=<PROJECT>-postgres-1  PG_DB=newapi  PG_USER=newapi
宿主无psql时本工具自动走 docker exec 进 PG_CONTAINER 查库(规避"默认5432误打他库"的雷)。
"""
import json, os, re, subprocess, glob, sys

def sh(c):
    return subprocess.run(c, shell=True, capture_output=True, text=True).stdout.strip()

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
OFFLINE = os.environ.get("OFFLINE_COMPOSE", os.path.join(ROOT, "deploy/docker-compose/docker-compose.offline.yml"))
MIGR = os.environ.get("MIGRATIONS_DIR", os.path.join(ROOT, "deploy/migrations"))

try:
    import yaml
except ImportError:
    print("[fatal] 需要 python3-yaml (pip install pyyaml 或 apt install python3-yaml)", file=sys.stderr)
    sys.exit(3)

if not os.path.exists(OFFLINE):
    print(f"[fatal] 离线compose不存在: {OFFLINE}", file=sys.stderr); sys.exit(3)
off = yaml.safe_load(open(OFFLINE)).get("services", {})
# profile-gated 服务未激活时不算"包有未跑"（chat/full 是可选维度，非漂移）
PROFILED = {svc for svc, sdef in off.items() if (sdef or {}).get("profiles")}


def detect_project(candidate_services):
    """按 compose 标签挑"命中离线包服务最多"的项目名。

    只认 com.docker.compose.project/service 标签,不靠容器名猜——包目录名里
    有连字符,靠 f"{PROJECT}-{svc}-1" 反推会在名字里含连字符的服务上错切。
    探测不到时回退 docker-compose(旧默认),让本机源码树直起的部署仍能用。
    """
    fmt = '{{.Label "com.docker.compose.project"}}\x1f{{.Label "com.docker.compose.service"}}'
    tally = {}
    for line in sh("docker ps --format '%s'" % fmt).splitlines():
        parts = line.split("\x1f")
        if len(parts) != 2:
            continue
        proj, svc = parts[0].strip(), parts[1].strip()
        if not proj or svc not in candidate_services:
            continue
        tally[proj] = tally.get(proj, 0) + 1
    if not tally:
        return "docker-compose"
    # 命中数相同时按名字排序,保证可复现(不能依赖 docker ps 的顺序)
    return sorted(tally.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]


PROJECT = os.environ.get("PROJECT") or detect_project(set(off))
PG_CONTAINER = os.environ.get("PG_CONTAINER") or f"{PROJECT}-postgres-1"


def detect_pg_credentials(container):
    """从 postgres 容器自身的 POSTGRES_USER/DB 取凭据。

    写死 newapi/newapi 会让 [C] 在任何按离线包装的部署上恒报"库读不到"
    (那里是 jjdguard/jjdguard)。凭据的唯一真源是容器自己。
    """
    user = db_name = ""
    for line in sh("docker exec %s env" % container).splitlines():
        if line.startswith("POSTGRES_USER="):
            user = line.split("=", 1)[1].strip()
        elif line.startswith("POSTGRES_DB="):
            db_name = line.split("=", 1)[1].strip()
    return user, db_name


_det_user, _det_db = detect_pg_credentials(PG_CONTAINER)
PG_USER = os.environ.get("PG_USER") or _det_user or "newapi"
PG_DB = os.environ.get("PG_DB") or _det_db or "newapi"

NOISE = {"PATH","HOSTNAME","HOME","TERM","LANG","LC_ALL","GOTRACEBACK","GODEBUG","SSL_CERT_DIR",
"SSL_CERT_FILE","PWD","SHLVL","container","GPG_KEY","PYTHON_VERSION","PYTHON_SHA256","NODE_VERSION","YARN_VERSION"}
# 第三方镜像的基础服务：不走 {PROJECT}-{svc}:latest 镜像对账，也不做 ENV 对账。
INFRA = {"postgres","redis","redis-cache"}

# 运行中容器 svc->name
running = {}
_fmt = ('{{.Label "com.docker.compose.project"}}\x1f'
        '{{.Label "com.docker.compose.service"}}\x1f{{.Names}}')
for line in sh("docker ps --format '%s'" % _fmt).splitlines():
    _parts = line.split("\x1f")
    if len(_parts) != 3:
        continue
    _proj, _svc, _name = (x.strip() for x in _parts)
    if _proj == PROJECT and _svc in off:
        running[_svc] = _name

def db(q):
    return sh(f'docker exec {PG_CONTAINER} psql -U {PG_USER} -d {PG_DB} -tAc "{q}"')

def env_container(name):
    try: arr = json.loads(sh(f'docker inspect {name} --format "{{{{json .Config.Env}}}}"'))
    except Exception: return set()
    return {e.split("=",1)[0] for e in arr}

def _bootstrap_declared_keys(env_basename):
    """从引导脚本里枚举它会写进该 env 文件的变量名。

    只认 `printf 'KEY=` 这种字面声明,不执行脚本、不读任何真实凭据值。
    找不到对应引导脚本时返回空集,让 [B] 照常报——宁可多报一次,
    不能让"文件不在"变成永久免检。
    """
    boot_dir = os.path.join(os.path.dirname(OFFLINE), "chat")
    if not os.path.isdir(boot_dir):
        return set()
    keys = set()
    for name in sorted(os.listdir(boot_dir)):
        if not name.startswith("bootstrap-") or not name.endswith(".sh"):
            continue
        try:
            text = open(os.path.join(boot_dir, name), encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        # 脚本必须确实写这个 env 文件,才把它声明的键算进来
        if env_basename not in text:
            continue
        keys |= set(re.findall(r"""printf ['"]([A-Z][A-Z0-9_]*)=""", text))
    return keys


def _env_file_keys(spec):
    """读 env_file 里声明的变量名。

    compose 的 env_file 支持三种写法:字符串、字符串数组、{path,required} 数组。
    只要文件在,里面的变量对客户就是"包声明过"的。
    """
    if not spec:
        return set()
    entries = spec if isinstance(spec, list) else [spec]
    keys = set()
    for entry in entries:
        path = entry.get("path") if isinstance(entry, dict) else entry
        if not isinstance(path, str):
            continue
        full = path if os.path.isabs(path) else os.path.join(os.path.dirname(OFFLINE), path)
        if not os.path.isfile(full):
            # 这个文件是部署时由引导脚本生成的(0600、含 secret,本就不该入库),
            # 源码树里没有。不能因此当"没声明"——那会把根因 4 的正确修法
            # (删空覆盖、让 env_file 说话)误报成漂移,照着改就把 bug 装回包里。
            # 也不能直接跳过(等于永不检查),所以回退去引导脚本里静态枚举键名。
            keys |= _bootstrap_declared_keys(os.path.basename(full))
            continue
        try:
            text = open(full, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            name = line.split("=", 1)[0].strip()
            # 不能用 lstrip("export"):那是按字符集剥,会把 PORT_X 剥成 _X。
            if name.startswith("export "):
                name = name[len("export "):].strip()
            keys.add(name)
    return keys


def env_offline(svc):
    sdef = off.get(svc, {}) or {}
    out = set()
    for e in (sdef.get("environment") or []):
        if isinstance(e, str): out.add(e.split("=",1)[0])
        elif isinstance(e, dict): out.update(e.keys())
    # env_file 与 environment 同为"包声明过"。漏掉它会把根因 4 的正确修法
    # (删空覆盖、交给 0600 env 文件)误报成漂移。
    out |= _env_file_keys(sdef.get("env_file"))
    return out


def env_image(svc):
    """镜像基底自带的 ENV(Dockerfile/上游基础镜像),不是部署配置。

    PGDATA/PG_MAJOR/CADDY_VERSION/NODE_ENV/LD_LIBRARY_PATH 这类随镜像走,
    客户装包时一定拿得到,报成"包没声明"纯属噪声。
    """
    image = sh('docker inspect %s --format "{{.Config.Image}}"' % running.get(svc, ""))
    if not image:
        return set()
    try:
        arr = json.loads(sh('docker inspect %s --format "{{json .Config.Env}}"' % image))
    except Exception:
        return set()
    return {e.split("=", 1)[0] for e in arr if isinstance(e, str) and "=" in e}

drift = []  # 结构性漂移(致命) ; warn = 提示
warn = []

print("================ drift-audit · 运行部署 vs 离线包 ================")
print(f"project={PROJECT}  offline={os.path.relpath(OFFLINE, ROOT)}  pg={PG_CONTAINER}\n")

print("[A] 镜像漂移")
for svc in off:
    if svc in INFRA or svc not in running: continue
    runid = sh(f'docker inspect {running[svc]} --format "{{{{.Image}}}}"')[:19]
    latest = sh(f'docker inspect {PROJECT}-{svc}:latest --format "{{{{.Id}}}}"')[:19]
    lcreated = sh(f'docker inspect {PROJECT}-{svc}:latest --format "{{{{.Created}}}}"')[:10]
    srcdate = sh(f'cd {ROOT} && git log -1 --format="%ci" -- apps/{svc} 2>/dev/null')[:10]
    if latest and runid != latest:
        drift.append(f"{svc}: 运行镜像≠latest(在跑旧代码 {runid} vs {latest})")
        print(f"  !! {svc:16} 跑{runid} ≠ latest{latest}")
    else:
        print(f"  ok {svc:16} 运行==latest({runid})")
    if srcdate and lcreated and srcdate > lcreated:
        warn.append(f"{svc}: latest({lcreated})比源码({srcdate})旧,下次build行为会变")
        print(f"     ~ latest建于{lcreated} 源码末改{srcdate}(latest比源码旧)")

print("\n[B] ENV漂移(运行容器有、离线包没声明 = 客户拿不到)")
hit_b = False
for svc in off:
    if svc in INFRA or svc not in running: continue
    miss = sorted(env_container(running[svc]) - env_offline(svc) - NOISE - env_image(svc))
    if miss:
        hit_b = True
        drift.append(f"{svc}: ENV运行态有但离线包没声明: {','.join(miss)}")
        print(f"  !! [{svc}] {', '.join(miss)}")
if not hit_b: print("  ok 运行态所有env离线包都声明了")

print("\n[C] 迁移漂移(schema_migrations vs 文件)")
hmax = db("SELECT max(version) FROM schema_migrations")
files = sorted(os.path.basename(f) for f in glob.glob(os.path.join(MIGR, "[0-9]*.sql")) if "_verify" not in f)
fmax = files[-1] if files else ""
print(f"  库已应用最高: {hmax or '(读不到)'}")
print(f"  源码文件最高: {fmax}")
if hmax and fmax and fmax > hmax:
    behind = [f for f in files if f > hmax]
    drift.append(f"迁移落后: 库到{hmax},源码到{fmax},缺 {len(behind)} 个: {','.join(behind)}")
    print(f"  !! 缺 {len(behind)} 个未应用: {', '.join(behind)}")
elif hmax:
    print("  ok 库迁移对齐源码")

print("\n[D] 服务集漂移")
off_s, run_s = set(off), set(running)
only_off = sorted((off_s - run_s) - PROFILED); only_run = sorted(run_s - off_s)
if only_off: drift.append(f"离线包声明但没在跑: {','.join(only_off)}"); print(f"  !! 包有未跑: {', '.join(only_off)}")
if only_run: drift.append(f"在跑但离线包没声明: {','.join(only_run)}"); print(f"  !! 跑了包没有: {', '.join(only_run)}")
if not only_off and not only_run: print("  ok 服务集一致")

print("\n[E] 镜像清单单一源(images.lst)")
DC_DIR = os.path.dirname(OFFLINE)
_lst = os.path.join(DC_DIR, "images.lst")
if not os.path.isfile(_lst):
    drift.append("images.lst 缺失(镜像清单单一真源没了)"); print("  !! images.lst 不存在")
else:
    _bad = []
    for _cons in ("package-offline-bundle.sh", "export-offline-images.sh"):
        try:
            _txt = open(os.path.join(DC_DIR, _cons), encoding="utf-8").read()
        except OSError:
            _bad.append(f"{_cons}(读不到)"); continue
        if "read_images_for_profile" not in _txt:
            _bad.append(f"{_cons}(未 source images.lst,疑回退硬编码)")
    if _bad:
        drift.append("镜像清单消费方漂移: " + ", ".join(_bad)); print("  !! " + ", ".join(_bad))
    else:
        print("  ok 打包/导出脚本都 source images.lst,无硬编码回退")

print("\n================ 结论 ================")
for w in warn: print(f"  ~ 提示: {w}")
if drift:
    print(f"\n  ❌ 发现 {len(drift)} 处结构性漂移(会导致'home好/客户坏'):")
    for d in drift: print(f"     - {d}")
    print("\n  → 修齐后再发货。退出码 2。")
    sys.exit(2)
print("\n  ✅ 无结构性漂移 —— 运行部署与离线包对齐,没掉队。")
sys.exit(0)
