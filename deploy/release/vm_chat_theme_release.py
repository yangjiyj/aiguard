#!/usr/bin/env python3
"""Publish frozen login theme files through the existing managed VM transaction."""
import argparse, base64, contextlib, hashlib, io, ipaddress, json, os, re, stat, tarfile, time, urllib.request
from pathlib import Path
import vm_development_apply as vm

THEME_FILES = (
    'login/theme.properties', 'login/resources/css/jjdguard-portal-20261005.css',
    'login/resources/img/jjdguard-logo-portal-20261005.svg',
    'login/messages/messages_en.properties', 'login/messages/messages_zh_CN.properties',
)
THEME_PATH = 'deploy/docker-compose/chat/keycloak-themes/jjdguard'
MEDIA_FILES = ('manifest.json', 'theme.tar', 'vm_development_apply.py', 'vm_chat_theme_release.py')
MAX_THEME_BYTES = 2 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def object_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def validate_manifest(manifest):
    allowed = {'schema', 'purpose', 'chat_theme_only', 'release_id', 'revision', 'tree', 'version',
               'created_at', 'services', 'migrations', 'theme_files', 'source_archive_sha256',
               'theme_archive_sha256', 'apply_script_sha256', 'theme_script_sha256'}
    require(set(manifest) <= allowed and manifest.get('schema') == 1 and
            manifest.get('purpose') == 'chat-theme-only' and manifest.get('chat_theme_only') is True,
            'invalid chat theme release scope')
    require(manifest.get('services') == {} and manifest.get('migrations') == {},
            'chat theme release cannot carry images or migrations')
    require(re.fullmatch(r'dev-[A-Za-z0-9-]+', manifest.get('release_id', '')),
            'invalid theme release identity')
    for field in ('revision', 'tree'):
        require(re.fullmatch(r'[0-9a-f]{40}', manifest.get(field, '')), 'invalid theme source '+field)
    for field in ('source_archive_sha256', 'theme_archive_sha256', 'apply_script_sha256', 'theme_script_sha256'):
        require(re.fullmatch(r'[0-9a-f]{64}', manifest.get(field, '')), 'invalid theme checksum '+field)
    files = manifest.get('theme_files')
    require(isinstance(files, dict) and set(files) == set(THEME_FILES) and
            all(re.fullmatch(r'[0-9a-f]{64}', value) for value in files.values()),
            'theme scope must contain exactly the reviewed login assets and messages')


def read_theme_archive(content, expected):
    require(len(content) <= MAX_THEME_BYTES, 'theme archive exceeds size limit')
    result = {}
    with tarfile.open(fileobj=io.BytesIO(content)) as archive:
        for entry in archive:
            require(entry.name in expected and entry.name not in result and entry.isfile() and
                    0 <= entry.size <= MAX_THEME_BYTES, 'unreviewed or unsafe theme archive entry')
            value = archive.extractfile(entry).read()
            require(sum(map(len, result.values()))+len(value) <= MAX_THEME_BYTES,
                    'theme contents exceed size limit')
            require(hashlib.sha256(value).hexdigest() == expected[entry.name], 'theme file checksum differs')
            result[entry.name] = value
    require(set(result) == set(expected) == set(THEME_FILES), 'theme archive is incomplete')
    styles = re.findall(rb'^styles[ \t]*=[ \t]*(.*)$', result['login/theme.properties'], re.MULTILINE)
    require(styles == [b'css/styles.css css/jjdguard-portal-20261005.css?v=portal-20261005'],
            'theme stylesheet must reference the frozen versioned resource')
    urls = re.findall(rb'url\(([^)]*)\)', result['login/resources/css/jjdguard-portal-20261005.css'])
    require(urls == [b'"../img/jjdguard-logo-portal-20261005.svg?v=portal-20261005"'],
            'theme logo must reference the frozen versioned resource')
    return result


def build_theme_media(source, media, manifest):
    root = source/THEME_PATH
    files = {p.relative_to(root).as_posix(): p for p in (root/'login').rglob('*') if p.is_file()}
    require(set(files) == set(THEME_FILES) and not any(p.is_symlink() for p in root.rglob('*')),
            'source login theme scope differs')
    media.mkdir()
    hashes = {name: vm.digest(path) for name, path in sorted(files.items())}
    with tarfile.open(media/'theme.tar', 'w') as archive:
        for name, path in sorted(files.items()):
            value = path.read_bytes()
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode = len(value), 0o644
            archive.addfile(entry, io.BytesIO(value))
    for name, field in (('vm_development_apply.py', 'apply_script_sha256'),
                        ('vm_chat_theme_release.py', 'theme_script_sha256')):
        (media/name).write_bytes((source/'deploy/release'/name).read_bytes())
        manifest[field] = vm.digest(media/name)
    manifest.update(theme_files=hashes, theme_archive_sha256=vm.digest(media/'theme.tar'))
    validate_manifest(manifest)
    read_theme_archive((media/'theme.tar').read_bytes(), hashes)
    (media/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')


def validate_idp_mount(row, installed):
    labels = row.get('Config', {}).get('Labels') or {}
    workdir = installed/'deploy/docker-compose'
    require(labels.get('com.docker.compose.service') == 'chat-idp' and
            labels.get('com.docker.compose.project.working_dir') == str(workdir),
            'IDP is not bound to the authenticated installation')
    target = workdir/'chat/keycloak-themes/jjdguard'
    matches = [item for item in row.get('Mounts', []) if item.get('Destination') == '/opt/keycloak/themes/jjdguard']
    require(len(matches) == 1 and matches[0].get('Type') == 'bind' and
            matches[0].get('RW') is False and matches[0].get('Source') == str(target),
            'IDP theme must be the authenticated read-only installation bind')
    return target


def readiness_url(row, address):
    ipaddress.IPv4Address(address)
    values = {}
    for item in row.get('Config', {}).get('Env') or []:
        name, separator, value = item.partition('=')
        if separator and name in ('KC_HTTP_RELATIVE_PATH', 'KC_HTTP_PORT'):
            require(name not in values, 'duplicate IDP HTTP setting')
            values[name] = value
    arguments = row.get('Args')
    arguments = [] if arguments is None else arguments
    require(isinstance(arguments, list) and all(isinstance(item, str) for item in arguments),
            'invalid IDP CLI arguments')
    options = {'--http-relative-path': 'KC_HTTP_RELATIVE_PATH', '--http-port': 'KC_HTTP_PORT'}
    cli_values = {}
    iterator = iter(arguments)
    for argument in iterator:
        option, separator, value = argument.partition('=')
        if option not in options:
            continue
        name = options[option]
        require(name not in cli_values, 'duplicate IDP CLI HTTP setting')
        if not separator:
            value = next(iterator, None)
            require(value is not None and not value.startswith('-'), 'missing IDP CLI HTTP value')
        cli_values[name] = value
    values.update(cli_values)
    prefix = values.get('KC_HTTP_RELATIVE_PATH', '/')
    port = values.get('KC_HTTP_PORT', '8080')
    require(re.fullmatch(r'/(?:[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*/?)?', prefix), 'invalid IDP HTTP relative path')
    require(re.fullmatch(r'[0-9]{1,5}', port) and 1 <= int(port) <= 65535, 'invalid IDP HTTP port')
    return 'http://'+address+':'+port+prefix.rstrip('/')+'/realms/master/.well-known/openid-configuration'


def inspect_all():
    ids = vm.run(['docker', 'ps', '-aq']).split()
    require(ids, 'runtime inventory is empty')
    return json.loads(vm.run(['docker', 'inspect', *ids]))


def fingerprint(row):
    result = vm.safe_identity({'idp': row})['idp']
    stable = {key: row.get(key) for key in ('Config', 'HostConfig', 'Mounts', 'Name', 'Path', 'Args')}
    # Docker inspect does not guarantee mount order; retain every mount field.
    stable['Mounts'] = sorted(row.get('Mounts') or [], key=object_hash)
    result['config_sha256'] = object_hash(stable)
    return result


@contextlib.contextmanager
def installation_identity(installed):
    info = installed.stat()
    owner = (info.st_uid, info.st_gid)
    require(owner == (0, 0) or vm.INSTALL_OWNER.get() == owner,
            'theme installation owner is not authenticated')
    old = (os.geteuid(), os.getegid())
    require(old[0] == 0 or old == owner, 'theme publisher cannot use the installation owner')
    changed = old != owner
    old_mask = None
    try:
        if changed:
            os.setegid(owner[1])
            os.seteuid(owner[0])
        old_mask = os.umask(0)
        yield owner
    finally:
        if old_mask is not None:
            os.umask(old_mask)
        if changed:
            os.seteuid(old[0])
            os.setegid(old[1])


def metadata(path):
    info = path.lstat()
    return dict(uid=info.st_uid, gid=info.st_gid, mode=stat.S_IMODE(info.st_mode))


def tree_snapshot(root, installed):
    result = {'files': {}, 'directories': {}, 'mount_inode': list(vm.fd_identity(root.lstat())[:2])}
    with installation_identity(installed) as owner:
        for path in [root, *sorted(root.rglob('*'))]:
            info = path.lstat()
            require(not path.is_symlink() and (info.st_uid, info.st_gid) == owner,
                    'theme entry owner or type differs')
            name = path.relative_to(root).as_posix()
            entry = metadata(path)
            if path.is_dir():
                with vm.safe_parent(path/'authenticated-child'):
                    pass
                result['directories'][name] = entry
            else:
                require(path.is_file(), 'unsupported theme entry')
                value = vm.safe_read(path)
                entry.update(sha256=hashlib.sha256(value).hexdigest(), content=base64.b64encode(value).decode())
                result['files'][name] = entry
    return result


def ensure_directory(path, owner):
    with vm.safe_parent(path) as (parent, name, verify):
        os.mkdir(name, 0o755, dir_fd=parent)
        descriptor = os.open(name, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW, dir_fd=parent)
        try:
            info = os.fstat(descriptor)
            require((info.st_uid, info.st_gid) == owner and stat.S_IMODE(info.st_mode) == 0o755,
                    'new theme directory identity differs')
            verify(); os.fsync(parent)
        finally:
            os.close(descriptor)


class ThemeRelease:
    def __init__(self, media, manifest_sha):
        self.media = Path(media)
        require(self.media.parent == vm.ROOT/'development-releases', 'theme media escapes managed releases')
        require(re.fullmatch(r'[0-9a-f]{64}', manifest_sha), 'invalid manifest pin')
        self.manifest_sha = manifest_sha
        self.verify_media()
        self.state = self.media/'state'
        self.pointer = vm.ROOT/'development-releases/active-chat-theme.json'

    def verify_media(self):
        require(not self.media.is_symlink() and self.media.is_dir(), 'unsafe theme media directory')
        require(set(p.name for p in self.media.iterdir()) <= set(MEDIA_FILES)|{'state', 'receipt.json', 'rollback-receipt.json'},
                'unrecorded theme executable or media entry')
        data = vm.safe_read(self.media/'manifest.json')
        require(hashlib.sha256(data).hexdigest() == self.manifest_sha, 'theme manifest pin differs')
        self.manifest = json.loads(data)
        validate_manifest(self.manifest)
        require(self.media.name == self.manifest['release_id'], 'theme media identity differs')
        for name, field in (('vm_development_apply.py', 'apply_script_sha256'),
                            ('vm_chat_theme_release.py', 'theme_script_sha256'), ('theme.tar', 'theme_archive_sha256')):
            require(hashlib.sha256(vm.safe_read(self.media/name)).hexdigest() == self.manifest[field],
                    'frozen theme media differs: '+name)
        self.assets = read_theme_archive(vm.safe_read(self.media/'theme.tar'), self.manifest['theme_files'])

    def context(self):
        current = vm.ROOT/'current'
        installed = current.resolve(strict=True)
        require(current.is_symlink() and installed.parent == vm.ROOT/'releases' and
                current.lstat().st_uid in {0, installed.stat().st_uid}, 'installation pointer differs')
        rows = inspect_all()
        matches = [row for row in rows if (row.get('Config', {}).get('Labels') or {}).get('com.docker.compose.service') == 'chat-idp']
        require(len(matches) == 1, 'runtime must have exactly one chat IDP')
        row = matches[0]
        root = validate_idp_mount(row, installed)
        require(re.fullmatch(r'[0-9a-f]{64}', row['Id']) and row['State']['Status'] == 'running', 'IDP baseline is not running')
        require(row['Config'].get('User', '').split(':')[0] == str(installed.stat().st_uid),
                'IDP theme reader does not match installation owner')
        readiness_url(row, '127.0.0.1')
        others = {}
        for item in rows:
            if item['Id'] != row['Id']:
                others[item['Id']] = dict(fingerprint(item), network_sha256=object_hash(item.get('NetworkSettings')))
        return installed, root, row, others

    def stage(self):
        self.verify_media()
        require(not (self.media/'receipt.json').exists(), 'theme release already applied')
        installed, root, row, others = self.context()
        before = tree_snapshot(root, installed)
        vm.safe_mkdir(self.state)
        pointer = vm.safe_read(self.pointer) if self.pointer.exists() else None
        record = dict(manifest_sha256=self.manifest_sha, installed=str(installed), root=str(root),
                      before=before, idp=fingerprint(row), non_targets=others,
                      previous_pointer=base64.b64encode(pointer).decode() if pointer else None)
        vm.write_json(self.state/'before.json', record)
        vm.write_json(self.state/'stage.json', dict(before_sha256=vm.digest(self.state/'before.json'),
                                                  manifest_sha256=self.manifest_sha))
        print('CHAT_THEME_STAGE_SHA256='+vm.digest(self.state/'before.json'), flush=True)

    def original(self):
        binding = json.loads(vm.safe_read(self.state/'stage.json'))
        require(binding == dict(before_sha256=vm.digest(self.state/'before.json'), manifest_sha256=self.manifest_sha),
                'theme stage evidence changed')
        record = json.loads(vm.safe_read(self.state/'before.json'))
        require(record.get('manifest_sha256') == self.manifest_sha, 'theme stage is from another manifest')
        return record

    def candidate_tree(self, before):
        result = json.loads(json.dumps(before))
        owner = before['directories']['.']
        for name, value in self.assets.items():
            previous = before['files'].get(name)
            result['files'][name] = dict(uid=owner['uid'], gid=owner['gid'],
                                        mode=previous['mode'] if previous else 0o644,
                                        sha256=hashlib.sha256(value).hexdigest(), content=base64.b64encode(value).decode())
            for parent in Path(name).parents:
                key = parent.as_posix()
                if key not in result['directories']:
                    result['directories'][key] = dict(uid=owner['uid'], gid=owner['gid'], mode=0o755)
        return result

    def write_assets(self, root, installed, original, restore=False):
        with installation_identity(installed) as owner:
            old_files = original['files']
            for name in sorted(self.assets):
                path = root/name
                if restore and name not in old_files:
                    if path.exists():
                        vm.safe_unlink(path)
                    continue
                for parent in reversed(path.parent.parents):
                    if parent.is_relative_to(root) and not parent.exists():
                        ensure_directory(parent, owner)
                if not path.parent.exists():
                    ensure_directory(path.parent, owner)
                value = base64.b64decode(old_files[name]['content']) if restore else self.assets[name]
                mode = old_files[name]['mode'] if name in old_files else 0o644
                if not path.exists() or vm.safe_read(path) != value:
                    vm.atomic_bytes(path, value, mode=mode)
                require(metadata(path) == dict(uid=owner[0], gid=owner[1], mode=mode),
                        'published theme changed ownership or permissions')
            if restore:
                for directory in sorted(root.rglob('*'), reverse=True):
                    if directory.is_dir() and directory.relative_to(root).as_posix() not in original['directories']:
                        with vm.safe_parent(directory) as (parent, name, verify):
                            os.rmdir(name, dir_fd=parent); verify(); os.fsync(parent)

    def ready(self, container):
        deadline = time.monotonic()+180
        while time.monotonic() < deadline:
            row = json.loads(vm.run(['docker', 'inspect', container]))[0]
            if row['State']['Status'] == 'running':
                addresses = [value['IPAddress'] for value in row.get('NetworkSettings', {}).get('Networks', {}).values() if value.get('IPAddress')]
                for address in addresses:
                    url = readiness_url(row, address)
                    try:
                        with urllib.request.urlopen(url, timeout=2) as response:
                            value = json.load(response)
                            if response.status == 200 and str(value.get('issuer', '')).endswith('/realms/master'):
                                return
                    except (OSError, ValueError):
                        pass
            time.sleep(1)
        raise RuntimeError('IDP readiness deadline exceeded')

    def verify_runtime(self, record, expected_tree):
        installed, root, row, others = self.context()
        require(str(installed) == record['installed'] and str(root) == record['root'] and
                row['Id'] == record['idp']['id'] and row['Image'] == record['idp']['image'] and
                fingerprint(row)['config_sha256'] == record['idp']['config_sha256'], 'IDP runtime contract changed')
        require(others == record['non_targets'], 'a non-IDP container changed during theme release')
        require(tree_snapshot(root, installed) == expected_tree, 'published theme tree differs')
        return fingerprint(row)

    def apply(self):
        self.verify_media()
        require(not (self.media/'receipt.json').exists(), 'theme apply cannot be replayed')
        record = self.original()
        installed, root, row, others = self.context()
        require(str(installed) == record['installed'] and str(root) == record['root'] and
                fingerprint(row) == record['idp'] and others == record['non_targets'] and
                tree_snapshot(root, installed) == record['before'], 'theme stage drifted before apply')
        container = row['Id']
        vm.run(['docker', 'stop', '--time', '30', container])
        try:
            self.write_assets(root, installed, record['before'])
            after = tree_snapshot(root, installed)
            require(after == self.candidate_tree(record['before']), 'installed theme scope or bind inode changed')
            vm.run(['docker', 'start', container])
            self.ready(container)
            runtime = self.verify_runtime(record, after)
            receipt = dict(status='deployed', purpose='chat-theme-only', release_id=self.manifest['release_id'],
                           revision=self.manifest['revision'], manifest_sha256=self.manifest_sha,
                           state_sha256=vm.digest(self.state/'before.json'), before_sha256=object_hash(record['before']),
                           after_sha256=object_hash(after), idp=runtime)
            vm.write_json(self.media/'receipt.json', receipt)
            checksum = vm.digest(self.media/'receipt.json')
            vm.write_json(self.pointer, dict(release=str(self.media), receipt_sha256=checksum))
        except BaseException as error:
            vm.run(['docker', 'stop', '--time', '30', container])
            self.write_assets(root, installed, record['before'], restore=True)
            vm.run(['docker', 'start', container])
            self.ready(container)
            self.verify_runtime(record, record['before'])
            if record['previous_pointer']:
                vm.atomic_bytes(self.pointer, base64.b64decode(record['previous_pointer']))
            elif self.pointer.exists():
                vm.safe_unlink(self.pointer)
            if (self.media/'receipt.json').exists():
                vm.safe_unlink(self.media/'receipt.json')
            raise RuntimeError('theme apply failed; original theme and runtime restored') from error
        print('CHAT_THEME_RECEIPT_SHA256='+checksum, flush=True)

    def rollback(self, receipt_sha):
        require(re.fullmatch(r'[0-9a-f]{64}', receipt_sha or ''), 'invalid theme rollback receipt pin')
        require(vm.digest(self.media/'receipt.json') == receipt_sha, 'theme rollback receipt differs')
        receipt = json.loads(vm.safe_read(self.media/'receipt.json'))
        require(receipt.get('status') == 'deployed' and receipt.get('purpose') == 'chat-theme-only' and
                receipt.get('manifest_sha256') == self.manifest_sha and
                receipt.get('state_sha256') == vm.digest(self.state/'before.json'), 'theme rollback evidence differs')
        require(json.loads(vm.safe_read(self.pointer)) == dict(release=str(self.media), receipt_sha256=receipt_sha),
                'theme rollback is not the active release')
        record = self.original()
        installed, root, row, others = self.context()
        current_idp = fingerprint(row)
        require(str(root) == record['root'] and str(installed) == record['installed'] and
                all(current_idp[key] == receipt['idp'][key] for key in ('id', 'image', 'config_sha256')) and
                object_hash(tree_snapshot(root, installed)) == receipt['after_sha256'],
                'active theme changed before rollback')
        record['non_targets'] = others
        candidate = tree_snapshot(root, installed)
        active_pointer = vm.safe_read(self.pointer)
        vm.run(['docker', 'stop', '--time', '30', row['Id']])
        try:
            self.write_assets(root, installed, record['before'], restore=True)
            vm.run(['docker', 'start', row['Id']])
            self.ready(row['Id'])
            self.verify_runtime(record, record['before'])
            if record['previous_pointer']:
                vm.atomic_bytes(self.pointer, base64.b64decode(record['previous_pointer']))
            else:
                vm.safe_unlink(self.pointer)
            vm.write_json(self.media/'rollback-receipt.json', dict(status='rolled_back', apply_receipt_sha256=receipt_sha))
        except BaseException as error:
            vm.run(['docker', 'stop', '--time', '30', row['Id']])
            self.write_assets(root, installed, candidate, restore=True)
            vm.run(['docker', 'start', row['Id']])
            self.ready(row['Id'])
            self.verify_runtime(record, candidate)
            vm.atomic_bytes(self.pointer, active_pointer)
            if (self.media/'rollback-receipt.json').exists():
                vm.safe_unlink(self.media/'rollback-receipt.json')
            raise RuntimeError('theme rollback failed; active theme and runtime restored') from error
        print('CHAT_THEME_ROLLBACK_VERIFIED', flush=True)


def apply_guest_code(release_id, manifest_sha, action, receipt_sha=None):
    import inspect
    from deploy_vm_development import run_installation_helper
    from vm_console_release import protected, controlled_environment
    require(re.fullmatch(r'dev-[A-Za-z0-9-]+', release_id) and action in ('stage', 'apply', 'rollback') and
            re.fullmatch(r'[0-9a-f]{64}', manifest_sha), 'invalid theme guest invocation')
    require((action != 'rollback' and receipt_sha is None) or
            (action == 'rollback' and re.fullmatch(r'[0-9a-f]{64}', receipt_sha or '')), 'invalid theme receipt pin')
    validators = '\n\n'.join(inspect.getsource(fn) for fn in (require, protected, controlled_environment, run_installation_helper))
    arguments = [action, '--media', '/opt/jjdguard/development-releases/'+release_id,
                 '--manifest-sha256', manifest_sha]
    if receipt_sha:
        arguments += ['--receipt-sha256', receipt_sha]
    return ('import hashlib,json,os,subprocess\nfrom pathlib import Path\nfrom types import SimpleNamespace\n'
            'vm=SimpleNamespace(ROOT=Path("/opt/jjdguard"))\n'+validators+'\n'
            'media=vm.ROOT/"development-releases"/'+repr(release_id)+'\nprotected(media,directory=True)\n'
            'require({p.name for p in media.iterdir()} <= '+repr(set(MEDIA_FILES)|{'state', 'receipt.json', 'rollback-receipt.json'})+',"unrecorded theme media")\n'
            'def sha(path):\n return hashlib.sha256(protected(path).read_bytes()).hexdigest()\n'
            'require(sha(media/"manifest.json")=='+repr(manifest_sha)+',"theme manifest changed")\n'
            'manifest=json.loads((media/"manifest.json").read_text())\n'
            'require(manifest.get("purpose")=="chat-theme-only" and manifest.get("release_id")=='+repr(release_id)+',"theme identity changed")\n'
            'for name,field in (("vm_development_apply.py","apply_script_sha256"),("vm_chat_theme_release.py","theme_script_sha256")):\n'
            ' require(sha(media/name)==manifest[field],"theme script changed before execution")\n'
            'run_installation_helper(["/usr/bin/python3","-E","-s","-B",str(media/"vm_chat_theme_release.py"),*'+repr(arguments)+'],vm.ROOT)\n')


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('stage', 'apply', 'rollback'))
    parser.add_argument('--media', required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--receipt-sha256')
    parser.add_argument('--install-owner-uid', type=int)
    parser.add_argument('--install-owner-gid', type=int)
    args = parser.parse_args()
    vm.configure_installation_owner(args.install_owner_uid, args.install_owner_gid)
    with vm.release_lock():
        release = ThemeRelease(args.media, args.manifest_sha256)
        if args.action == 'rollback':
            release.rollback(args.receipt_sha256)
        else:
            require(args.receipt_sha256 is None, 'receipt pin is only for rollback')
            getattr(release, args.action)()


if __name__ == '__main__':
    main()
