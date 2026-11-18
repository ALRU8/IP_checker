import base64
import ctypes
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


def run(args, data=None):
    result = subprocess.run(args, input=data, capture_output=True, text=True, timeout=15)
    if result.returncode or "AuthorizationCreate() failed" in result.stderr + result.stdout:
        raise RuntimeError((result.stderr.strip() or result.stdout.strip() or str(args[0]))[:400])
    return result


def ps(script):
    script = "$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[System.Text.UTF8Encoding]::new(); " + script
    encoded = base64.b64encode(script.encode('utf-16le')).decode()
    return run(['powershell.exe', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded]).stdout


def is_admin():
    return bool(ctypes.windll.shell32.IsUserAnAdmin()) if os.name == 'nt' else os.geteuid() == 0


def elevate(script):
    if is_admin():
        return False
    print('Нужны права администратора для отключения сети.', flush=True)
    if os.name == 'nt':
        exe = str(Path(sys.executable).resolve()).replace("'", "''")
        arguments = subprocess.list2cmdline([str(script)]).replace("'", "''")
        ps(f"Start-Process -FilePath '{exe}' -ArgumentList '{arguments}' -Verb RunAs")
        return True
    os.execvp('sudo', ['sudo', sys.executable, str(script)])


def valid_interface(name):
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,64}', name) or name in ('lo', 'lo0'):
        raise ValueError('Некорректный сетевой интерфейс')
    return name


def steps(commands):
    failures = []
    for command in commands:
        try:
            run(command)
        except Exception as exc:
            failures.append(str(exc))
    if failures:
        raise RuntimeError('; '.join(failures))


def parse_mac_hardware(text):
    found = []
    title = ''
    for line in text.splitlines():
        if line.startswith('Hardware Port: '):
            title = line.partition(': ')[2]
        elif line.startswith('Device: ') and title:
            name = valid_interface(line.partition(': ')[2].strip())
            found.append({'id': name, 'name': name, 'label': title, 'wifi': title.lower() in ('wi-fi', 'airport')})
            title = ''
    return found


def parse_mac_services(text):
    found = {}
    service = None
    for line in text.splitlines():
        match = re.match(r'\s*\*?\s*\(\d+\)\s+(.+)', line)
        if match:
            service = match[1].lstrip('*').strip()
        match = re.search(r'Device:\s*([^,)]+)', line)
        if match and service:
            found.setdefault(match[1].strip(), []).append(service)
            service = None
    return found


class MacAdapters:
    def __init__(self):
        self.setup = '/usr/sbin/networksetup'
        self.ifconfig = '/sbin/ifconfig'

    def list(self):
        return parse_mac_hardware(run([self.setup, '-listallhardwareports']).stdout)

    def up(self, adapter):
        text = run([self.ifconfig, valid_interface(adapter['name'])]).stdout
        match = re.search(r'flags=[^<\s]+<([^>]+)>', text)
        if not match:
            raise RuntimeError('Не удалось прочитать состояние ' + adapter['name'])
        return 'UP' in match[1].split(',')

    def snapshot(self, adapter):
        record = dict(adapter, up=self.up(adapter), services=[])
        service_map = parse_mac_services(run([self.setup, '-listnetworkserviceorder']).stdout)
        for name in service_map.get(adapter['name'], []):
            value = run([self.setup, '-getnetworkserviceenabled', name]).stdout.strip()
            if value not in ('Enabled', 'Disabled'):
                raise RuntimeError('Не удалось прочитать сетевую службу ' + name)
            record['services'].append({'name': name, 'enabled': value == 'Enabled'})
        if adapter['wifi']:
            value = run([self.setup, '-getairportpower', adapter['name']]).stdout.strip()
            if not value.endswith((': On', ': Off')):
                raise RuntimeError('Не удалось прочитать питание Wi-Fi')
            record['power'] = value.endswith(': On')
        return record

    def disable(self, record):
        name = valid_interface(record['name'])
        commands = [[self.ifconfig, name, 'down']]
        commands += [[self.setup, '-setnetworkserviceenabled', x['name'], 'off'] for x in record['services']]
        if record['wifi']:
            commands.append([self.setup, '-setairportpower', name, 'off'])
        commands.append([self.ifconfig, name, 'down'])
        steps(commands)

    def restore(self, record):
        name = valid_interface(record['name'])
        commands = []
        if record['wifi'] and record.get('power'):
            commands.append([self.setup, '-setairportpower', name, 'on'])
        commands += [[self.setup, '-setnetworkserviceenabled', x['name'], 'on'] for x in record['services'] if x['enabled']]
        commands.append([self.ifconfig, name, 'up' if record['up'] else 'down'])
        steps(commands)


class LinuxAdapters:
    def __init__(self):
        self.ip = shutil.which('ip')
        self.nm = shutil.which('nmcli')
        if not self.ip:
            raise RuntimeError('Установи iproute2: не найдена команда ip')

    def list(self):
        return [{'id': x.name, 'name': valid_interface(x.name), 'label': x.name}
                for x in Path('/sys/class/net').iterdir() if (x / 'device').exists()]

    def up(self, adapter):
        rows = json.loads(run([self.ip, '-j', 'link', 'show', 'dev', valid_interface(adapter['name'])]).stdout)
        if len(rows) != 1:
            raise RuntimeError('Не удалось проверить сетевой адаптер')
        return 'UP' in rows[0]['flags']

    def snapshot(self, adapter):
        record = dict(adapter, up=self.up(adapter), managed=False, connection='')
        if self.nm:
            result = subprocess.run([self.nm, '-g', 'GENERAL.NM-MANAGED,GENERAL.CON-UUID', 'device', 'show', adapter['name']],
                                    capture_output=True, text=True, timeout=5, env={**os.environ, 'LC_ALL': 'C'})
            if result.returncode == 0:
                values = result.stdout.splitlines()
                record['managed'] = bool(values and values[0] == 'yes')
                record['connection'] = values[1] if len(values) > 1 and values[1] != '--' else ''
        return record

    def disable(self, record):
        name = valid_interface(record['name'])
        commands = [[self.ip, 'link', 'set', 'dev', name, 'down']]
        if self.nm and record['managed']:
            commands.append([self.nm, 'device', 'set', name, 'managed', 'no'])
        commands.append([self.ip, 'link', 'set', 'dev', name, 'down'])
        steps(commands)

    def restore(self, record):
        name = valid_interface(record['name'])
        commands = []
        if self.nm and record['managed']:
            commands.append([self.nm, 'device', 'set', name, 'managed', 'yes'])
        commands.append([self.ip, 'link', 'set', 'dev', name, 'up' if record['up'] else 'down'])
        if self.nm and record['managed'] and record['connection'] and record['up']:
            commands.append([self.nm, 'connection', 'up', 'uuid', record['connection'], 'ifname', name])
        steps(commands)


class WindowsAdapters:
    def list(self):
        text = ps("@(Get-NetAdapter -Physical -IncludeHidden | Select-Object @{n='id';e={$_.InterfaceGuid.ToString()}},@{n='name';e={$_.Name}},@{n='label';e={$_.InterfaceDescription}},@{n='up';e={$_.AdminStatus -eq 'Up'}}) | ConvertTo-Json -Compress")
        data = json.loads(text or '[]')
        return data if isinstance(data, list) else [data]

    def query(self, adapter):
        import uuid
        guid = str(uuid.UUID(adapter['id'].strip('{}')))
        return "Get-NetAdapter -IncludeHidden | Where-Object { $_.InterfaceGuid -eq '" + guid + "' }"

    def up(self, adapter):
        text = ps("$a=@(" + self.query(adapter) + "); if($a.Count -ne 1){throw 'Adapter missing'}; $a[0].AdminStatus -eq 'Up'").strip()
        if text not in ('True', 'False'):
            raise RuntimeError('Не удалось прочитать статус сетевого адаптера')
        return text == 'True'

    def snapshot(self, adapter):
        return dict(adapter)

    def disable(self, record):
        ps(self.query(record) + ' | Disable-NetAdapter -Confirm:$false -ErrorAction Stop')

    def restore(self, record):
        if record['up']:
            ps(self.query(record) + ' | Enable-NetAdapter -Confirm:$false -ErrorAction Stop')


def adapters_for(name):
    return {'macos': MacAdapters, 'linux': LinuxAdapters, 'windows': WindowsAdapters}[name]()
