import ast
import contextlib
import ctypes
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from guard.config import load, resolve_proxy, validate_proxy
from guard.monitor import monitor
from guard.network import Controller, Store
from guard.packet_lock import Action, Filter, MacLock, Sublayer, Value
from guard.probe import Result, check, parse, sources
from guard.system import MacAdapters, parse_mac_hardware, parse_mac_services


class ProbeTests(unittest.TestCase):
    def test_foreign_sources_only(self):
        from guard.sources import APPROVED_SOURCES
        self.assertEqual({s['url'] for s in sources()}, set(APPROVED_SOURCES))
        self.assertGreaterEqual(len(sources()), 8)
        self.assertTrue(all(s['url'].startswith('https://') and '.ru/' not in s['url'] for s in sources()))

    def test_every_source_parses_its_own_format(self):
        for source in sources():
            if source['format'] == 'trace':
                body = f"ip=8.8.8.8\n{source['country_field']}=DE\n"
            else:
                body = json.dumps({source['ip_field']: '8.8.8.8', source['country_field']: 'DE', source.get('timezone_field', 'x'): 'Europe/Berlin'})
            with self.subTest(source=source['name']):
                result = parse(source, body)
                self.assertTrue(result.safe)
                self.assertEqual(result.timezone, 'Europe/Berlin' if 'timezone_field' in source else '')

    def test_reads_country_and_ipv4(self):
        self.assertEqual(parse(sources()[0], 'ip=8.8.8.8\nloc=RU\n').country, 'RU')
        self.assertEqual(parse(sources()[1], '{"ip":"8.8.4.4","country_code":"DE"}').country, 'DE')

    def test_reads_ipv6(self):
        result = parse(sources()[1], '{"ip":"2001:4860:4860::8888","country_code":"US"}')
        self.assertIn(':', result.ip)
        self.assertTrue(result.safe)

    def test_unknown_private_malformed_and_api_error_are_unsafe(self):
        for data in ({}, {'ip': '127.0.0.1', 'country_code': 'DE'}, {'ip': '8.8.8.8', 'country_code': 'ZZ'},
                     {'ip': '8.8.8.8', 'country_code': 'DE', 'success': False}, []):
            with self.subTest(data=data), self.assertRaises(ValueError):
                parse(sources()[1], json.dumps(data))

    def test_ru_always_unsafe(self):
        self.assertFalse(Result('test', '8.8.8.8', 'RU').safe)
        self.assertFalse(Result('test', '8.8.8.8', 'DE', 'error').safe)

    def test_unapproved_url_never_executes_curl(self):
        source = dict(sources()[0], url='https://example.ru/')
        with patch('guard.probe.subprocess.run') as run:
            result = check(source, 2, '')
            run.assert_not_called()
        self.assertTrue(result.error)

    def test_curl_uses_explicit_proxy_no_redirects_and_no_curlrc(self):
        with patch('guard.probe.curl_path', return_value='curl'), patch('guard.probe.subprocess.run') as run:
            run.return_value = subprocess.CompletedProcess([], 0, '{"ip":"8.8.8.8","country_code":"DE"}', '')
            result = check(sources()[1], 2, 'http://127.0.0.1:10809')
            self.assertTrue(result.safe)
            command = run.call_args.args[0]
            self.assertEqual(command[1], '--disable')
            self.assertEqual(command[command.index('--proxy') + 1], 'http://127.0.0.1:10809')
            self.assertNotIn('--location', command)
            self.assertNotIn('--insecure', command)
            self.assertEqual(command[-1], sources()[1]['url'])

    def test_direct_mode_ignores_proxy_environment(self):
        with patch('guard.probe.curl_path', return_value='curl'), patch('guard.probe.subprocess.run') as run, patch.dict(os.environ, {'HTTPS_PROXY': 'http://unwanted.example'}):
            run.return_value = subprocess.CompletedProcess([], 7, '', '')
            self.assertFalse(check(sources()[0], 2, '').safe)
            self.assertNotIn('HTTPS_PROXY', run.call_args.kwargs['env'])
            command = run.call_args.args[0]
            self.assertEqual(command[command.index('--proxy') + 1], '')
            self.assertEqual(command[command.index('--noproxy') + 1], '*')

    def test_timeout_is_reported(self):
        with patch('guard.probe.curl_path', return_value='curl'), patch('guard.probe.subprocess.run', side_effect=subprocess.TimeoutExpired('curl', 2)):
            self.assertTrue(check(sources()[0], 2, '').error)


class ConfigTests(unittest.TestCase):
    def test_configuration_for_every_platform(self):
        for name in ('macos', 'windows', 'linux'):
            with patch('guard.config.system_name', return_value=name):
                self.assertEqual(load()['os'], name)

    def test_proxy_auto_respects_system_local_proxy(self):
        with patch('guard.config.urllib.request.getproxies', return_value={'https': 'http://127.0.0.1:10809'}):
            self.assertEqual(resolve_proxy('auto'), 'http://127.0.0.1:10809')

    def test_proxy_auto_falls_back_to_system_route_without_proxy(self):
        with patch('guard.config.urllib.request.getproxies', return_value={}):
            self.assertEqual(resolve_proxy('auto'), '')
        self.assertEqual(resolve_proxy('direct'), '')

    def test_mac_socks_proxy_uses_remote_dns(self):
        with patch('guard.config.urllib.request.getproxies', return_value={'socks': 'socks://127.0.0.1:10808'}):
            self.assertEqual(resolve_proxy('auto'), 'socks5h://127.0.0.1:10808')

    def test_remote_and_authenticated_proxy_rejected(self):
        for value in ('http://example.com:8080', 'http://user:password@127.0.0.1:10809', 'ftp://127.0.0.1:21'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_proxy(value)


class MacParserTests(unittest.TestCase):
    def test_hexadecimal_interface_flags_are_supported(self):
        result = subprocess.CompletedProcess([], 0, 'en0: flags=8b63<UP,BROADCAST,RUNNING> mtu 1500', '')
        with patch('guard.system.run', return_value=result):
            self.assertTrue(MacAdapters().up({'name': 'en0'}))

    def test_restore_keeps_administratively_disabled_interface_down(self):
        record = {'name': 'en0', 'wifi': True, 'power': True, 'up': False, 'services': [{'name': 'Wi-Fi', 'enabled': False}]}
        with patch('guard.system.run') as run:
            MacAdapters().restore(record)
        self.assertEqual(run.call_args.args[0], ['/sbin/ifconfig', 'en0', 'down'])
        self.assertNotIn(['/usr/sbin/networksetup', '-setnetworkserviceenabled', 'Wi-Fi', 'on'], [x.args[0] for x in run.call_args_list])

    def test_wifi_ethernet_and_thunderbolt_are_included(self):
        text = 'Hardware Port: USB Ethernet\nDevice: en7\nEthernet Address: 00:00\n\nHardware Port: Wi-Fi\nDevice: en0\n\nHardware Port: Thunderbolt Bridge\nDevice: bridge0\n'
        rows = parse_mac_hardware(text)
        self.assertEqual([x['name'] for x in rows], ['en7', 'en0', 'bridge0'])
        self.assertTrue(rows[1]['wifi'])

    def test_network_service_names_can_contain_spaces(self):
        text = '(1) Work Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n(2) USB Cable\n(Hardware Port: USB LAN, Device: en7)'
        self.assertEqual(parse_mac_services(text), {'en0': ['Work Wi-Fi'], 'en7': ['USB Cable']})

    def test_loopback_rejected(self):
        with self.assertRaises(ValueError):
            parse_mac_hardware('Hardware Port: Unexpected\nDevice: lo0\n')


class MacPacketLockTests(unittest.TestCase):
    def test_scrub_anchor_is_preserved_for_restore_and_not_rejected(self):
        original = 'scrub-anchor "com.apple/*" all fragment reassemble\nanchor "com.apple/*" all\n'
        calls, snapshots = [], []

        def run(command, data=None):
            calls.append((command, data))
            if command[-1] == '-sr':
                output = original if len([x for x, _ in calls if x[-1] == '-sr']) == 1 else 'scrub-anchor "com.apple/*" all fragment reassemble\nblock drop quick all\n'
            elif command[-1] == '-E':
                return subprocess.CompletedProcess(command, 0, '', 'No ALTQ support in kernel\nToken : 42\n')
            elif command[-2:] == ['-s', 'info']:
                output = 'Status: Enabled for 00:01:00'
            elif command[-1] == 'kern.boottime':
                output = '{ sec = 12345, usec = 0 }'
            else:
                output = ''
            return subprocess.CompletedProcess(command, 0, output, '')

        state = {}
        with patch('guard.packet_lock.run', side_effect=run):
            lock = MacLock(lambda state: snapshots.append(dict(state)))
            lock.acquire(state)
            self.assertEqual(state['pf_rules'], original)
            self.assertEqual(state['pf_token'], '42')
            self.assertIn((['/sbin/pfctl', '-R', '-f', '-'], 'block drop quick all\n'), calls)
            self.assertLess([c for c, _ in calls].index(['/sbin/pfctl', '-R', '-f', '-']), [c for c, _ in calls].index(['/sbin/pfctl', '-F', 'states']))
            lock.release(state)
            self.assertIn((['/sbin/pfctl', '-R', '-f', '-'], original), calls)
            self.assertIn((['/sbin/pfctl', '-X', '42'], None), calls)

    def test_pf_snapshot_from_another_boot_is_not_restored(self):
        lock = MacLock(lambda state: None)
        state = {'pf_boot': '12345', 'pf_rules': 'pass all\n', 'pf_token': '42'}
        with patch.object(lock, 'boot_id', return_value='67890'), patch('guard.packet_lock.run') as run:
            lock.release(state)
            run.assert_not_called()

    def test_x64_wfp_structures(self):
        if ctypes.sizeof(ctypes.c_void_p) != 8:
            self.skipTest('64-bit layout')
        self.assertEqual(ctypes.sizeof(Value), 16)
        self.assertEqual(ctypes.sizeof(Filter), 200)
        self.assertEqual(ctypes.sizeof(Sublayer), 72)
        self.assertEqual(ctypes.sizeof(Action), 20)


class MemoryStore:
    def __init__(self):
        self.state = None
        self.events = []
        self.privacy = None

    def read(self):
        return self.state

    def write(self, state):
        self.state = state
        self.events.append('save')

    def clear(self):
        self.state = None
        self.events.append('clear')

    def read_privacy(self):
        return self.privacy

    def write_privacy(self, state):
        self.privacy = dict(state)
        self.events.append('save-privacy')

    def clear_privacy(self):
        self.privacy = None
        self.events.append('clear-privacy')


class FakeAdapters:
    def __init__(self, events):
        self.events = events
        self.rows = [{'id': 'wifi', 'name': 'wifi', 'label': 'Wi-Fi', 'up': True},
                     {'id': 'eth', 'name': 'eth', 'label': 'Ethernet', 'up': False}]
        self.enabled = {'wifi': True, 'eth': False}
        self.fail_disable = set()
        self.fail_restore = set()

    def list(self):
        return self.rows

    def snapshot(self, row):
        self.events.append('snapshot')
        return dict(row, up=self.enabled[row['id']])

    def disable(self, row):
        self.events.append('disable:' + row['id'])
        if row['id'] in self.fail_disable:
            raise RuntimeError('driver failure')
        self.enabled[row['id']] = False

    def restore(self, row):
        self.events.append('restore:' + row['id'])
        if row['id'] in self.fail_restore:
            raise RuntimeError('restore failed')
        self.enabled[row['id']] = row['up']

    def up(self, row):
        return self.enabled[row['id']]


class FakeLock:
    def __init__(self, events, fail=False):
        self.events = events
        self.fail = fail

    def acquire(self, state):
        self.events.append('lock')
        state['lock'] = 'fake'
        if self.fail:
            raise RuntimeError('filter failure')

    def release(self, state):
        self.events.append('unlock')


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.store = MemoryStore()
        self.adapters = FakeAdapters(self.events)
        self.controller = Controller('macos', self.store, self.adapters, FakeLock(self.events))
        self.admin = patch('guard.network.is_admin', return_value=True)
        self.admin.start()
        self.addCleanup(self.admin.stop)

    def test_kernel_block_precedes_adapter_inspection_and_disconnect(self):
        report = self.controller.cut('manual')
        self.assertTrue(report['complete'])
        self.assertEqual(self.events[0], 'lock')
        self.assertFalse(any(self.adapters.enabled.values()))
        self.assertTrue(self.controller.blocked)

    def test_filter_failure_still_disables_all_adapters_but_is_not_success(self):
        self.controller.packet_lock = FakeLock(self.events, fail=True)
        report = self.controller.cut('test')
        self.assertFalse(report['complete'])
        self.assertFalse(report['kernel'])
        self.assertFalse(any(self.adapters.enabled.values()))

    def test_one_adapter_failure_does_not_stop_other_disconnections(self):
        self.adapters.fail_disable.add('wifi')
        report = self.controller.cut('test')
        self.assertFalse(report['complete'])
        self.assertIn('disable:eth', self.events)
        self.assertTrue(report['errors'])

    def test_restore_recreates_only_previously_enabled_states(self):
        self.controller.cut('test')
        self.assertFalse(self.controller.restore())
        self.assertTrue(self.adapters.enabled['wifi'])
        self.assertFalse(self.adapters.enabled['eth'])
        self.assertIsNone(self.store.state)
        self.assertGreater(self.events.index('unlock'), self.events.index('restore:wifi'))

    def test_restore_error_keeps_filter_and_saved_state(self):
        self.controller.cut('test')
        self.adapters.fail_restore.add('wifi')
        self.assertTrue(self.controller.restore())
        self.assertNotIn('unlock', self.events)
        self.assertIsNotNone(self.store.state)

    def test_repeated_cut_keeps_original_state_for_restore(self):
        self.controller.cut('test')
        self.controller.cut('test again')
        self.controller.restore()
        self.assertTrue(self.adapters.enabled['wifi'])
        self.assertFalse(self.adapters.enabled['eth'])

    def test_without_admin_no_mutations(self):
        with patch('guard.network.is_admin', return_value=False), self.assertRaises(RuntimeError):
            self.controller.cut('test')
        self.assertEqual(self.events, [])
        self.assertIsNone(self.store.state)


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.cfg = {'request_timeout': 0.01, 'check_interval': 0.01, 'startup_timeout': 0.01, 'proxy': 'direct'}
        self.events = []
        self.controller = Controller('macos', MemoryStore(), FakeAdapters(self.events), FakeLock(self.events))
        self.console = type('Console', (), {'table': lambda *args: None, 'cut': lambda *args: None})()

    def test_first_ru_disables_before_slow_provider_finishes(self):
        import threading
        import time
        slow_done = threading.Event()
        cut_seen = []
        real_cut = self.controller.cut

        def check(source, *_):
            if source['name'] == 'Cloudflare':
                return Result(source['name'], '8.8.8.8', 'RU')
            time.sleep(0.2)
            slow_done.set()
            return Result(source['name'], '8.8.4.4', 'DE')

        def cut(reason):
            cut_seen.append(slow_done.is_set())
            return real_cut(reason)

        with patch('guard.monitor.curl_path'), patch('guard.monitor.check', side_effect=check), patch('guard.network.is_admin', return_value=True), patch.object(self.controller, 'cut', side_effect=cut):
            monitor(self.cfg, self.controller, self.console)
        self.assertEqual(cut_seen, [False])
        self.assertTrue(self.controller.blocked)
        slow_done.wait(1)

    def test_view_only_does_not_disable_when_ru(self):
        with patch('guard.monitor.curl_path'), patch('guard.monitor.check', side_effect=lambda source, *_: Result(source['name'], '8.8.8.8', 'RU')):
            monitor(self.cfg, self.controller, self.console, once=True)
        self.assertFalse(self.controller.blocked)
        self.assertEqual(self.events, [])

    def test_timeout_at_start_disables_after_startup_deadline(self):
        with patch('guard.monitor.curl_path'), patch('guard.monitor.check', side_effect=lambda source, *_: Result(source['name'], error='timeout')), patch('guard.network.is_admin', return_value=True):
            monitor(self.cfg, self.controller, self.console)
        self.assertTrue(self.controller.blocked)

    def run_rounds(self, check, rounds=3, sync=lambda results: 'Europe/Berlin'):
        self.cfg['startup_timeout'] = 60
        calls = []

        def counted(source, *args):
            calls.append(source['name'])
            if len(calls) > rounds * len(sources()):
                raise KeyboardInterrupt
            return check(source)

        def guarded(*args):
            if len(calls) >= rounds * len(sources()):
                raise KeyboardInterrupt
            return None

        console = type('Console', (), {'table': guarded, 'cut': lambda *args: None})()
        with patch('guard.monitor.curl_path'), patch('guard.monitor.check', side_effect=counted), patch('guard.network.is_admin', return_value=True), patch.object(self.controller, 'sync_timezone', side_effect=sync) as synced, contextlib.redirect_stdout(io.StringIO()):
            monitor(self.cfg, self.controller, console)
        return synced

    def test_timeouts_do_not_disable_when_one_source_is_safe(self):
        def check(source):
            if source['name'] == 'IP.SB':
                return Result(source['name'], '8.8.4.4', 'DE', timezone='Europe/Berlin')
            return Result(source['name'], error='Нет ответа (curl 28)')

        synced = self.run_rounds(check)
        self.assertFalse(self.controller.blocked)
        self.assertEqual([x.name for x in synced.call_args.args[0]], ['IP.SB'])

    def test_missing_timezone_after_sync_does_not_disable(self):
        state = {'round': 0}

        def check(source):
            if source['name'] == 'IP.SB':
                state['round'] += 1
                if state['round'] == 1:
                    return Result(source['name'], '8.8.4.4', 'DE', timezone='Europe/Berlin')
                return Result(source['name'], error='timeout')
            if source['name'] == 'Cloudflare':
                return Result(source['name'], '8.8.8.8', 'DE')
            return Result(source['name'], error='timeout')

        from guard.timezone import target_zone
        self.run_rounds(check, sync=target_zone)
        self.assertFalse(self.controller.blocked)

    def test_ru_among_timeouts_still_disables(self):
        def check(source):
            if source['name'] == 'ifconfig.co':
                return Result(source['name'], '8.8.8.8', 'RU')
            if source['name'] == 'IP.SB':
                return Result(source['name'], '8.8.4.4', 'DE', timezone='Europe/Berlin')
            return Result(source['name'], error='timeout')

        self.run_rounds(check)
        self.assertTrue(self.controller.blocked)

    def test_all_sources_timing_out_disables_after_deadline(self):
        self.cfg['startup_timeout'] = 0.01
        with patch('guard.monitor.curl_path'), patch('guard.monitor.check', side_effect=lambda source, *_: Result(source['name'], error='timeout')), patch('guard.network.is_admin', return_value=True):
            monitor(self.cfg, self.controller, self.console)
        self.assertTrue(self.controller.blocked)

    def test_monitoring_can_restart_after_recorded_cut(self):
        with patch('guard.network.is_admin', return_value=True):
            self.controller.cut('previous test')
            with patch('guard.monitor.curl_path'), patch('guard.monitor.check', side_effect=lambda source, *_: Result(source['name'], '8.8.8.8', 'RU')):
                monitor(self.cfg, self.controller, self.console)
        self.assertIn('unlock', self.events)
        self.assertEqual(self.events.count('lock'), 2)


class StoreTests(unittest.TestCase):
    def test_state_roundtrip_and_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store('macos', directory)
            try:
                self.assertIsNone(store.read())
                store.write({'test': 'value'})
                self.assertEqual(store.read(), {'test': 'value'})
                if os.name != 'nt':
                    self.assertEqual(store.path.stat().st_mode & 0o777, 0o600)
                store.clear()
                self.assertIsNone(store.read())
            finally:
                store.close()

    def test_second_instance_is_rejected(self):
        if os.name == 'nt':
            self.skipTest('Unix flock')
        with tempfile.TemporaryDirectory() as directory:
            first = Store('macos', directory)
            try:
                with self.assertRaises(RuntimeError):
                    Store('macos', directory)
            finally:
                first.close()


class ConsoleTests(unittest.TestCase):
    def test_menu_dispatches_manual_cut_without_cli_flags(self):
        from guard.console import Console
        from vpn_guard import menu
        store = MemoryStore()
        controller = Controller('macos', store, FakeAdapters([]), FakeLock([]))
        with patch('builtins.input', side_effect=['3', '', '0']), patch('guard.network.is_admin', return_value=True), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(menu({'os': 'macos'}, controller, Console()), 0)
        self.assertIn('ИНТЕРНЕТ ВЫКЛЮЧЕН', output.getvalue())
        self.assertIsNotNone(store.state)

    def test_no_comments_or_docstrings(self):
        import tokenize
        for path in [Path('vpn_guard.py'), *Path('guard').glob('*.py')]:
            source = path.read_text()
            for token in tokenize.generate_tokens(io.StringIO(source).readline):
                if token.type == tokenize.COMMENT:
                    self.assertTrue(token.start[0] == 1 and token.string.startswith('#!'), str(path))
            for node in ast.walk(ast.parse(source)):
                if isinstance(node, (ast.Module, ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)):
                    self.assertIsNone(ast.get_docstring(node), str(path))


if __name__ == '__main__':
    unittest.main()
