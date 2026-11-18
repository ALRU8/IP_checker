import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from guard.network import Controller, Store
from guard.probe import Result, parse, sources
from guard.timezone import MacTimezone, TimezoneManager, WindowsTimezone, target_zone
from test_guard import FakeAdapters, FakeLock, MemoryStore


def results(country='DE', zone='Europe/Berlin'):
    return [Result('Cloudflare', '8.8.8.8', country), Result('IP.SB', '8.8.4.4', country, timezone=zone)]


class FakeTimezone:
    def __init__(self, store):
        self.zone = 'Europe/Moscow'
        self.store = store
        self.calls = []
        self.fail_set = False
        self.fail_restore = False

    def current(self):
        return self.zone

    def matches(self, state):
        return self.zone == state['timezone']

    def native(self, zone):
        return zone

    def snapshot(self):
        return {'timezone': self.zone, 'test_setting': 'preserved'}

    def set(self, zone):
        if self.store.read_privacy() is None:
            raise AssertionError('original settings were not saved')
        self.calls.append(('set', zone))
        if self.fail_set:
            raise RuntimeError('permission denied')
        self.zone = zone

    def restore(self, state):
        self.calls.append(('restore', dict(state)))
        if self.fail_restore:
            raise RuntimeError('restore failed')
        self.zone = state['timezone']


class ZoneSelectionTests(unittest.TestCase):
    def test_uses_specific_timezone_in_a_multi_timezone_country(self):
        self.assertEqual(target_zone(results('US', 'America/Los_Angeles')), 'America/Los_Angeles')
        self.assertEqual(target_zone(results('US', 'America/New_York')), 'America/New_York')

    def test_country_conflict_rejected(self):
        data = results()
        data[0] = Result('Cloudflare', '8.8.8.8', 'NL')
        with self.assertRaises(RuntimeError):
            target_zone(data)

    def test_majority_country_and_zone_win_over_inaccurate_source(self):
        data = results('NL', 'Europe/Amsterdam') + [Result('ifconfig.co', '8.8.8.8', 'FR', timezone='Europe/Paris')]
        self.assertEqual(target_zone(data), 'Europe/Amsterdam')

    def test_lack_of_geo_data_is_distinguished_from_other_failures(self):
        from guard.timezone import GeoDataError
        with self.assertRaises(GeoDataError):
            target_zone([Result('Cloudflare', '8.8.8.8', 'DE')])

    def test_missing_unknown_or_wrong_country_timezone_rejected(self):
        for zone in ('', 'Not/A_Timezone', 'Europe/Moscow', '../../private/file'):
            with self.subTest(zone=zone), self.assertRaises(RuntimeError):
                target_zone(results('DE', zone))

    def test_ru_is_never_used_to_set_timezone(self):
        with self.assertRaises(RuntimeError):
            target_zone(results('RU', 'Europe/Moscow'))

    def test_geoip_timezone_is_parsed_and_terminal_controls_rejected(self):
        source = sources()[1]
        data = {'ip': '8.8.8.8', 'country_code': 'DE', 'timezone': 'Europe/Berlin'}
        self.assertEqual(parse(source, json.dumps(data)).timezone, 'Europe/Berlin')
        data['timezone'] = '\x1b[2J'
        self.assertEqual(parse(source, json.dumps(data)).timezone, '')


class TimezoneManagerTests(unittest.TestCase):
    def setUp(self):
        self.store = MemoryStore()
        self.backend = FakeTimezone(self.store)
        self.manager = TimezoneManager('macos', self.store, self.backend)

    def test_saves_original_before_mutation_and_restores(self):
        self.assertEqual(self.manager.sync(results()), 'Europe/Berlin')
        self.assertEqual(self.backend.zone, 'Europe/Berlin')
        self.assertEqual(self.store.privacy['original_timezone'], 'Europe/Moscow')
        self.manager.restore()
        self.assertEqual(self.backend.zone, 'Europe/Moscow')
        self.assertEqual(self.backend.calls[-1][1]['test_setting'], 'preserved')
        self.assertIsNone(self.store.privacy)

    def test_repeated_checks_do_not_rewrite_timezone_or_original_snapshot(self):
        self.manager.sync(results())
        writes = self.store.events.count('save-privacy')
        self.manager.sync(results())
        self.assertEqual(self.store.events.count('save-privacy'), writes)
        self.assertEqual(len(self.backend.calls), 1)
        self.assertEqual(self.store.privacy['original_timezone'], 'Europe/Moscow')

    def test_switching_safe_country_preserves_initial_snapshot(self):
        self.manager.sync(results())
        self.manager.sync(results('FR', 'Europe/Paris'))
        self.assertEqual(self.backend.zone, 'Europe/Paris')
        self.assertEqual(self.store.privacy['original_timezone'], 'Europe/Moscow')
        self.manager.restore()
        self.assertEqual(self.backend.zone, 'Europe/Moscow')

    def test_external_timezone_drift_is_detected(self):
        self.manager.sync(results())
        self.backend.zone = 'Europe/Moscow'
        with self.assertRaisesRegex(RuntimeError, 'извне'):
            self.manager.sync(results())
        self.assertIsNotNone(self.store.privacy)

    def test_failed_application_keeps_rollback_snapshot(self):
        self.backend.fail_set = True
        with self.assertRaises(RuntimeError):
            self.manager.sync(results())
        self.assertEqual(self.store.privacy['original_timezone'], 'Europe/Moscow')
        self.backend.fail_set = False
        self.manager.restore()
        self.assertIsNone(self.store.privacy)

    def test_failed_restore_keeps_snapshot_for_retry(self):
        self.manager.sync(results())
        self.backend.fail_restore = True
        with self.assertRaises(RuntimeError):
            self.manager.restore()
        self.assertIsNotNone(self.store.privacy)

    def test_invalid_country_never_reads_or_changes_system_settings(self):
        with patch.object(self.backend, 'current') as current, self.assertRaises(RuntimeError):
            self.manager.sync(results('RU', 'Europe/Moscow'))
        current.assert_not_called()
        self.assertIsNone(self.store.privacy)


class RollbackTests(unittest.TestCase):
    def setUp(self):
        self.store = MemoryStore()
        self.backend = FakeTimezone(self.store)
        self.manager = TimezoneManager('macos', self.store, self.backend)
        self.events = []
        self.controller = Controller('macos', self.store, FakeAdapters(self.events), FakeLock(self.events), self.manager)

    def test_full_rollback_works_without_network_cut(self):
        self.manager.sync(results())
        self.assertFalse(self.controller.blocked)
        self.assertTrue(self.controller.has_changes)
        with patch('guard.network.is_admin', return_value=True):
            self.assertEqual(self.controller.restore(), [])
        self.assertEqual(self.backend.zone, 'Europe/Moscow')
        self.assertFalse(self.controller.has_changes)
        self.assertEqual(self.events, [])

    def test_network_only_restore_keeps_privacy_until_explicit_full_rollback(self):
        self.manager.sync(results())
        with patch('guard.network.is_admin', return_value=True):
            self.controller.cut('test')
            self.assertEqual(self.controller.restore(network_only=True), [])
        self.assertEqual(self.backend.zone, 'Europe/Berlin')
        self.assertIsNotNone(self.store.privacy)
        self.assertFalse(self.controller.blocked)

    def test_timezone_restore_failure_keeps_network_filter(self):
        self.manager.sync(results())
        with patch('guard.network.is_admin', return_value=True):
            self.controller.cut('test')
            self.backend.fail_restore = True
            self.assertTrue(self.controller.restore())
        self.assertNotIn('unlock', self.events)
        self.assertIsNotNone(self.store.state)

    def test_privacy_snapshot_is_persisted_privately(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store('macos', directory)
            try:
                store.write_privacy({'os': 'macos', 'original_timezone': 'Europe/Moscow'})
                self.assertEqual(store.read_privacy()['original_timezone'], 'Europe/Moscow')
                import os
                if os.name != 'nt':
                    self.assertEqual((Path(directory) / 'privacy.json').stat().st_mode & 0o777, 0o600)
                store.clear_privacy()
                self.assertIsNone(store.read_privacy())
            finally:
                store.close()


class NativeCommandTests(unittest.TestCase):
    def test_mac_changes_only_timezone_not_clock_or_ntp(self):
        import subprocess
        response = subprocess.CompletedProcess([], 0, 'Time Zone: Europe/Berlin\n', '')
        with patch('guard.timezone.run', return_value=response) as run, patch('guard.timezone.refresh_clock'):
            MacTimezone().set('Europe/Berlin')
        self.assertEqual([x.args[0] for x in run.call_args_list], [
            ['/usr/sbin/systemsetup', '-settimezone', 'Europe/Berlin'],
            ['/usr/sbin/systemsetup', '-gettimezone'],
        ])

    def test_windows_restores_daylight_saving_preference(self):
        backend = WindowsTimezone()
        with patch('guard.timezone.run') as run, patch.object(backend, 'current', return_value='Pacific Standard Time'), patch.object(backend, 'daylight_disabled', return_value=True):
            backend.restore({'timezone': 'Pacific Standard Time', 'daylight_disabled': True})
        run.assert_called_once_with(['tzutil.exe', '/s', 'Pacific Standard Time_dstoff'])


class AutoPrivacyTests(unittest.TestCase):
    def test_successful_auto_round_changes_timezone_and_keeps_rollback(self):
        from guard.monitor import monitor
        cfg, controller, console, backend = self.setup_monitor()
        with patch('guard.monitor.curl_path'), patch('guard.monitor.check', side_effect=lambda source, *_: Result(source['name'], '8.8.8.8', 'DE', timezone='Europe/Berlin')), patch('guard.network.is_admin', return_value=True), patch('guard.monitor.time.sleep', side_effect=KeyboardInterrupt), contextlib.redirect_stdout(io.StringIO()):
            monitor(cfg, controller, console)
        self.assertEqual(backend.zone, 'Europe/Berlin')
        self.assertEqual(console.timezone, 'Europe/Berlin')
        self.assertFalse(controller.blocked)
        self.assertTrue(controller.has_changes)

    def setup_monitor(self):
        store = MemoryStore()
        backend = FakeTimezone(store)
        manager = TimezoneManager('macos', store, backend)
        controller = Controller('macos', store, FakeAdapters([]), FakeLock([]), manager)
        console = type('Console', (), {'table': lambda *args: None, 'cut': lambda *args: None})()
        cfg = {'proxy': 'direct', 'request_timeout': 0.01, 'check_interval': 0.01, 'startup_timeout': 0.01}
        return cfg, controller, console, backend

    def test_country_disagreement_uses_majority_without_cut(self):
        from guard.monitor import monitor
        cfg, controller, console, backend = self.setup_monitor()

        def check(source, *_):
            return Result(source['name'], '8.8.8.8', 'DE' if source['name'] == 'Cloudflare' else 'NL', timezone='Europe/Amsterdam')

        with patch('guard.monitor.curl_path'), patch('guard.monitor.check', side_effect=check), patch('guard.network.is_admin', return_value=True), patch('guard.monitor.time.sleep', side_effect=KeyboardInterrupt), contextlib.redirect_stdout(io.StringIO()):
            monitor(cfg, controller, console)
        self.assertFalse(controller.blocked)
        self.assertEqual(backend.zone, 'Europe/Amsterdam')

    def test_country_tie_without_timezone_cuts_after_startup_deadline(self):
        from guard.monitor import monitor
        cfg, controller, console, backend = self.setup_monitor()

        def check(source, *_):
            if source['name'] in ('Cloudflare', 'IP.SB'):
                return Result(source['name'], '8.8.8.8', 'DE' if source['name'] == 'Cloudflare' else 'NL', timezone='Europe/Amsterdam')
            return Result(source['name'], error='timeout')

        with patch('guard.monitor.curl_path'), patch('guard.monitor.check', side_effect=check), patch('guard.network.is_admin', return_value=True):
            monitor(cfg, controller, console)
        self.assertTrue(controller.blocked)
        self.assertEqual(backend.calls, [])

    def test_view_only_never_changes_timezone(self):
        from guard.monitor import monitor
        cfg, controller, console, backend = self.setup_monitor()
        with patch('guard.monitor.curl_path'), patch('guard.monitor.check', side_effect=lambda source, *_: Result(source['name'], '8.8.8.8', 'DE', timezone='Europe/Berlin')):
            monitor(cfg, controller, console, once=True)
        self.assertFalse(controller.has_changes)
        self.assertEqual(backend.calls, [])

    def test_timezone_application_failure_cuts_network(self):
        from guard.monitor import monitor
        cfg, controller, console, backend = self.setup_monitor()
        backend.fail_set = True
        with patch('guard.monitor.curl_path'), patch('guard.monitor.check', side_effect=lambda source, *_: Result(source['name'], '8.8.8.8', 'DE', timezone='Europe/Berlin')), patch('guard.network.is_admin', return_value=True):
            monitor(cfg, controller, console)
        self.assertTrue(controller.blocked)
        self.assertIsNotNone(controller.store.read_privacy())

    def test_menu_rolls_back_timezone_without_any_network_cut(self):
        from guard.console import Console
        from vpn_guard import menu
        cfg, controller, _, backend = self.setup_monitor()
        controller.privacy().sync(results())
        with patch('builtins.input', side_effect=['4', '', '0']), patch('guard.network.is_admin', return_value=True), contextlib.redirect_stdout(io.StringIO()) as output:
            menu({'os': 'macos'}, controller, Console())
        self.assertEqual(backend.zone, 'Europe/Moscow')
        self.assertFalse(controller.has_changes)
        self.assertIn('Исходные настройки восстановлены', output.getvalue())


if __name__ == '__main__':
    unittest.main()
