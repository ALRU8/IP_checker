import ctypes
import json
import re
import time
from pathlib import Path

from .system import run

ZONES = json.loads((Path(__file__).parent / 'data/timezones.json').read_text(encoding='utf-8'))


def target_zone(results):
    if not results or not all(value.safe for value in results):
        raise RuntimeError('Часовой пояс нельзя менять без безопасных ответов GeoIP')
    countries = {value.country for value in results}
    if len(countries) != 1:
        raise RuntimeError('GeoIP-сервисы определили разные страны')
    country = next(iter(countries))
    zones = {value.timezone for value in results if value.timezone}
    if len(zones) != 1:
        raise RuntimeError('GeoIP не сообщил единственный часовой пояс')
    zone = next(iter(zones))
    if country not in ZONES.get(zone, []):
        raise RuntimeError('Часовой пояс GeoIP не соответствует определённой стране')
    return zone


def refresh_clock():
    if hasattr(time, 'tzset'):
        time.tzset()


class MacTimezone:
    def matches(self, state):
        return self.current() == state['timezone']

    def snapshot(self):
        return {'timezone': self.current()}

    def restore(self, state):
        self.set(state['timezone'])

    def current(self):
        text = run(['/usr/sbin/systemsetup', '-gettimezone']).stdout.strip()
        if not text.startswith('Time Zone: '):
            raise RuntimeError('macOS не сообщила текущий часовой пояс')
        return text.partition(': ')[2]

    def native(self, zone):
        return zone

    def set(self, zone):
        run(['/usr/sbin/systemsetup', '-settimezone', zone])
        if self.current() != zone:
            raise RuntimeError('macOS не подтвердила смену часового пояса')
        refresh_clock()


class LinuxTimezone:
    def matches(self, state):
        return self.current() == state['timezone']

    def snapshot(self):
        return {'timezone': self.current()}

    def restore(self, state):
        self.set(state['timezone'])

    def current(self):
        value = run(['timedatectl', 'show', '--property=Timezone', '--value']).stdout.strip()
        if not value or not re.fullmatch(r'[A-Za-z0-9_+./-]+', value):
            raise RuntimeError('Linux не сообщил текущий часовой пояс')
        return value

    def native(self, zone):
        return zone

    def set(self, zone):
        run(['timedatectl', 'set-timezone', zone])
        if self.current() != zone:
            raise RuntimeError('Linux не подтвердил смену часового пояса')
        refresh_clock()


class WindowsTimezone:
    def matches(self, state):
        return self.current() == state['timezone'] and self.daylight_disabled() == state['daylight_disabled']

    def daylight_disabled(self):
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Control\TimeZoneInformation') as key:
            try:
                return bool(winreg.QueryValueEx(key, 'DynamicDaylightTimeDisabled')[0])
            except FileNotFoundError:
                return False

    def snapshot(self):
        return {'timezone': self.current(), 'daylight_disabled': self.daylight_disabled()}

    def restore(self, state):
        original = state['timezone']
        run(['tzutil.exe', '/s', original + ('_dstoff' if state['daylight_disabled'] else '')])
        if self.current() != original or self.daylight_disabled() != state['daylight_disabled']:
            raise RuntimeError('Windows не подтвердила восстановление часового пояса и настройки DST')

    def current(self):
        return run(['tzutil.exe', '/g']).stdout.strip()

    def native(self, zone):
        api = ctypes.WinDLL('icu.dll')
        convert = api.ucal_getWindowsTimeZoneID
        convert.argtypes = [ctypes.c_wchar_p, ctypes.c_int32, ctypes.c_wchar_p,
                            ctypes.c_int32, ctypes.POINTER(ctypes.c_int32)]
        convert.restype = ctypes.c_int32
        output = ctypes.create_unicode_buffer(256)
        error = ctypes.c_int32()
        length = convert(zone, len(zone), output, len(output), ctypes.byref(error))
        if error.value > 0 or not 0 < length < len(output):
            raise RuntimeError('Windows не смогла преобразовать IANA-часовой пояс')
        return output.value

    def set(self, zone):
        if not zone:
            raise RuntimeError('Пустой часовой пояс Windows')
        run(['tzutil.exe', '/s', zone])
        if self.current() != zone:
            raise RuntimeError('Windows не подтвердила смену часового пояса')


def backend_for(name):
    return {'macos': MacTimezone, 'linux': LinuxTimezone, 'windows': WindowsTimezone}[name]()


class TimezoneManager:
    def __init__(self, name, store, backend=None):
        self.name = name
        self.store = store
        self.backend = backend

    def get_backend(self):
        if self.backend is None:
            self.backend = backend_for(self.name)
        return self.backend

    def sync(self, results):
        zone = target_zone(results)
        backend = self.get_backend()
        native = backend.native(zone)
        current = backend.current()
        if not current:
            raise RuntimeError('Не удалось сохранить исходный часовой пояс')
        state = self.store.read_privacy()
        if state is not None:
            if state['os'] != self.name:
                raise RuntimeError('Снимок настроек принадлежит другой ОС')
            if state.get('status') == 'applied' and current != state['applied_native']:
                state['status'] = 'drift'
                self.store.write_privacy(state)
                raise RuntimeError('Системный часовой пояс изменён извне — возможен возврат реального местоположения')
            if state.get('status') == 'applied' and current == native and state.get('target_timezone') == zone:
                return zone
        else:
            original = backend.snapshot()
            if original.get('timezone') != current:
                raise RuntimeError('Часовой пояс изменился во время сохранения исходных настроек')
            state = {'os': self.name, 'original_timezone': current, 'original_settings': original, 'created': time.time()}
        state.update(target_timezone=zone, applied_native=native, status='pending')
        self.store.write_privacy(state)
        if current != native:
            backend.set(native)
        if backend.current() != native:
            raise RuntimeError('Часовой пояс не соответствует GeoIP')
        state['status'] = 'applied'
        self.store.write_privacy(state)
        return zone

    def restore(self):
        state = self.store.read_privacy()
        if state is None:
            return
        if state['os'] != self.name:
            raise RuntimeError('Снимок настроек принадлежит другой ОС')
        backend = self.get_backend()
        original = state['original_timezone']
        settings = state.get('original_settings', {'timezone': original})
        if not backend.matches(settings):
            backend.restore(settings)
        if backend.current() != original:
            raise RuntimeError('Исходный часовой пояс не восстановлен')
        self.store.clear_privacy()
