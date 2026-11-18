import json
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .packet_lock import lock_for
from .system import adapters_for, is_admin


def state_directory(name):
    if name == 'windows':
        return Path(os.environ.get('ProgramFiles', r'C:\Program Files')) / 'ALRU8 IP Monitor State'
    return Path('/Library/Application Support/ALRU8 IP Monitor' if name == 'macos' else '/var/lib/alru8-ip-monitor')


class Store:
    def __init__(self, name, directory=None):
        self.directory = Path(directory) if directory else state_directory(name)
        self.directory.mkdir(mode=0o700, exist_ok=True)
        if self.directory.is_symlink():
            raise RuntimeError('Небезопасный путь состояния')
        st = self.directory.stat()
        if os.name != 'nt' and (st.st_uid != os.geteuid() or st.st_mode & 0o077):
            raise RuntimeError('Папка состояния должна принадлежать администратору с правами 0700')
        self.path = self.directory / 'state.json'
        fd = os.open(self.directory / 'instance.lock', os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        self.file = os.fdopen(fd, 'r+b')
        try:
            if os.name == 'nt':
                import msvcrt
                self.file.write(b'0')
                self.file.flush()
                self.file.seek(0)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.file.close()
            raise RuntimeError('Другая копия программы уже запущена') from None

    def read(self):
        if not self.path.exists():
            return None
        if self.path.is_symlink():
            raise RuntimeError('Небезопасный файл состояния')
        return json.loads(self.path.read_text(encoding='utf-8'))

    def write(self, state):
        self.write_path(self.path, state)

    def write_path(self, path, state):
        target = path.with_suffix('.tmp')
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(state, stream, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(target, path)

    def read_privacy(self):
        path = self.directory / 'privacy.json'
        if not path.exists():
            return None
        if path.is_symlink():
            raise RuntimeError('Небезопасный файл настроек')
        return json.loads(path.read_text(encoding='utf-8'))

    def write_privacy(self, state):
        self.write_path(self.directory / 'privacy.json', state)

    def clear_privacy(self):
        (self.directory / 'privacy.json').unlink(missing_ok=True)

    def clear(self):
        self.path.unlink(missing_ok=True)

    def close(self):
        self.file.close()


class Controller:
    def __init__(self, name, store, adapters=None, packet_lock=None, timezone_manager=None):
        self.name = name
        self.store = store
        self.adapters = adapters or adapters_for(name)
        self.packet_lock = packet_lock
        self.timezone_manager = timezone_manager

    @property
    def blocked(self):
        return self.store.read() is not None

    @property
    def has_changes(self):
        return self.blocked or self.store.read_privacy() is not None

    def privacy(self):
        if self.timezone_manager is None:
            from .timezone import TimezoneManager
            self.timezone_manager = TimezoneManager(self.name, self.store)
        return self.timezone_manager

    def sync_timezone(self, results):
        if not is_admin():
            raise RuntimeError('Для смены часового пояса нужны права администратора')
        return self.privacy().sync(results)

    def lock(self):
        if self.packet_lock is None:
            self.packet_lock = lock_for(self.name, self.store.write)
        return self.packet_lock

    def cut(self, reason):
        if not is_admin():
            raise RuntimeError('Нет прав администратора для отключения сети')
        state = self.store.read() or {'os': self.name, 'adapters': {}, 'reason': reason, 'time': time.time()}
        if state['os'] != self.name:
            raise RuntimeError('Файл состояния принадлежит другой ОС')
        state['reason'] = reason
        state['complete'] = False
        self.store.write(state)
        failures = []
        kernel_ok = False
        try:
            self.lock().acquire(state)
            kernel_ok = True
        except Exception as exc:
            failures.append(('Системный фильтр', str(exc)))
        results = {}
        for attempt in range(3):
            try:
                current = self.adapters.list()
            except Exception as exc:
                failures.append(('Поиск адаптеров', str(exc)))
                break
            new = [x for x in current if x['id'] not in state['adapters']]
            if not new and attempt:
                break
            for adapter in new:
                try:
                    record = self.adapters.snapshot(adapter)
                    record['restorable'] = True
                except Exception as exc:
                    failures.append((adapter['name'], 'Не сохранено исходное состояние: ' + str(exc)))
                    record = dict(adapter, up=False, services=[], managed=False, connection='', restorable=False)
                state['adapters'][adapter['id']] = record
            self.store.write(state)
            targets = [state['adapters'][x['id']] for x in current]
            if targets:
                with ThreadPoolExecutor(max_workers=min(len(targets), 16)) as pool:
                    pending = {pool.submit(self.adapters.disable, x): x for x in targets}
                    for future in as_completed(pending):
                        adapter = pending[future]
                        try:
                            future.result()
                            results[adapter['name']] = 'отключён'
                        except Exception as exc:
                            results[adapter['name']] = 'ошибка'
                            failures.append((adapter['name'], str(exc)))
        adapters_down = True
        try:
            for adapter in self.adapters.list():
                if self.adapters.up(adapter):
                    adapters_down = False
                    failures.append((adapter['name'], 'Адаптер остаётся включённым'))
        except Exception as exc:
            adapters_down = False
            failures.append(('Проверка отключения', str(exc)))
        state['complete'] = kernel_ok and adapters_down and not failures
        state['failures'] = failures
        self.store.write(state)
        return {'complete': state['complete'], 'kernel': kernel_ok, 'adapters': results, 'errors': failures}

    def restore(self, network_only=False):
        if not is_admin():
            raise RuntimeError('Нужны права администратора')
        state = self.store.read()
        if state is not None and state['os'] != self.name:
            raise RuntimeError('Файл состояния принадлежит другой ОС')
        if not network_only:
            try:
                self.privacy().restore()
            except Exception as exc:
                return [('Часовой пояс', str(exc))]
        if state is None:
            return []
        failures = []
        records = list(state['adapters'].values())
        with ThreadPoolExecutor(max_workers=min(max(len(records), 1), 16)) as pool:
            pending = {}
            for record in records:
                if not record.get('restorable', True):
                    failures.append((record['name'], 'Исходное состояние неизвестно; восстанови вручную'))
                    continue
                pending[pool.submit(self.adapters.restore, record)] = record
            for future in as_completed(pending):
                record = pending[future]
                try:
                    future.result()
                except Exception as exc:
                    failures.append((record['name'], str(exc)))
        if failures:
            return failures
        try:
            if state.get('lock'):
                self.lock().release(state)
        except Exception as exc:
            return [('Системный фильтр', str(exc))]
        self.store.clear()
        return []
