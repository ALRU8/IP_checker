import os
import sys
from datetime import datetime

from .banner import show


class Console:
    def __init__(self):
        self.interactive = sys.stdout.isatty()
        self.color = self.interactive and 'NO_COLOR' not in os.environ and os.environ.get('TERM') != 'dumb'

    def paint(self, text, color):
        return f'\033[{color}m{text}\033[0m' if self.color else text

    def header(self, subtitle):
        if self.interactive and self.color:
            print('\033[2J\033[H', end='')
        show(subtitle)

    def table(self, results, source_names, title, proxy, rounds=0, started=None):
        self.header('IP MONITOR')
        print(self.paint('  ' + title, '36'))
        print('  ' + datetime.now().strftime('%d.%m.%Y %H:%M:%S') + f'  |  раунд {rounds}  |  ' + ('локальный прокси' if proxy else 'системный маршрут'))
        print('  Часовой пояс системы по IP: ' + getattr(self, 'timezone', 'ещё не подтверждён'))
        print('\n  СЕРВИС         ВНЕШНИЙ IP                              СТРАНА   РЕЗУЛЬТАТ')
        print('  ' + '─' * 82)
        for name in source_names:
            result = results.get(name)
            if result is None:
                print(f'  {name:<14} {"…":<39} {"—":<8} ожидание')
                continue
            status = result.error or ('РОССИЯ' if result.country == 'RU' else 'OK')
            row = f'  {name:<14} {result.ip or "—":<39} {result.country or "—":<8} {status}'
            print(self.paint(row, '31' if result.country == 'RU' else '33' if result.error else '32'))
            if result.timezone:
                print(self.paint('                 GeoIP timezone: ' + result.timezone, '36'))
        print('\n  Ctrl+C — остановить мониторинг и вернуться в меню.')
        sys.stdout.flush()

    def cut(self, report, reason):
        title = 'ИНТЕРНЕТ ВЫКЛЮЧЕН' if report['complete'] else 'ОТКЛЮЧЕНИЕ ПОДТВЕРЖДЕНО НЕ ПОЛНОСТЬЮ'
        print('\n' + self.paint('  ╔' + '═' * 72 + '╗', '31;1'))
        print(self.paint('  ' + title, '31;1'))
        print(self.paint('  ' + reason, '31;1'))
        print(self.paint('  ╚' + '═' * 72 + '╝', '31;1'))
        print('  Фильтр пакетов: ' + ('полный запрет без исключений' if report['kernel'] else 'ошибка установки'))
        for name, status in report['adapters'].items():
            print(f'  {name}: {status}')
        for name, error in report['errors']:
            print(self.paint(f'  ОШИБКА / {name}: {error}', '31'))
        print('\n  Проверки прекращены. Сеть сама не включится.')
        print('  Пункт 4 главного меню откатывает сеть и часовой пояс.')
        sys.stdout.flush()
