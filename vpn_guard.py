#!/usr/bin/env python3
import sys
from pathlib import Path

from guard.config import load
from guard.console import Console
from guard.monitor import monitor
from guard.network import Controller, Store
from guard.system import elevate


def menu(cfg, controller, console):
    while True:
        console.header('ГЛАВНОЕ МЕНЮ')
        print('  ОС: ' + cfg['os'])
        state = controller.store.read()
        status = 'программа не отключала адаптеры' if state is None else 'отключена программой' if state.get('complete') else 'есть незавершённое отключение — проверь сообщения об ошибках'
        print('  Сеть: ' + status)
        privacy = controller.store.read_privacy()
        if privacy is not None:
            value = privacy.get('target_timezone', '—') if privacy.get('status') == 'applied' else 'изменение не подтверждено'
            print('  Подтверждённый пояс сеанса: ' + value + ' | исходная настройка сохранена для отката')
        print('  Мониторинг: не активен\n')
        print('  [1] АВТО — проверять IP, отключать при РФ')
        print('  [2] Показать IP по сервисам (без отключения)')
        print('  [3] ОТКЛЮЧИТЬ ВЕСЬ ИНТЕРНЕТ')
        print('  [4] Откатить всё: сеть и исходный часовой пояс')
        print('  [0] Выход\n')
        try:
            choice = input('  Выбор: ').strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        try:
            if choice == '0':
                return 0
            if choice in ('1', '2'):
                monitor(cfg, controller, console, once=choice == '2')
            elif choice == '3':
                report = controller.cut('Сеть отключена вручную пользователем')
                console.cut(report, 'РУЧНОЕ ОТКЛЮЧЕНИЕ')
            elif choice == '4':
                if not controller.has_changes:
                    print('  Нет сохранённых изменений. Настройки не изменены.')
                else:
                    print('  Восстанавливаю исходные настройки. Проверка страны в этом пункте не выполняется…', flush=True)
                    errors = controller.restore()
                    if errors:
                        for name, error in errors:
                            print(f'  ОШИБКА / {name}: {error}')
                        print('  Полное восстановление не подтверждено.')
                    else:
                        print('  Исходные настройки восстановлены. Подключение Wi-Fi может занять несколько секунд.')
            else:
                print('  Выбери 0, 1, 2, 3 или 4.')
                continue
        except KeyboardInterrupt:
            print('\n  Действие прервано. Состояние сети сохранено.')
        except Exception as exc:
            print(f'\n  ОШИБКА: {exc}')
            print('  Успешное отключение или включение не подтверждено.')
        try:
            input('\n  Enter — главное меню…')
        except (EOFError, KeyboardInterrupt):
            return 0


def main():
    if len(sys.argv) != 1:
        print('Запуск без параметров: python3 vpn_guard.py. Режим выбирается в меню.')
        return 2
    cfg = load()
    if elevate(Path(__file__).resolve()):
        return 0
    console = Console()
    store = Store(cfg['os'])
    try:
        controller = Controller(cfg['os'], store)
        return menu(cfg, controller, console)
    finally:
        store.close()


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print('\nВыход. Сеть автоматически не изменяется.')
        raise SystemExit(130)
    except Exception as exc:
        print(f'Ошибка запуска: {exc}', file=sys.stderr)
        raise SystemExit(1)
