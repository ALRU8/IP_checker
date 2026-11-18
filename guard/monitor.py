import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

from .config import resolve_proxy
from .probe import Result, check, curl_path, sources
from .timezone import GeoDataError


def monitor(cfg, controller, console, once=False):
    if hasattr(console, 'timezone'):
        del console.timezone
    providers = sources()
    names = [x['name'] for x in providers]
    curl_path()
    proxy = resolve_proxy(cfg['proxy'])
    if controller.blocked:
        if once:
            print('Сеть отключена этой программой. Для проверки выбери пункт 1 или 4.')
            return
        print('Включаю сохранённые адаптеры для новой проверки IP…', flush=True)
        errors = controller.restore(network_only=True)
        if errors:
            for name, error in errors:
                print(f'Не удалось восстановить {name}: {error}')
            return
        print('До получения ответов сервисов соединение ещё не проверено.', flush=True)
    pool = ThreadPoolExecutor(max_workers=len(providers))
    started = time.monotonic()
    synced = False
    rounds = 0
    try:
        while True:
            rounds += 1
            round_start = time.monotonic()
            results = {}
            pending = {pool.submit(check, source, cfg['request_timeout'], proxy): source['name'] for source in providers}
            console.table(results, names, 'ПРОВЕРЯЮ IP', proxy, rounds)
            while pending:
                done, _ = wait(pending, timeout=0.1, return_when=FIRST_COMPLETED)
                completed = []
                for future in done:
                    name = pending.pop(future)
                    try:
                        value = future.result()
                    except Exception:
                        value = Result(name, error='Ошибка получения ответа')
                    completed.append(value)
                completed.sort(key=lambda value: value.country != 'RU')
                for value in completed:
                    results[value.name] = value
                    if value.country == 'RU' and not once:
                        reason = f'УТЕЧКА: {value.name} определил РФ, IP {value.ip}'
                        report = controller.cut(reason)
                        for name in names:
                            results.setdefault(name, Result(name, error='Нет ответа к моменту отключения'))
                        console.table(results, names, 'ОБНАРУЖЕНА УТЕЧКА', proxy, rounds)
                        console.cut(report, reason)
                        return
                    console.table(results, names, 'ПРОВЕРЯЮ IP', proxy, rounds)
            confirmed = [x for x in results.values() if x.safe]
            safe = bool(confirmed) and not any(x.country == 'RU' for x in results.values())
            if safe and not once:
                try:
                    console.timezone = controller.sync_timezone(confirmed)
                    synced = True
                except GeoDataError:
                    pass
                except Exception as exc:
                    if hasattr(console, 'timezone'):
                        del console.timezone
                    reason = f'Не удалось подтвердить часовой пояс по IP: {exc}'
                    report = controller.cut(reason)
                    console.table(results, names, 'ПРОВЕРКА ПРИВАТНОСТИ НЕ ПРОЙДЕНА', proxy, rounds)
                    console.cut(report, reason)
                    return
            title = f'IP НЕ ИЗ РФ: ПОДТВЕРДИЛИ {len(confirmed)} ИЗ {len(providers)}' if safe else 'НИ ОДИН СЕРВИС НЕ ПОДТВЕРДИЛ СТРАНУ'
            if once and any(x.country == 'RU' for x in results.values()):
                title = 'ОБНАРУЖЕНА РФ — ПРОСМОТР БЕЗ ОТКЛЮЧЕНИЯ'
            console.table(results, names, title, proxy, rounds)
            if once:
                return
            if time.monotonic() - started >= cfg['startup_timeout'] and (not safe or not synced):
                reason = ('Истекло время начальной проверки: часовой пояс по IP не подтверждён' if safe
                          else 'Ни один сервис не подтвердил безопасный IP')
                report = controller.cut(reason)
                console.cut(report, reason)
                return
            time.sleep(max(0, cfg['check_interval'] - (time.monotonic() - round_start)))
    except KeyboardInterrupt:
        print('\nМониторинг остановлен. Возвращаюсь в меню.\n', flush=True)
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
