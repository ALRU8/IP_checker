import ctypes as C
import json
import re
import shutil
import uuid

from .system import run

TABLE = 'alru8_offline'


class MacLock:
    def __init__(self, save):
        self.save = save

    def boot_id(self):
        text = run(['/usr/sbin/sysctl', '-n', 'kern.boottime']).stdout
        match = re.search(r'sec\s*=\s*(\d+)', text)
        if not match:
            raise RuntimeError('Не удалось определить загрузку macOS')
        return match[1]

    def acquire(self, state):
        boot = self.boot_id()
        if 'pf_rules' not in state or state.get('pf_boot') != boot:
            state['pf_rules'] = run(['/sbin/pfctl', '-sr']).stdout
            state['pf_boot'] = boot
            state.pop('pf_token', None)
            state['lock'] = 'macos'
            self.save(state)
        if not state.get('pf_token'):
            result = run(['/sbin/pfctl', '-E'])
            match = re.search(r'Token\s*:\s*(\d+)', result.stdout + result.stderr)
            if not match:
                raise RuntimeError('PF не вернул enable token')
            state['pf_token'] = match[1]
            self.save(state)
        run(['/sbin/pfctl', '-R', '-f', '-'], 'block drop quick all\n')
        run(['/sbin/pfctl', '-F', 'states'])
        rules = run(['/sbin/pfctl', '-sr']).stdout
        meaningful = [x.strip() for x in rules.splitlines() if x.strip() and not x.lstrip().startswith('scrub')]
        if meaningful != ['block drop quick all']:
            raise RuntimeError('Не удалось подтвердить полный запрет PF')
        if not re.search(r'Status:\s*Enabled', run(['/sbin/pfctl', '-s', 'info']).stdout):
            raise RuntimeError('PF не подтвердил включение')

    def release(self, state):
        if state.get('pf_boot') != self.boot_id():
            return
        if 'pf_rules' in state:
            run(['/sbin/pfctl', '-R', '-f', '-'], state['pf_rules'])
        if state.get('pf_token'):
            run(['/sbin/pfctl', '-X', state['pf_token']])


class LinuxLock:
    def __init__(self, save):
        self.save = save
        self.nft = shutil.which('nft')
        if not self.nft:
            raise RuntimeError('Не найден nft: установи nftables')

    def acquire(self, state):
        exists = False
        try:
            run([self.nft, 'list', 'table', 'inet', TABLE])
            exists = True
        except RuntimeError:
            pass
        if exists and state.get('lock') != 'linux':
            raise RuntimeError('Имя firewall-таблицы уже занято')
        state['lock'] = 'linux'
        self.save(state)
        text = (f'delete table inet {TABLE}\n' if exists else '') + f'''table inet {TABLE} {{
 chain output {{ type filter hook output priority -300; policy drop; }}
 chain input {{ type filter hook input priority -300; policy drop; }}
 chain forward {{ type filter hook forward priority -300; policy drop; }}
}}
'''
        run([self.nft, '-f', '-'], text)
        result = run([self.nft, '-j', 'list', 'table', 'inet', TABLE]).stdout
        chains = [x['chain'] for x in json.loads(result)['nftables'] if 'chain' in x]
        if {x.get('hook') for x in chains if x.get('policy') == 'drop'} != {'input', 'output', 'forward'}:
            raise RuntimeError('Не удалось подтвердить запрет nftables')

    def release(self, state):
        if state.get('lock') == 'linux':
            try:
                run([self.nft, 'list', 'table', 'inet', TABLE])
            except RuntimeError:
                return
            run([self.nft, 'delete', 'table', 'inet', TABLE])


U8, U16, U32, U64, PTR = C.c_uint8, C.c_uint16, C.c_uint32, C.c_uint64, C.c_void_p


class Guid(C.Structure):
    _fields_ = [('data', U8 * 16)]

    @classmethod
    def of(cls, value):
        return cls((U8 * 16).from_buffer_copy(uuid.UUID(value).bytes_le))


class Blob(C.Structure):
    _fields_ = [('size', U32), ('data', PTR)]


class ValueUnion(C.Union):
    _fields_ = [('u8', U8), ('ptr', PTR)]


class Value(C.Structure):
    _fields_ = [('type', U32), ('value', ValueUnion)]


class Display(C.Structure):
    _fields_ = [('name', C.c_wchar_p), ('description', C.c_wchar_p)]


class Action(C.Structure):
    _fields_ = [('type', U32), ('key', Guid)]


class Context(C.Union):
    _fields_ = [('raw', U64), ('key', Guid)]


class Filter(C.Structure):
    _fields_ = [('key', Guid), ('display', Display), ('flags', U32), ('provider', PTR), ('data', Blob),
                ('layer', Guid), ('sublayer', Guid), ('weight', Value), ('count', U32), ('conditions', PTR),
                ('action', Action), ('context', Context), ('reserved', PTR), ('id', U64), ('effective', Value)]


class Sublayer(C.Structure):
    _fields_ = [('key', Guid), ('display', Display), ('flags', U32), ('provider', PTR), ('data', Blob), ('weight', U16)]


SUBLAYER = '461792bd-3156-4b07-b11b-ff38031492db'
LAYERS = (
    'c38d57d1-05a7-4c33-904f-7fbceee60e82', '4a72393b-319f-44bc-84c3-ba54dcb3b6b4',
    'e1cd9fe7-f4b5-4273-96c0-592e487b8650', 'a3b42c97-9f04-4672-b87e-cee9c483257f',
    '09e61aea-d214-46e2-9b21-b26b0b2f28c8', 'e1735bde-013f-4655-b351-a49e15762df0',
    '5926dfc8-e3cf-4426-a283-dc393f5d0f9d', '634a869f-fc23-4b90-b0c1-bf620a36ae6f',
    'a82acc24-4ee1-4ee1-b465-fd1d25cb10a4', '7b964818-19c7-493a-b71f-832c3684d28c',
    '1e5c9fae-8a84-4135-a331-950b54229ecd', 'a3b3ab6b-3564-488c-9117-f34e82142763',
    'c86fd1bf-21cd-497e-a0bb-17425c885c58', 'f52032cb-991c-46e7-971d-2601459a91ca',
)


def wincheck(code):
    if code:
        raise RuntimeError(f'WFP: 0x{code:08x}')


class WindowsLock:
    def __init__(self, save):
        if C.sizeof(PTR) != 8:
            raise RuntimeError('Нужен 64-битный Python')
        self.save = save
        self.api = C.WinDLL('fwpuclnt.dll')
        self.handle = PTR()
        signatures = {
            'FwpmEngineOpen0': [C.c_wchar_p, U32, PTR, PTR, C.POINTER(PTR)],
            'FwpmEngineClose0': [PTR],
            'FwpmTransactionBegin0': [PTR, U32], 'FwpmTransactionCommit0': [PTR], 'FwpmTransactionAbort0': [PTR],
            'FwpmSubLayerAdd0': [PTR, C.POINTER(Sublayer), PTR], 'FwpmSubLayerDeleteByKey0': [PTR, C.POINTER(Guid)],
            'FwpmFilterAdd0': [PTR, C.POINTER(Filter), PTR, C.POINTER(U64)],
            'FwpmFilterDeleteByKey0': [PTR, C.POINTER(Guid)],
        }
        for name, args in signatures.items():
            getattr(self.api, name).argtypes = args
            getattr(self.api, name).restype = U32
        wincheck(self.api.FwpmEngineOpen0(None, 10, None, None, C.byref(self.handle)))

    def acquire(self, state):
        keys = [str(uuid.uuid5(uuid.UUID(SUBLAYER), layer)) for layer in LAYERS]
        state.update(lock='windows', filter_keys=keys)
        self.save(state)
        wincheck(self.api.FwpmTransactionBegin0(self.handle, 0))
        try:
            sub = Sublayer()
            sub.key, sub.display, sub.weight = Guid.of(SUBLAYER), Display('ALRU8 offline', 'Block every network connection'), 0xFFFF
            error = self.api.FwpmSubLayerAdd0(self.handle, C.byref(sub), None)
            if error not in (0, 0x80320009):
                wincheck(error)
            for key, layer in zip(keys, LAYERS):
                error = self.api.FwpmFilterDeleteByKey0(self.handle, C.byref(Guid.of(key)))
                if error not in (0, 0x80320003):
                    wincheck(error)
                item = Filter()
                item.key, item.layer, item.sublayer = Guid.of(key), Guid.of(layer), Guid.of(SUBLAYER)
                item.display = Display('ALRU8 BLOCK ALL', 'No exceptions')
                item.weight = Value(1, ValueUnion(u8=15))
                item.action.type = 0x1001
                fid = U64()
                wincheck(self.api.FwpmFilterAdd0(self.handle, C.byref(item), None, C.byref(fid)))
            wincheck(self.api.FwpmTransactionCommit0(self.handle))
        except BaseException:
            self.api.FwpmTransactionAbort0(self.handle)
            raise

    def release(self, state):
        wincheck(self.api.FwpmTransactionBegin0(self.handle, 0))
        try:
            for key in state.get('filter_keys', []):
                error = self.api.FwpmFilterDeleteByKey0(self.handle, C.byref(Guid.of(key)))
                if error not in (0, 0x80320003):
                    wincheck(error)
            error = self.api.FwpmSubLayerDeleteByKey0(self.handle, C.byref(Guid.of(SUBLAYER)))
            if error not in (0, 0x80320007):
                wincheck(error)
            wincheck(self.api.FwpmTransactionCommit0(self.handle))
        except BaseException:
            self.api.FwpmTransactionAbort0(self.handle)
            raise

    def __del__(self):
        if getattr(self, 'handle', None) and getattr(self, 'api', None):
            self.api.FwpmEngineClose0(self.handle)


def lock_for(name, save):
    return {'macos': MacLock, 'linux': LinuxLock, 'windows': WindowsLock}[name](save)
