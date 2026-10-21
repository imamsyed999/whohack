"""Isolated, read-only Windows NVML telemetry worker; no CUDA or ML imports.

Stdout is ``source_monotonic_seconds,used_MiB,temperature_C`` once per second,
flushed immediately. The source timestamp precedes both native queries, so
delayed queries or queued pipe output cannot be mistaken for fresh evidence.
The owning trainer retains its independent eight-second stale-data stop.
Only the OS System32 NVML library is loaded; no device settings are changed.

API/layout sources:
https://docs.nvidia.com/deploy/nvml-api/latest/api/group__nvmlDeviceQueries.html
https://docs.nvidia.com/deploy/nvml-api/latest/api/structnvmlMemory__v2__t.html
https://github.com/NVIDIA/go-nvml/blob/main/pkg/nvml/nvml.h
"""
import ctypes
import os
from pathlib import Path
import sys
import threading
import time

MAX_RUNTIME_SECONDS = 7200
MAX_SAMPLE_SECONDS = 8
LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800


class TelemetryError(RuntimeError):
    pass


class MemoryV2(ctypes.Structure):
    _fields_ = [('version', ctypes.c_uint), ('total', ctypes.c_ulonglong),
                ('reserved', ctypes.c_ulonglong), ('free', ctypes.c_ulonglong),
                ('used', ctypes.c_ulonglong)]


MEMORY_V2_VERSION = ctypes.sizeof(MemoryV2) | (2 << 24)


def memory_used(memory):
    """Include system reservations without counting them twice.

    NVML's struct describes allocated and reserved bytes separately, while the
    query documentation also describes versions where ``used`` includes reserved
    memory. Total minus free safely captures both on the physical-device handle.
    """
    if (memory.total <= 0 or any(value > memory.total for value in
                               (memory.free, memory.used, memory.reserved))
            or memory.free + memory.used > memory.total
            or memory.free + memory.reserved > memory.total):
        raise TelemetryError('NVML returned inconsistent device-memory measurements')
    return max(memory.used, memory.total - memory.free)


def system_nvml_path():
    if os.name != 'nt' or ctypes.sizeof(ctypes.c_void_p) != 8:
        raise TelemetryError('NVML worker requires native 64-bit Windows')
    # Query the OS directory; do not trust an environment-variable or PATH DLL.
    kernel = ctypes.WinDLL('kernel32.dll', winmode=LOAD_LIBRARY_SEARCH_SYSTEM32)
    get_directory = kernel.GetSystemDirectoryW
    get_directory.argtypes = [ctypes.POINTER(ctypes.c_wchar), ctypes.c_uint]
    get_directory.restype = ctypes.c_uint
    buffer = ctypes.create_unicode_buffer(32768)
    length = get_directory(buffer, len(buffer))
    if not 0 < length < len(buffer):
        raise TelemetryError('cannot resolve Windows System32 directory')
    path = Path(buffer.value) / 'nvml.dll'
    if not path.is_absolute() or not path.is_file():
        raise TelemetryError('NVML library is missing from Windows System32')
    return path


class NvmlReader:
    def __init__(self, library=None, clock=time.monotonic):
        self.library = library if library is not None else ctypes.CDLL(
            str(system_nvml_path()), winmode=LOAD_LIBRARY_SEARCH_SYSTEM32)
        self.initialized = False
        self.clock = clock
        self.handle = ctypes.c_void_p()
        # Bind only lifecycle and read APIs. Missing exports are fatal.
        self.init = self._bind('nvmlInit_v2', [])
        self.shutdown = self._bind('nvmlShutdown', [])
        self.get_handle = self._bind('nvmlDeviceGetHandleByIndex_v2',
                                     [ctypes.c_uint, ctypes.POINTER(ctypes.c_void_p)])
        self.get_memory = self._bind('nvmlDeviceGetMemoryInfo_v2',
                                     [ctypes.c_void_p, ctypes.POINTER(MemoryV2)])
        self.get_temperature = self._bind('nvmlDeviceGetTemperature',
                                          [ctypes.c_void_p, ctypes.c_uint, ctypes.POINTER(ctypes.c_uint)])

    def _bind(self, name, arguments):
        function = getattr(self.library, name)
        function.argtypes, function.restype = arguments, ctypes.c_int
        return function

    @staticmethod
    def _check(result, operation):
        if result != 0:
            raise TelemetryError(f'{operation} failed with NVML status {result}')

    def start(self):
        self._check(self.init(), 'initialization')
        self.initialized = True
        try:
            self._check(self.get_handle(0, ctypes.byref(self.handle)), 'GPU 0 lookup')
            if not self.handle.value:
                raise TelemetryError('NVML returned an empty physical-device handle')
        except BaseException:
            self.close()
            raise
        return self

    def sample(self):
        if not self.initialized:
            raise TelemetryError('NVML reader is not initialized')
        memory = MemoryV2()
        memory.version = MEMORY_V2_VERSION
        temperature = ctypes.c_uint()
        source_stamp = self.clock()
        self._check(self.get_memory(self.handle, ctypes.byref(memory)), 'device-memory query')
        self._check(self.get_temperature(self.handle, 0, ctypes.byref(temperature)), 'GPU temperature query')
        if self.clock() - source_stamp > MAX_SAMPLE_SECONDS:
            raise TelemetryError('NVML query took longer than the eight-second freshness limit')
        if temperature.value > 200:
            raise TelemetryError('NVML returned an invalid GPU temperature')
        return source_stamp, memory_used(memory), temperature.value

    def close(self):
        if self.initialized:
            self.initialized = False
            self._check(self.shutdown(), 'shutdown')


def stream(reader, output, duration=MAX_RUNTIME_SECONDS, clock=time.monotonic, sleep=time.sleep):
    if type(duration) is not int or not 1 <= duration <= MAX_RUNTIME_SECONDS:
        raise ValueError('worker runtime must be an integer from 1 to 7200 seconds')
    deadline = clock() + duration
    while clock() < deadline:
        source_stamp, used, temperature = reader.sample()
        # A late result must never become an apparently fresh sample at shutdown.
        if clock() >= deadline:
            break
        # Round UP to an integral MiB: serialization must not understate bytes.
        used_mib = (used + 1024**2 - 1) // 1024**2
        print(f'{source_stamp:.9f},{used_mib},{temperature}', file=output, flush=True)
        sleep(min(1., max(0., deadline - clock())))


def main():
    # This watchdog also bounds a DLL call that never returns. The trainer's
    # much shorter independent stale limit remains the primary stop mechanism.
    watchdog = threading.Timer(MAX_RUNTIME_SECONDS, lambda: os._exit(75))
    watchdog.daemon = True
    watchdog.start()
    reader = None
    try:
        if len(sys.argv) != 1:
            raise TelemetryError('this worker accepts no arguments')
        reader = NvmlReader().start()
        stream(reader, sys.stdout)
        return 0
    except Exception as exc:
        print(f'NVML telemetry failed: {type(exc).__name__}: {exc}', file=sys.stderr, flush=True)
        return 1
    finally:
        try:
            if reader:
                reader.close()
        finally:
            watchdog.cancel()


if __name__ == '__main__':
    raise SystemExit(main())
