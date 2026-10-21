"""NVML worker safety/ABI tests; fake native calls never allocate GPU memory."""
import ctypes
import io
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from nvml_telemetry import MEMORY_V2_VERSION, MemoryV2, NvmlReader, TelemetryError, memory_used, stream


def library(memory_status=0, temperature_status=0):
    def get_handle(index, pointer):
        assert index == 0
        ctypes.cast(pointer, ctypes.POINTER(ctypes.c_void_p)).contents.value = 123
        return 0

    def get_memory(handle, pointer):
        value = ctypes.cast(pointer, ctypes.POINTER(MemoryV2)).contents
        assert value.version == MEMORY_V2_VERSION
        value.total, value.free, value.reserved, value.used = 1000, 600, 100, 300
        return memory_status

    def get_temperature(handle, sensor, pointer):
        assert sensor == 0
        ctypes.cast(pointer, ctypes.POINTER(ctypes.c_uint)).contents.value = 45
        return temperature_status

    return SimpleNamespace(nvmlInit_v2=Mock(return_value=0), nvmlShutdown=Mock(return_value=0),
                           nvmlDeviceGetHandleByIndex_v2=Mock(side_effect=get_handle),
                           nvmlDeviceGetMemoryInfo_v2=Mock(side_effect=get_memory),
                           nvmlDeviceGetTemperature=Mock(side_effect=get_temperature))


class NvmlTelemetryTests(unittest.TestCase):
    def test_memory_v2_native_abi_and_version(self):
        self.assertEqual(ctypes.sizeof(MemoryV2), 40)
        self.assertEqual([getattr(MemoryV2, name).offset for name, _ in MemoryV2._fields_],
                         [0, 8, 16, 24, 32])
        self.assertEqual(MEMORY_V2_VERSION, 0x02000028)

    def test_reserved_memory_is_included_without_double_counting(self):
        separated = MemoryV2(total=1000, free=600, reserved=100, used=300)
        included = MemoryV2(total=1000, free=600, reserved=100, used=400)
        self.assertEqual(memory_used(separated), 400)
        self.assertEqual(memory_used(included), 400)

    def test_invalid_memory_is_never_a_zero_measurement(self):
        for values in [dict(), dict(total=100, free=101), dict(total=100, used=101),
                       dict(total=100, reserved=101), dict(total=100, free=80, used=30),
                       dict(total=100, free=80, reserved=30)]:
            with self.subTest(values=values), self.assertRaises(TelemetryError):
                memory_used(MemoryV2(**values))

    def test_reads_gpu_zero_and_preserves_lifecycle(self):
        dll = library()
        reader = NvmlReader(dll, clock=Mock(side_effect=[10., 10.1])).start()
        self.assertEqual(reader.sample(), (10., 400, 45))
        reader.close()
        reader.close()
        dll.nvmlInit_v2.assert_called_once_with()
        dll.nvmlShutdown.assert_called_once_with()
        self.assertEqual(dll.nvmlDeviceGetMemoryInfo_v2.restype, ctypes.c_int)

    def test_query_errors_have_no_fallback(self):
        for kwargs in [dict(memory_status=3), dict(temperature_status=15)]:
            reader = NvmlReader(library(**kwargs)).start()
            with self.subTest(kwargs=kwargs), self.assertRaises(TelemetryError):
                reader.sample()
            reader.close()

    def test_failed_device_lookup_closes_nvml(self):
        dll = library()
        dll.nvmlDeviceGetHandleByIndex_v2.side_effect = None
        dll.nvmlDeviceGetHandleByIndex_v2.return_value = 6
        with self.assertRaises(TelemetryError):
            NvmlReader(dll).start()
        dll.nvmlShutdown.assert_called_once_with()

    def test_stream_rounds_memory_up_and_stops_at_deadline(self):
        reader = Mock()
        reader.sample.side_effect = [(0., 1024**2 + 1, 45), (1., 1024**2 + 1, 45)]
        now = [0.]
        output = io.StringIO()
        stream(reader, output, duration=2, clock=lambda: now[0],
               sleep=lambda seconds: now.__setitem__(0, now[0] + seconds))
        self.assertEqual(output.getvalue(), '0.000000000,2,45\n1.000000000,2,45\n')
        self.assertEqual(reader.sample.call_count, 2)

    def test_a_query_finishing_after_deadline_does_not_emit_a_sample(self):
        reader = Mock()
        reader.sample.return_value = (0., 1024, 45)
        output = io.StringIO()
        stream(reader, output, duration=1, clock=Mock(side_effect=[0., 0., 2.]))
        self.assertEqual(output.getvalue(), '')

    def test_runtime_cannot_exceed_authorized_bound(self):
        for duration in [0, -1, 7201, float('inf'), True]:
            with self.subTest(duration=duration), self.assertRaises(ValueError):
                stream(Mock(), io.StringIO(), duration=duration)

    def test_source_stamp_precedes_both_queries_and_late_query_fails_closed(self):
        dll = library()
        now = [10.]
        memory_call = dll.nvmlDeviceGetMemoryInfo_v2.side_effect
        temperature_call = dll.nvmlDeviceGetTemperature.side_effect

        def delayed_memory(*args):
            now[0] += 4.
            return memory_call(*args)

        def delayed_temperature(*args):
            now[0] += 4.1
            return temperature_call(*args)

        dll.nvmlDeviceGetMemoryInfo_v2.side_effect = delayed_memory
        dll.nvmlDeviceGetTemperature.side_effect = delayed_temperature
        reader = NvmlReader(dll, clock=lambda: now[0]).start()
        with self.assertRaisesRegex(TelemetryError, 'freshness limit'):
            reader.sample()
        reader.close()

    def test_stream_preserves_source_stamp_not_receipt_time(self):
        reader = Mock()
        reader.sample.return_value = (10.25, 1024**2, 30)
        output = io.StringIO()
        stream(reader, output, duration=1, clock=Mock(side_effect=[11., 11., 11.25, 11.25, 12.]),
               sleep=Mock())
        self.assertEqual(output.getvalue(), '10.250000000,1,30\n')


if __name__ == '__main__':
    unittest.main()
