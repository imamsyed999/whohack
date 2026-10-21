"""Conservative limits for one owned training process; never changes GPU settings."""
import json
import math
import os
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class Budget:
    # Decimal GB: the user's ceiling is 50 GB, not 50 GiB.
    ceiling_bytes: int = 50_000_000_000
    allocator_bytes: int = 16_000_000_000
    headroom_bytes: int = 5_000_000_000
    max_rss_bytes: int = 24_000_000_000
    min_available_ram_bytes: int = 16_000_000_000
    min_free_disk_bytes: int = 10_000_000_000
    max_output_bytes: int = 2_500_000_000
    max_seconds: int = 5400
    max_temperature_c: int = 82

    def validate(self):
        if any(type(v) is not int or v <= 0 for v in asdict(self).values()):
            raise ValueError('budgets must be positive integer limits')
        if self.ceiling_bytes > 50_000_000_000:
            raise ValueError('the authorized VRAM ceiling is 50,000,000,000 bytes')
        if self.allocator_bytes + self.headroom_bytes >= self.ceiling_bytes:
            raise ValueError('allocator must leave VRAM headroom')
        if self.max_seconds > 7200:
            raise ValueError('a training job is limited to two hours')
        return self

    def fraction(self, device_total):
        self.validate()
        if device_total <= self.allocator_bytes + self.headroom_bytes:
            raise ValueError('insufficient device memory for this allocator budget')
        return self.allocator_bytes / device_total

    def stop_reason(self, sample):
        limits = [
            ('gpu_used_bytes', self.ceiling_bytes - self.headroom_bytes, 'high'),
            ('rss_bytes', self.max_rss_bytes, 'high'),
            ('available_ram_bytes', self.min_available_ram_bytes, 'low'),
            ('free_disk_bytes', self.min_free_disk_bytes, 'low'),
            ('output_bytes', self.max_output_bytes, 'high'),
            ('elapsed_seconds', self.max_seconds, 'high'),
            ('temperature_c', self.max_temperature_c, 'high'),
        ]
        for key, bound, direction in limits:
            value = sample.get(key)
            if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                return 'missing or invalid resource measurement: ' + key
            if (value >= bound if direction == 'high' else value <= bound):
                return 'resource limit reached: ' + key
        return None


class ResourceStop(RuntimeError):
    pass


class NvidiaTelemetry:
    """One owned query stream; stale, invalid or missing samples stop training.

    NVIDIA documents --loop-ms for repeated queries. Keeping the query process
    alive avoids repeatedly initializing its driver client during CUDA work.
    https://docs.nvidia.com/deploy/nvidia-smi/index.html
    """
    def __init__(self, backend='nvidia-smi'):
        if backend not in ('nvidia-smi', 'nvml'):
            raise ValueError('unknown GPU telemetry backend')
        self.backend = backend
        self.process = None
        self.ready = threading.Event()
        self.last = None
        self.error = None
        self.thread = None

    def start(self):
        command = [
            'nvidia-smi', '--id=0', '--query-gpu=memory.used,temperature.gpu',
            '--format=csv,noheader,nounits', '--loop-ms=1000',
        ]
        if self.backend == 'nvml':
            # The base interpreter avoids a Windows venv launcher child, so the
            # exact owned telemetry process can always be terminated on close.
            python = Path(sys._base_executable).resolve(strict=True)
            worker = Path(__file__).with_name('nvml_telemetry.py').resolve(strict=True)
            command = [str(python), '-I', '-u', str(worker)]
        self.process = subprocess.Popen(command,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        def reader():
            try:
                for line in self.process.stdout:
                    self.accept(line)
                    self.ready.set()
            except Exception as exc:
                self.error = type(exc).__name__
                self.ready.set()
        self.thread = threading.Thread(target=reader, daemon=True)
        self.thread.start()
        return self

    def accept(self, line):
        received = time.monotonic()
        values = [float(value.strip()) for value in line.strip().split(',')]
        if self.backend == 'nvml':
            stamp, used, temperature = values
            if (not math.isfinite(stamp) or stamp < 0 or stamp > received
                    or received - stamp > 8 or self.last and stamp <= self.last[0]):
                raise ValueError('stale, invalid or nonadvancing source GPU timestamp')
        else:
            used, temperature = values
            stamp = received
        if not all(math.isfinite(v) and v >= 0 for v in (used, temperature)):
            raise ValueError('invalid GPU sample')
        self.last = (stamp, used * 1024**2, temperature)

    def sample(self):
        if not self.ready.wait(8) or self.error or self.process.poll() is not None or self.last is None:
            raise ResourceStop('GPU telemetry missing, invalid or exited')
        stamp, used, temperature = self.last
        if time.monotonic() - stamp > 8:
            raise ResourceStop('GPU telemetry is stale')
        return used, temperature

    def close(self):
        if self.process is not None:
            if self.process.poll() is None:
                self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
            if self.thread:
                self.thread.join(timeout=2)
            # Closing a pipe while another thread is blocked in read can wait
            # indefinitely for its I/O lock on Windows. The reader is a daemon;
            # close here only after it has actually stopped.
            if self.process.stdout and (not self.thread or not self.thread.is_alive()):
                self.process.stdout.close()


class ResourceGuard:
    """Allocator cap plus independent sampling. Only terminates its own process.

    The allocator cap covers PyTorch's caching allocator, not all CUDA allocations
    or other applications. Total-device monitoring reserves an additional 5 GB.
    A different application can allocate memory between samples: this is not a
    system-wide VRAM reservation or a guarantee against every driver failure.
    """
    def __init__(self, output, budget, forward_idle_seconds=.1, telemetry_backend='nvidia-smi'):
        if (type(forward_idle_seconds) not in (int, float)
                or not math.isfinite(forward_idle_seconds)
                or not .05 <= forward_idle_seconds <= .5):
            raise ValueError('forward idle must be between 50 and 500 milliseconds')
        self.output = Path(output)
        self.budget = budget.validate()
        self.forward_idle_seconds = forward_idle_seconds
        if telemetry_backend not in ('nvidia-smi', 'nvml'):
            raise ValueError('unknown GPU telemetry backend')
        self.telemetry_backend = telemetry_backend
        self.started = time.monotonic()
        self.stopped = threading.Event()
        self.reason = None
        self.peaks = {}
        self.last = {}
        self.thread = None
        self.hook = None
        self.gpu = None
        self.torch = None
        self.next_yield = 0.

    def sample(self):
        import psutil
        used, temperature = self.gpu.sample()
        sample = dict(gpu_used_bytes=used, temperature_c=temperature,
                      rss_bytes=psutil.Process().memory_info().rss,
                      available_ram_bytes=psutil.virtual_memory().available,
                      free_disk_bytes=shutil.disk_usage(self.output).free,
                      output_bytes=sum(p.stat().st_size for p in self.output.rglob('*') if p.is_file()),
                      elapsed_seconds=time.monotonic() - self.started)
        self.last = sample
        for key, value in sample.items():
            if key in ('available_ram_bytes', 'free_disk_bytes'):
                self.peaks[key] = min(self.peaks.get(key, value), value)
            else:
                self.peaks[key] = max(self.peaks.get(key, 0), value)
        return sample

    def write_report(self):
        data = dict(budget=asdict(self.budget), stop_reason=self.reason,
                    peaks=self.peaks, last=self.last,
                    telemetry=self.telemetry_backend + ' persistent 1-second stream; 8-second stale limit',
                    forward_idle_seconds=self.forward_idle_seconds,
                    limitation='Allocator cap is per process; other apps allocate independently.')
        temp = self.output / 'resources.json.tmp'
        temp.write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')
        temp.replace(self.output / 'resources.json')

    def _monitor(self):
        while not self.stopped.wait(2):
            try:
                self.reason = self.reason or self.budget.stop_reason(self.sample())
                self.write_report()
            except Exception as exc:
                self.reason = 'resource monitor failed: ' + type(exc).__name__ + ': ' + str(exc)
            if self.reason:
                # Forward hooks normally raise immediately. A hung kernel gets
                # a grace period, then only this owned Python process exits.
                try:
                    self.write_report()
                except Exception:
                    # Failed disk/report I/O must not disable the watchdog.
                    pass
                if not self.stopped.wait(15):
                    try:
                        if self.gpu:
                            self.gpu.close()
                    finally:
                        # Worker cleanup can fail too. Only this owned trainer
                        # exits; the emergency stop remains unconditional.
                        os._exit(75)
                return

    def check(self, *_):
        if self.reason:
            raise ResourceStop(self.reason)
        # On this WDDM desktop sustained forward/backward submission coincided
        # with NVIDIA query stalls despite a once-per-second cooperative yield.
        # Drain prior work and leave a bounded idle interval before EVERY model
        # forward. This reduces throughput; it never relaxes the stale-sample or
        # memory limits. Hooks receive (module, args); explicit checks do not.
        if _ and self.torch is not None:
            self.torch.cuda.synchronize(0)
            time.sleep(self.forward_idle_seconds)
            if self.reason:
                raise ResourceStop(self.reason)
        # Leave short idle intervals for the desktop and driver telemetry on
        # WDDM. Never continue issuing work while a sample is getting stale.
        if self.torch is not None and time.monotonic() >= self.next_yield:
            self.torch.cuda.synchronize(0)
            time.sleep(.05)
            self.next_yield = time.monotonic() + 1
            if self.gpu and self.gpu.last:
                while time.monotonic() - self.gpu.last[0] > 2:
                    if self.reason:
                        raise ResourceStop(self.reason)
                    try:
                        self.gpu.sample()  # Same eight-second stale limit.
                    except ResourceStop as exc:
                        self.reason = self.reason or str(exc)
                        raise
                    time.sleep(.05)

    def start(self, torch):
        import psutil
        self.gpu = NvidiaTelemetry(self.telemetry_backend).start()
        self.gpu.sample()  # Verify monitoring before any training CUDA allocation.
        if not torch.cuda.is_available():
            raise ResourceStop('CUDA is required for this bounded training job')
        total = torch.cuda.get_device_properties(0).total_memory
        torch.cuda.set_per_process_memory_fraction(self.budget.fraction(total), 0)
        torch.set_num_threads(4)
        self.torch = torch
        if os.name == 'nt':
            psutil.Process().nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
        self.reason = self.budget.stop_reason(self.sample())
        self.write_report()
        self.check()
        self.thread = threading.Thread(target=self._monitor, daemon=True)
        self.thread.start()
        return self

    def attach(self, model):
        self.hook = model.register_forward_pre_hook(self.check)

    def close(self, torch=None):
        self.stopped.set()
        if self.thread:
            self.thread.join(timeout=10)
        if self.hook:
            self.hook.remove()
        if self.gpu:
            self.gpu.close()
        if torch is not None and torch.cuda.is_initialized():
            self.peaks['torch_allocated_bytes'] = torch.cuda.max_memory_allocated(0)
            self.peaks['torch_reserved_bytes'] = torch.cuda.max_memory_reserved(0)
        self.write_report()
