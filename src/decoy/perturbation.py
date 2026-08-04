import asyncio
import time
import numpy as np
from enum import Enum

class Regime(Enum):
    R0_BASELINE = "baseline"
    R1_SLOWDOWN = "slowdown"
    R2_JITTER = "jitter"
    R3_FS_LATENCY = "fs_latency"

class PerturbationEngine:
    def __init__(self, seed: int = 42):
        self.rng = np.random.RandomState(seed)
        
    def get_regime_for_command(self, cmd_index: int) -> Regime:
        if cmd_index < 3:
            return Regime.R0_BASELINE
        elif cmd_index < 5:
            return Regime.R1_SLOWDOWN
        elif cmd_index < 7:
            return Regime.R2_JITTER
        else:
            return Regime.R3_FS_LATENCY
            
    async def apply_delay(self, regime: Regime, fs_weight: int = 0) -> int:
        start_ns = time.monotonic_ns()
        
        if regime == Regime.R0_BASELINE:
            delay_ms = 0
        elif regime == Regime.R1_SLOWDOWN:
            delay_ms = 100
        elif regime == Regime.R2_JITTER:
            delay_ms = self.rng.randint(50, 200)
        elif regime == Regime.R3_FS_LATENCY:
            delay_ms = 200 if fs_weight > 0 else 50
        else:
            delay_ms = 0
            
        if delay_ms > 0:
            await asyncio.sleep(delay_ms / 1000.0)
            
        elapsed_ns = time.monotonic_ns() - start_ns
        return elapsed_ns
