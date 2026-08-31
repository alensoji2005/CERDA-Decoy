import asyncio
import time
import numpy as np
from enum import Enum
from typing import Optional

class Regime(Enum):
    R0_BASELINE = "baseline"
    R1_SLOWDOWN = "slowdown"
    R2_JITTER = "jitter"
    R3_FS_LATENCY = "fs_latency"

class PerturbationEngine:
    def __init__(self, seed: int = 42, use_rl: bool = False, default_schedule: list = None):
        self.rng = np.random.RandomState(seed)
        self.use_rl = use_rl
        self.rl_scheduler = None
        self.default_schedule = default_schedule or [
            (0, Regime.R0_BASELINE),
            (5, Regime.R1_SLOWDOWN),
            (10, Regime.R2_JITTER),
            (15, Regime.R3_FS_LATENCY)
        ]
        if self.use_rl:
            from .rl_scheduler import RLPerturbationScheduler
            self.rl_scheduler = RLPerturbationScheduler(seed=seed)
        
    def get_regime_for_command(self, cmd_index: int, last_regime: str = "baseline", delta_t_ns: int = 0) -> Regime:
        if self.use_rl and self.rl_scheduler is not None:
            return self.rl_scheduler.select_action(cmd_index, last_regime, delta_t_ns)
            
        selected_regime = Regime.R0_BASELINE
        for start_idx, regime in self.default_schedule:
            if cmd_index >= start_idx:
                selected_regime = regime
        return selected_regime
            
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
