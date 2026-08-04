import os
import json
import numpy as np
from typing import Tuple, Dict, Any
from .perturbation import Regime

class RLPerturbationScheduler:
    """
    Contextual Q-Learning Agent for Dynamic Perturbation Regime Selection.
    Implements Patent Claim 5: Reinforcement learning agent dynamically selecting
    a next perturbation regime to maximize information gain regarding threat actor response characteristics.
    """
    def __init__(self, alpha: float = 0.1, gamma: float = 0.9, epsilon: float = 0.10, seed: int = 42, model_dir: str = "models"):
        self.alpha = alpha
        self.gamma = gamma
        self.epsilon = epsilon
        self.rng = np.random.RandomState(seed)
        self.model_dir = model_dir
        self.q_table: Dict[str, Dict[str, float]] = {}
        self.actions = [Regime.R0_BASELINE, Regime.R1_SLOWDOWN, Regime.R2_JITTER, Regime.R3_FS_LATENCY]
        
    def _discretize_state(self, command_index: int, last_regime: str, delta_t_ns: int) -> str:
        # State band: early (0-4), mid (5-14), late (15+)
        if command_index < 5:
            band = "early"
        elif command_index < 15:
            band = "mid"
        else:
            band = "late"
            
        # Delta_t level (fast < 10ms, medium 10-200ms, slow > 200ms)
        dt_ms = delta_t_ns / 1e6
        if dt_ms < 10:
            speed = "fast"
        elif dt_ms < 200:
            speed = "medium"
        else:
            speed = "slow"
            
        return f"{band}:{last_regime}:{speed}"

    def select_action(self, command_index: int, last_regime: str = "baseline", delta_t_ns: int = 0) -> Regime:
        state = self._discretize_state(command_index, last_regime, delta_t_ns)
        
        if state not in self.q_table:
            self.q_table[state] = {a.value: 0.0 for a in self.actions}
            
        # Epsilon-greedy exploration
        if self.rng.rand() < self.epsilon:
            return self.rng.choice(self.actions)
            
        # Exploitation (best Q-value)
        best_action_val = max(self.q_table[state].values())
        best_actions = [a for a in self.actions if self.q_table[state][a.value] == best_action_val]
        return self.rng.choice(best_actions)

    def compute_reward(self, delta_t_ns: int, regime: Regime, session_disconnected: bool = False) -> float:
        if session_disconnected:
            return -10.0  # Heavy penalty for disconnecting the session early
            
        dt_ms = delta_t_ns / 1e6
        
        # Reward distinctiveness of attacker reaction based on regime
        if regime == Regime.R0_BASELINE:
            reward = 1.0 if dt_ms < 50 else -0.5
        elif regime == Regime.R1_SLOWDOWN:
            # High reward if attacker slows down in response
            reward = 3.0 if dt_ms > 100 else 0.5
        elif regime == Regime.R2_JITTER:
            # Reward variance extraction
            reward = 2.5 if 20 <= dt_ms <= 300 else 1.0
        elif regime == Regime.R3_FS_LATENCY:
            reward = 4.0 if dt_ms > 150 else 1.0
        else:
            reward = 0.0
            
        return reward

    def update(self, command_index: int, last_regime: str, delta_t_ns: int, action: Regime, reward: float, next_command_index: int, next_delta_t_ns: int):
        state = self._discretize_state(command_index, last_regime, delta_t_ns)
        next_state = self._discretize_state(next_command_index, action.value, next_delta_t_ns)
        
        if state not in self.q_table:
            self.q_table[state] = {a.value: 0.0 for a in self.actions}
        if next_state not in self.q_table:
            self.q_table[next_state] = {a.value: 0.0 for a in self.actions}
            
        current_q = self.q_table[state][action.value]
        max_next_q = max(self.q_table[next_state].values())
        
        # Q-learning formula
        new_q = current_q + self.alpha * (reward + self.gamma * max_next_q - current_q)
        self.q_table[state][action.value] = float(new_q)

    def save_policy(self, filename: str = "rl_policy.json"):
        os.makedirs(self.model_dir, exist_ok=True)
        path = os.path.join(self.model_dir, filename)
        with open(path, "w") as f:
            json.dump(self.q_table, f, indent=2)

    def load_policy(self, filename: str = "rl_policy.json"):
        path = os.path.join(self.model_dir, filename)
        if os.path.exists(path):
            with open(path, "r") as f:
                self.q_table = json.load(f)
