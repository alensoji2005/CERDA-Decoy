"""
Acceptance Tests for Reinforcement Learning Perturbation Scheduler
Patent Claim 5 Verification:
- Test RL1: Action selection & regime outputs
- Test RL2: Q-learning Q-value update convergence
- Test RL3: Policy model serialization (save/load)
- Test RL4: Integration with PerturbationEngine & DecoyServer
"""

import os
import shutil
import tempfile
import pytest

from src.decoy import (
    RLPerturbationScheduler,
    PerturbationEngine,
    Regime
)

@pytest.fixture
def temp_dir():
    d = tempfile.mkdtemp()
    yield d
    shutil.rmtree(d, ignore_errors=True)

def test_rl1_action_selection(temp_dir):
    """Test RL1: Verifies that RL agent selects valid actions across early, mid, late states."""
    scheduler = RLPerturbationScheduler(seed=42, model_dir=temp_dir)
    
    # Early state
    a1 = scheduler.select_action(command_index=0, last_regime="baseline", delta_t_ns=0)
    assert isinstance(a1, Regime)
    
    # Mid state
    a2 = scheduler.select_action(command_index=8, last_regime="slowdown", delta_t_ns=150_000_000)
    assert isinstance(a2, Regime)
    
    # Late state
    a3 = scheduler.select_action(command_index=20, last_regime="jitter", delta_t_ns=50_000_000)
    assert isinstance(a3, Regime)

def test_rl2_q_value_updates(temp_dir):
    """Test RL2: Verifies Q-table updates upon receiving positive rewards."""
    scheduler = RLPerturbationScheduler(alpha=0.5, gamma=0.9, epsilon=0.0, seed=42, model_dir=temp_dir)
    
    state_key = "early:baseline:fast"
    action = Regime.R3_FS_LATENCY
    
    # Q-value before update should be 0.0
    initial_q = scheduler.q_table.get(state_key, {}).get(action.value, 0.0)
    assert initial_q == 0.0
    
    # Apply a high reward update
    reward = scheduler.compute_reward(delta_t_ns=200_000_000, regime=action)
    scheduler.update(
        command_index=0, last_regime="baseline", delta_t_ns=1_000_000,
        action=action, reward=reward,
        next_command_index=1, next_delta_t_ns=200_000_000
    )
    
    updated_q = scheduler.q_table[state_key][action.value]
    assert updated_q > initial_q, f"Expected Q-value increase, got {updated_q}"

def test_rl3_policy_serialization(temp_dir):
    """Test RL3: Verifies saving and reloading the learned Q-table policy."""
    scheduler = RLPerturbationScheduler(seed=42, model_dir=temp_dir)
    
    # Force state entries
    scheduler.select_action(0, "baseline", 0)
    scheduler.update(0, "baseline", 0, Regime.R1_SLOWDOWN, 5.0, 1, 100_000_000)
    
    policy_file = "test_policy.json"
    scheduler.save_policy(policy_file)
    assert os.path.exists(os.path.join(temp_dir, policy_file))
    
    # Load into new scheduler
    new_scheduler = RLPerturbationScheduler(seed=42, model_dir=temp_dir)
    new_scheduler.load_policy(policy_file)
    
    assert new_scheduler.q_table == scheduler.q_table

def test_rl4_engine_integration():
    """Test RL4: Verifies PerturbationEngine seamlessly uses RL when enabled."""
    engine_rl = PerturbationEngine(seed=42, use_rl=True)
    assert engine_rl.use_rl is True
    assert engine_rl.rl_scheduler is not None
    
    regime = engine_rl.get_regime_for_command(cmd_index=2, last_regime="baseline", delta_t_ns=1_000_000)
    assert isinstance(regime, Regime)
