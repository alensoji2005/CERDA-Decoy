import pytest
from src.decoy.pseudo_fs import PseudoFilesystem

def test_llm_honeytoken_generation():
    fs = PseudoFilesystem("test-session")
    
    # Target an AWS credentials file
    output, _, _ = fs.execute_command("cat ~/.aws/credentials")
    
    # Assert honeytoken is present
    assert "AKIAIOSFODNN7EXAMPLE" in output
    assert "aws_secret_access_key" in output

def test_llm_context_awareness():
    fs = PseudoFilesystem("test-session")
    
    # Give some history
    fs.execute_command("docker ps")
    
    # Request generic file
    output, _, _ = fs.execute_command("cat /tmp/config.json")
    
    # Output should include docker context
    assert "Docker" in output or "docker" in output.lower()

def test_llm_command_mocking():
    fs = PseudoFilesystem("test-session")
    
    output, _, _ = fs.execute_command("ifconfig")
    assert "eth0" in output
    assert "inet" in output
    
    output, _, _ = fs.execute_command("ps aux")
    assert "PID" in output
    assert "systemd" in output
