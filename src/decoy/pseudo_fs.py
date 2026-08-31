import os
from typing import Tuple
from .llm_provider import LLMProvider

class PseudoFilesystem:
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.cwd = "/home/user"
        self.command_history = []
        self.llm = LLMProvider(use_mock=True)
        self.virtual_tree = {
            "/": ["bin", "etc", "home", "var", "tmp"],
            "/home": ["user"],
            "/home/user": ["notes.txt", "script.sh"],
            "/etc": ["passwd", "shadow", "hostname"]
        }
        
    def execute_command(self, raw_cmd: str) -> Tuple[str, str, int]:
        self.command_history.append(raw_cmd)
        parts = raw_cmd.strip().split()
        if not parts:
            return "", self.cwd, 0
            
        root = parts[0]
        output = ""
        latency_regime_weight = 0
        
        if root == "cd":
            if len(parts) > 1:
                target = parts[1]
                if target == "..":
                    if self.cwd != "/":
                        self.cwd = os.path.dirname(self.cwd)
                        if not self.cwd:
                            self.cwd = "/"
                elif target.startswith("/"):
                    self.cwd = target
                else:
                    new_path = os.path.normpath(os.path.join(self.cwd, target)).replace("\\", "/")
                    self.cwd = new_path
            output = ""
            
        elif root == "pwd":
            output = self.cwd + "\n"
            
        elif root == "ls":
            target_dir = self.cwd
            if len(parts) > 1:
                target_dir = parts[1] if parts[1].startswith("/") else os.path.normpath(os.path.join(self.cwd, parts[1]))
            
            if target_dir in self.virtual_tree:
                output = "  ".join(self.virtual_tree[target_dir]) + "\n"
            else:
                # LLM generates plausible directory listing for unknown paths
                content = self.llm.generate_file_content(f"{target_dir}_dir", self.command_history)
                # Parse the LLM output into a pseudo-listing (mock just returns strings, we can just split it)
                output = "file1.txt  config.json  app.py\n" # Fast fallback
                if "aws" in target_dir: output = "credentials  config\n"
            
        elif root == "cat":
            target_file = ""
            if len(parts) > 1:
                target_file = parts[1] if parts[1].startswith("/") else os.path.normpath(os.path.join(self.cwd, parts[1]))
                output = self.llm.generate_file_content(target_file, self.command_history)
            else:
                output = "cat: missing operand\n"
            latency_regime_weight = 1  # Trigger FS latency if active
            
        elif root in ["wget", "curl"]:
            output = "HTTP request sent, awaiting response... 200 OK\n"
            latency_regime_weight = 1
            
        elif root == "touch":
            if len(parts) > 1:
                filename = parts[1]
                if self.cwd not in self.virtual_tree:
                    self.virtual_tree[self.cwd] = []
                if filename not in self.virtual_tree[self.cwd]:
                    self.virtual_tree[self.cwd].append(filename)
            output = ""
            latency_regime_weight = 1
            
        elif root == "rm":
            if len(parts) > 1:
                filename = parts[-1]
                if self.cwd in self.virtual_tree and filename in self.virtual_tree[self.cwd]:
                    self.virtual_tree[self.cwd].remove(filename)
            output = ""
            latency_regime_weight = 1
            
        elif root == "chmod":
            output = ""
            latency_regime_weight = 1
            
        else:
            # Let the LLM handle unknown commands like whoami, ifconfig, ps, etc.
            output = self.llm.generate_command_output(raw_cmd, self.command_history)
            
        return output, self.cwd, latency_regime_weight
