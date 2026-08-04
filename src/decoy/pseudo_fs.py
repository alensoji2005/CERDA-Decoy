import os
from typing import Tuple

class PseudoFilesystem:
    def __init__(self):
        self.cwd = "/home/user"
        self.virtual_tree = {
            "/": ["bin", "etc", "home", "var", "tmp"],
            "/home": ["user"],
            "/home/user": ["notes.txt", "script.sh"],
            "/etc": ["passwd", "shadow", "hostname"]
        }
        
    def execute_command(self, raw_cmd: str) -> Tuple[str, str, int]:
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
                    if target in self.virtual_tree:
                        self.cwd = target
                else:
                    new_path = os.path.normpath(os.path.join(self.cwd, target)).replace("\\", "/")
                    if new_path in self.virtual_tree:
                        self.cwd = new_path
            output = ""
            
        elif root == "pwd":
            output = self.cwd + "\n"
            
        elif root == "ls":
            output = "  ".join(self.virtual_tree.get(self.cwd, [])) + "\n"
            
        elif root == "cat":
            if len(parts) > 1 and "passwd" in parts[1]:
                output = "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000:user:/home/user:/bin/bash\n"
            else:
                output = "File content mock stream\n"
            latency_regime_weight = 1  # Trigger FS latency if active
            
        elif root in ["wget", "curl"]:
            output = "HTTP request sent, awaiting response... 200 OK\n"
            latency_regime_weight = 1
            
        else:
            output = f"bash: {root}: command not found\n"
            
        return output, self.cwd, latency_regime_weight
