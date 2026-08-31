import socket
import sys
import time

def connect_and_attack(port):
    print(f"[*] Connecting to Decoy Server on port {port}...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", port))
        
        # Read the initial prompt
        time.sleep(0.5)
        print(s.recv(1024).decode(errors='ignore'), end="")
        
        print("\n[*] You are now connected to the Decoy. Type commands like 'ls', 'wget', or 'rm'.")
        print("[*] Notice how the responses get slower after 5 commands! (Type 'exit' to quit)")
        
        while True:
            cmd = input("")
            if cmd.lower() in ['exit', 'quit']:
                break
            
            # Send command
            s.sendall((cmd + "\n").encode())
            
            # Wait for response
            response = s.recv(4096).decode(errors='ignore')
            print(response, end="")
            
    except ConnectionRefusedError:
        print("[-] Connection refused. Make sure `python decoy_server.py` is running in another terminal!")
    finally:
        s.close()

if __name__ == "__main__":
    port = 2222
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    connect_and_attack(port)
