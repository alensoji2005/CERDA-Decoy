import socket
import time

def run_automated_attack(port=2222):
    print("[*] Bot starting automated attack sequence...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", port))
    
    # Read the initial prompt
    time.sleep(0.5)
    s.recv(1024)
    
    for i in range(15):
        cmd = "ls\n"
        
        start_time = time.time()
        s.sendall(cmd.encode())
        
        # Wait for response
        response = s.recv(4096).decode(errors='ignore')
        end_time = time.time()
        
        delay_ms = (end_time - start_time) * 1000
        print(f"Command {i+1:02d} Response Time: {delay_ms:6.1f} ms")
        
        time.sleep(0.1) # Simulate script processing time
        
    s.close()
    print("[*] Bot attack complete.")

if __name__ == "__main__":
    run_automated_attack()
