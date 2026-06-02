import socket

target = "IP ADDRESS" #Change to ip target
ports = [22,80,443,3389] 
#22 – SSH — remote login
#80 – HTTP — websites
#443 – HTTPS — secure websites
#3389 – RDP — Windows remote desktop

for port in ports:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    result = s.connect_ex((target,port))

    if result == 0:
        print(f"Port {port} is open")
    else:
        print(f"Port {port} is closed")
    s.close()