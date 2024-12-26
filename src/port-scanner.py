import socket

"""Scan a single port on the target IP."""
def scan_port(host, port):
  
  try:
    # Create a socket object
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1) # Timeout after 1 second

    # Try connecting to the target IP and port
    result = sock.connect_ex((host, port))

    if result == 0:
      return True #Port is open
    else:
      return False #Port is closed
    
  except socket.error as e:
    print(f"Error scanning port {port}: {e}")
    return False
  finally:
    sock.close()

"""Scan a range of ports on the target IP."""
def scan_port_range(host, start_port, end_port):
  
  open_ports = [] #storing the open ports
  for port in range(start_port, end_port + 1): 
        if scan_port(host, port):
            open_ports.append(port)
            print(f"Port {port} is OPEN")
  return open_ports

"""Scan a list of ports on the target IP.""" 
def scan_ports(host, ports):
   
  open_ports = [] #storing the open ports
  for port in ports:
    if scan_port(host, port):
      open_ports.append(port)
      print(f"Port {port} is open")
    else:
      print(f"Port {port} is closed")
  return open_ports

"""Scan all ports on the target IP."""
def scan_all_ports(host):
  
  ports = list(range(1, 65535))
  open_ports = [] #storing the open ports
  for port in ports:
    if scan_ports(host, ports):
      open_ports.append(port)
      print(f"Port {port} is open")
    else:
      print(f"Port {port} is closed")
  return open_ports
  
