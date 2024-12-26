import socket

def scan_port(host, port):
  """Scan a single port on the target IP."""
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

    