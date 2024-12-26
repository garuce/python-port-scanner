import socket
import argparse

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
  
  open_ports = [] #storing the open ports
  for port in range(1, 65536):  # Note: Port range is 1-65535
        if scan_port(host, port):
            open_ports.append(port)
            print(f"Port {port} is OPEN")
        else:
            print(f"Port {port} is CLOSED")
  return open_ports

"""Parse command-line arguments."""
def parse_args():
  parser = argparse.ArgumentParser(description="Port Scanner")
  parser.add_argument("host", help="Target IP address")
  parser.add_argument("-s", "--single", type=int, help="Single port to scan")
  parser.add_argument("-r", "--range", nargs=2, type=int, metavar=("START", "END"), help="Range of ports to scan")
  parser.add_argument("-a", "--all", action="store_true", help="Scan all ports")
  parser.add_argument("-l", "--list", nargs="+", type=int, help="List of specific ports to scan")
  return parser.parse_args()

"""Main program logic."""
def main():
    
    args = parse_args()

    if args.single:
        print(f"Scanning port {args.single} on {args.host}...")
        scan_port(args.host, args.single)
    
    elif args.range:
        start_port, end_port = args.range
        print(f"Scanning {args.host} from port {start_port} to {end_port}...")
        scan_port_range(args.host, start_port, end_port)
    
    elif args.all:
        print(f"Scanning all ports on {args.host}...")
        scan_all_ports(args.host)

    elif args.list:
        print(f"Scanning the following ports on {args.host}: {args.list}...")
        scan_ports(args.host, args.list)
    
    else:
        print("No valid option selected. Use --help for usage information.")

"""User input for host and port range."""
if __name__ == "__main__":
    main()
