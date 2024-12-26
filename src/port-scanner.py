import logging
import socket
import argparse
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm  # Importing tqdm for progress bar

# Set up logging configuration
logging.basicConfig(
    filename='port_scanner.log',  # Log file
    level=logging.INFO,           # Log everything from INFO level and above
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def log_port_scan(host, port, status):
    """Logs the port scan result."""
    if status:
        logging.info(f"Port {port} is OPEN on {host}")
    else:
        logging.info(f"Port {port} is CLOSED on {host}")

def scan_port(host, port):
    """Scan a single port on the target IP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Timeout after 1 second
        result = sock.connect_ex((host, port))
        status = result == 0  # Port is open if result is 0
        log_port_scan(host, port, status)
        return status
    except socket.error as e:
        logging.error(f"Error scanning port {port} on {host}: {e}")
        return False
    finally:
        sock.close()

def scan_port_range(host, start_port, end_port):
    """Scan a range of ports on the target IP with a progress bar."""
    open_ports = []  # Storing the open ports
    with ThreadPoolExecutor(max_workers=10) as executor:
        # Create a progress bar using tqdm for the range of ports
        with tqdm(total=end_port - start_port + 1, desc=f"Scanning {host}", unit="port") as pbar:
            futures = {executor.submit(scan_port, host, port): port for port in range(start_port, end_port + 1)}
            for future in futures:
                port = futures[future]
                if future.result():
                    open_ports.append(port)
                pbar.update(1)  # Update the progress bar after each port is scanned

    # Print summary of open ports in CLI
    if open_ports:
        print(f"Open ports on {host}: {open_ports}")
        logging.info(f"Open ports on {host}: {open_ports}")
    else:
        print(f"No open ports found on {host}")
        logging.info(f"No open ports found on {host}")

    return open_ports

def scan_ports(host, ports):
    """Scan a list of ports on the target IP with a progress bar."""
    open_ports = []  # Storing the open ports
    with ThreadPoolExecutor(max_workers=10) as executor:
        # Create a progress bar using tqdm for the list of ports
        with tqdm(total=len(ports), desc=f"Scanning {host}", unit="port") as pbar:
            futures = {executor.submit(scan_port, host, port): port for port in ports}
            for future in futures:
                port = futures[future]
                if future.result():
                    open_ports.append(port)
                pbar.update(1)  # Update the progress bar after each port is scanned

    # Print summary of open ports in CLI
    if open_ports:
        print(f"Open ports on {host}: {open_ports}")
        logging.info(f"Open ports on {host}: {open_ports}")
    else:
        print(f"No open ports found on {host}")
        logging.info(f"No open ports found on {host}")

    return open_ports

def scan_all_ports(host):
    """Scan all ports on the target IP with a progress bar."""
    open_ports = []  # Storing the open ports
    with ThreadPoolExecutor(max_workers=10) as executor:
        # Create a progress bar using tqdm for all ports (1-65535)
        with tqdm(total=65535, desc=f"Scanning all ports on {host}", unit="port") as pbar:
            futures = {executor.submit(scan_port, host, port): port for port in range(1, 65536)}
            for future in futures:
                port = futures[future]
                if future.result():
                    open_ports.append(port)
                pbar.update(1)  # Update the progress bar after each port is scanned

    # Print summary of open ports in CLI
    if open_ports:
        print(f"Open ports on {host}: {open_ports}")
        logging.info(f"Open ports on {host}: {open_ports}")
    else:
        print(f"No open ports found on {host}")
        logging.info(f"No open ports found on {host}")

    return open_ports

def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Port Scanner")
    parser.add_argument("host", help="Target IP address")
    parser.add_argument("-s", "--single", type=int, help="Single port to scan")
    parser.add_argument("-r", "--range", nargs=2, type=int, metavar=("START", "END"), help="Range of ports to scan")
    parser.add_argument("-a", "--all", action="store_true", help="Scan all ports")
    parser.add_argument("-l", "--list", nargs="+", type=int, help="List of specific ports to scan")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print detailed output to console")
    return parser.parse_args()

def main():
    args = parse_args()

    if args.single:
        print(f"Scanning port {args.single} on {args.host}...") if args.verbose else None
        scan_port(args.host, args.single)
    
    elif args.range:
        start_port, end_port = args.range
        print(f"Scanning {args.host} from port {start_port} to {end_port}...") if args.verbose else None
        scan_port_range(args.host, start_port, end_port)
    
    elif args.all:
        print(f"Scanning all ports on {args.host}...") if args.verbose else None
        scan_all_ports(args.host)

    elif args.list:
        print(f"Scanning the following ports on {args.host}: {args.list}...") if args.verbose else None
        scan_ports(args.host, args.list)
    
    else:
        print("No valid option selected. Use --help for usage information.")

if __name__ == "__main__":
    main()
