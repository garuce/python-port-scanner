import logging
import socket
import argparse
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from tqdm import tqdm  # Importing tqdm for progress bar
import time


def setup_logging(log_filename='port_scanner.log', log_level=logging.INFO):
    """Set up logging configuration."""
    logging.basicConfig(
        filename=log_filename,        # Log file
        level=log_level,               # Log everything from the specified level
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

MAX_RETRIES = 3  # Max retries for port scanning if there's an error or timeout

def log_port_scan(host, port, status):
    """Logs the port scan result with detailed information."""
    status_msg = "OPEN" if status else "CLOSED"
    logging.info(f"Port {port} is {status_msg} on {host}")

def scan_port(host, port, timeout):
    """Scan a single port on the target IP with detailed error handling."""
    retries = 0
    while retries < MAX_RETRIES:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)  # Timeout after the specified time
            result = sock.connect_ex((host, port))
            status = result == 0  # Port is open if result is 0
            log_port_scan(host, port, status)
            return status
        except socket.timeout:
            retries += 1
            logging.warning(f"Timeout scanning port {port} on {host}. Retry {retries}/{MAX_RETRIES}.")
            time.sleep(1)  # Wait before retrying
        except socket.gaierror:
            logging.error(f"Failed to resolve host {host}. Please check the hostname or IP address.")
            return False
        except socket.error as e:
            logging.error(f"Error scanning port {port} on {host}: {e}")
            return False
        finally:
            sock.close()
    
    logging.error(f"Failed to scan port {port} on {host} after {MAX_RETRIES} retries.")
    return False

def scan_port_range(host, start_port, end_port, timeout):
    """Scan a range of ports on the target IP with a progress bar and detailed output."""
    if start_port > end_port:
        logging.error("Start port cannot be greater than end port.")
        return []
    
    open_ports = []  # Storing the open ports
    with ThreadPoolExecutor(max_workers=10) as executor:
        with tqdm(total=end_port - start_port + 1, desc=f"Scanning {host}", unit="port") as pbar:
            futures = {executor.submit(scan_port, host, port, timeout): port for port in range(start_port, end_port + 1)}
            for future in futures:
                port = futures[future]
                try:
                    if future.result():
                        open_ports.append(port)
                except Exception as e:
                    logging.error(f"Error scanning port {port} on {host}: {e}")
                pbar.update(1)  # Update the progress bar after each port is scanned

    if open_ports:
        print(f"Open ports on {host}: {open_ports}")
        logging.info(f"Open ports on {host}: {open_ports}")
    else:
        print(f"No open ports found on {host}")
        logging.info(f"No open ports found on {host}")

    return open_ports

def scan_ports(host, ports, timeout):
    """Scan a list of ports on the target IP with a progress bar and detailed output."""
    if not ports:
        logging.error("No ports specified for scanning.")
        return []

    open_ports = []  # Storing the open ports
    with ThreadPoolExecutor(max_workers=10) as executor:
        with tqdm(total=len(ports), desc=f"Scanning {host}", unit="port") as pbar:
            futures = {executor.submit(scan_port, host, port, timeout): port for port in ports}
            for future in futures:
                port = futures[future]
                try:
                    if future.result():
                        open_ports.append(port)
                except Exception as e:
                    logging.error(f"Error scanning port {port} on {host}: {e}")
                pbar.update(1)

    if open_ports:
        print(f"Open ports on {host}: {open_ports}")
        logging.info(f"Open ports on {host}: {open_ports}")
    else:
        print(f"No open ports found on {host}")
        logging.info(f"No open ports found on {host}")

    return open_ports

def scan_all_ports(host, timeout):
    """Scan all ports on the target IP with a progress bar and detailed output."""
    open_ports = []  # Storing the open ports
    with ThreadPoolExecutor(max_workers=10) as executor:
        with tqdm(total=65535, desc=f"Scanning all ports on {host}", unit="port") as pbar:
            futures = {executor.submit(scan_port, host, port, timeout): port for port in range(1, 65536)}
            for future in futures:
                port = futures[future]
                try:
                    if future.result():
                        open_ports.append(port)
                except Exception as e:
                    logging.error(f"Error scanning port {port} on {host}: {e}")
                pbar.update(1)

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
    parser.add_argument("--timeout", type=int, default=1, help="Timeout for socket connection (default 1 second)")
    parser.add_argument("--workers", type=int, default=10, help="Number of concurrent workers (default 10)")
    return parser.parse_args()

def main():
    try:
        args = parse_args()

        if args.single:
            print(f"Scanning port {args.single} on {args.host}...") if args.verbose else None
            scan_port(args.host, args.single, args.timeout)
        
        elif args.range:
            start_port, end_port = args.range
            print(f"Scanning {args.host} from port {start_port} to {end_port}...") if args.verbose else None
            scan_port_range(args.host, start_port, end_port, args.timeout)
        
        elif args.all:
            print(f"Scanning all ports on {args.host}...") if args.verbose else None
            scan_all_ports(args.host, args.timeout)

        elif args.list:
            print(f"Scanning the following ports on {args.host}: {args.list}...") if args.verbose else None
            scan_ports(args.host, args.list, args.timeout)
        
        else:
            print("No valid option selected. Use --help for usage information.")
    
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        logging.info("Scan interrupted by user.")

if __name__ == "__main__":
    main()
