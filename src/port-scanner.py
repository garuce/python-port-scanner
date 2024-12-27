import logging
import socket
import argparse
import json
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from prettytable import PrettyTable
import time

# Load configuration

def load_config(config_file='config.json'):
    """Load the configuration from a JSON file."""
    try:
        with open(config_file, 'r') as file:
            config = json.load(file)
        return config
    except FileNotFoundError:
        print(f"Config file '{config_file}' not found. Using default settings.")
        logging.warning(f"Config file '{config_file}' not found. Using default settings.")
        return {}
    except json.JSONDecodeError:
        print(f"Error parsing the config file '{config_file}'. Using default settings.")
        logging.warning(f"Error parsing the config file '{config_file}'. Using default settings.")
        return {}

# Setup logging

def setup_logging(config):
    """Set up logging configuration using values from the config."""
    log_filename = config.get('log_filename', 'port_scanner.log')
    log_level = config.get('log_level', 'INFO').upper()
    log_level = getattr(logging, log_level, logging.INFO)

    logging.basicConfig(
        filename=log_filename,
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(formatter)
    logging.getLogger().addHandler(console_handler)

# Service detection
COMMON_SERVICES = {
    80: 'HTTP',
    443: 'HTTPS',
    22: 'SSH',
    21: 'FTP',
    25: 'SMTP',
    53: 'DNS',
    110: 'POP3',
    143: 'IMAP',
    3306: 'MySQL',
    5432: 'PostgreSQL',
    6379: 'Redis',
    11211: 'Memcached',
}

# Port scanning function

def scan_port(host, port, timeout):
    """Scan a single port on the target host."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            return True, COMMON_SERVICES.get(port, 'Unknown')
        else:
            return False, None
    except Exception as e:
        logging.error(f"Error scanning port {port} on {host}: {e}")
        return False, None

# Range scanning

def scan_port_range(host, start_port, end_port, timeout, workers=10):
    """Scan a range of ports on the target host."""
    open_ports = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        with tqdm(total=end_port - start_port + 1, desc=f"Scanning {host}", unit="port") as pbar:
            futures = {executor.submit(scan_port, host, port, timeout): port for port in range(start_port, end_port + 1)}
            for future in futures:
                port = futures[future]
                try:
                    status, service = future.result()
                    if status:
                        open_ports.append((port, service))
                except Exception as e:
                    logging.error(f"Error scanning port {port} on {host}: {e}")
                pbar.update(1)
    return open_ports

# Specific list scanning

def scan_ports(host, ports, timeout, workers=10):
    """Scan a specific list of ports on the target host."""
    open_ports = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        with tqdm(total=len(ports), desc=f"Scanning {host}", unit="port") as pbar:
            futures = {executor.submit(scan_port, host, port, timeout): port for port in ports}
            for future in futures:
                port = futures[future]
                try:
                    status, service = future.result()
                    if status:
                        open_ports.append((port, service))
                except Exception as e:
                    logging.error(f"Error scanning port {port} on {host}: {e}")
                pbar.update(1)
    return open_ports

# Banner display

def display_banner():
    """Display the banner for the application."""
    banner = """
    ==============================
      Port Scanner by Buchaf
    ==============================
    """
    print(banner)

# Pretty table display

def display_results(open_ports, host):
    """Display the scan results in a formatted table."""
    table = PrettyTable()
    table.field_names = ["Port", "Status", "Service"]
    for port, service in open_ports:
        table.add_row([port, "Open", service])
    print(f"\nScan results for {host}:\n")
    print(table)

# Argument parsing

def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Port Scanner")
    parser.add_argument("host", help="Target IP address")
    parser.add_argument("-s", "--single", type=int, help="Single port to scan")
    parser.add_argument("-r", "--range", nargs=2, type=int, metavar=("START", "END"), help="Range of ports to scan")
    parser.add_argument("-a", "--all", action="store_true", help="Scan all ports")
    parser.add_argument("-l", "--list", nargs="+", type=int, help="List of specific ports to scan")
    parser.add_argument("--timeout", type=int, default=1, help="Timeout for socket connection (default 1 second)")
    parser.add_argument("--workers", type=int, default=10, help="Number of concurrent workers (default 10)")
    return parser.parse_args()

# Main function

def main():
    config = load_config()
    setup_logging(config)

    args = parse_args()
    display_banner()

    host = args.host
    timeout = args.timeout
    workers = args.workers

    open_ports = []

    if args.single:
        status, service = scan_port(host, args.single, timeout)
        if status:
            open_ports.append((args.single, service))
    elif args.range:
        start_port, end_port = args.range
        open_ports = scan_port_range(host, start_port, end_port, timeout, workers)
    elif args.all:
        open_ports = scan_port_range(host, 1, 65535, timeout, workers)
    elif args.list:
        open_ports = scan_ports(host, args.list, timeout, workers)
    else:
        print("No valid option selected. Use --help for usage information.")
        return

    if open_ports:
        display_results(open_ports, host)
        logging.info(f"Open ports on {host}: {open_ports}")
    else:
        print(f"No open ports found on {host}")
        logging.info(f"No open ports found on {host}")

if __name__ == "__main__":
    main()
