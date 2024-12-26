import logging
import socket
import argparse
import json
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from tqdm import tqdm  # Importing tqdm for progress bar
import time


def load_config(config_file='config.json'):
    """Load the configuration from a JSON file."""
    try:
        # Attempt to open and read the config file
        with open(config_file, 'r') as file:
            config = json.load(file)
        return config
    except FileNotFoundError:
        # If config file is not found, use default settings
        print(f"Config file '{config_file}' not found. Using default settings.")
        logging.warning(f"Config file '{config_file}' not found. Using default settings.")
        return {}  # Return empty dict if the file is not found
    except json.JSONDecodeError:
        # Handle invalid JSON syntax in the config file
        print(f"Error parsing the config file '{config_file}'. Using default settings.")
        logging.warning(f"Error parsing the config file '{config_file}'. Using default settings.")
        return {}


def setup_logging(config):
    """Set up logging configuration using values from the config."""
    # Get the log filename and log level from the configuration (default to 'port_scanner.log' and 'INFO')
    log_filename = config.get('log_filename', 'port_scanner.log')
    log_level = config.get('log_level', 'INFO').upper()
    log_level = getattr(logging, log_level, logging.INFO)  # Convert string log level to actual logging level
    
    # Configure the logging to a file
    logging.basicConfig(
        filename=log_filename,
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Also log to the console with the same log level
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(formatter)
    logging.getLogger().addHandler(console_handler)
    
    if not config:
        # If config is empty, issue a warning about default configuration
        logging.warning("Using default configuration settings.")


MAX_RETRIES = 3  # Default retries for port scanning if there's an error or timeout

def log_port_scan(host, port, status):
    """Logs the result of the port scan (open or closed)."""
    status_msg = "OPEN" if status else "CLOSED"  # Determine port status
    logging.info(f"Port {port} is {status_msg} on {host}")


def scan_port(host, port, timeout, max_retries):
    """Scan a single port on the target IP address."""
    retries = 0
    while retries < max_retries:
        try:
            # Create a new socket and set the timeout
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)  # Timeout after the specified time
            result = sock.connect_ex((host, port))  # Attempt to connect to the port
            status = result == 0  # If result is 0, the port is open
            log_port_scan(host, port, status)  # Log the result
            return status
        except socket.timeout:
            # If timeout occurs, retry scanning the port
            retries += 1
            logging.warning(f"Timeout scanning port {port} on {host}. Retry {retries}/{max_retries}.")
            time.sleep(1)  # Wait for 1 second before retrying
        except socket.gaierror:
            # Handle errors related to DNS resolution
            logging.error(f"Failed to resolve host {host}. Please check the hostname or IP address.")
            return False
        except socket.error as e:
            # Log other socket-related errors
            logging.error(f"Error scanning port {port} on {host}: {e}")
            return False
        finally:
            sock.close()  # Ensure the socket is always closed after scanning

    # Log if the port scan failed after retries
    logging.error(f"Failed to scan port {port} on {host} after {max_retries} retries.")
    return False


def scan_port_range(host, start_port, end_port, timeout, max_retries, workers=10):
    """Scan a range of ports on the target IP with a progress bar."""
    if start_port > end_port:
        # If start port is greater than end port, log an error
        logging.error("Start port cannot be greater than end port.")
        return []
    
    open_ports = []  # List to store open ports
    with ThreadPoolExecutor(max_workers=workers) as executor:
        # Using tqdm for progress bar display while scanning ports
        with tqdm(total=end_port - start_port + 1, desc=f"Scanning {host}", unit="port") as pbar:
            # Submit scan tasks for each port in the range
            futures = {executor.submit(scan_port, host, port, timeout, max_retries): port for port in range(start_port, end_port + 1)}
            for future in futures:
                port = futures[future]
                try:
                    if future.result():  # If port is open, add to the list
                        open_ports.append(port)
                except Exception as e:
                    # Log any errors during scanning
                    logging.error(f"Error scanning port {port} on {host}: {e}")
                pbar.update(1)  # Update the progress bar after each port is scanned
    
    # Handle output and logging of open ports
    if open_ports:
        print(f"Open ports on {host}: {open_ports}")
        logging.info(f"Open ports on {host}: {open_ports}")
    else:
        print(f"No open ports found on {host}")
        logging.info(f"No open ports found on {host}")

    return open_ports


def scan_ports(host, ports, timeout, max_retries):
    """Scan a specific list of ports on the target IP with a progress bar."""
    if not ports:
        # If no ports are provided, log an error
        logging.error("No ports specified for scanning.")
        return []

    open_ports = []  # List to store open ports
    with ThreadPoolExecutor(max_workers=10) as executor:
        # Create a progress bar using tqdm for the list of ports
        with tqdm(total=len(ports), desc=f"Scanning {host}", unit="port") as pbar:
            # Submit scan tasks for each port in the list
            futures = {executor.submit(scan_port, host, port, timeout, max_retries): port for port in ports}
            for future in futures:
                port = futures[future]
                try:
                    if future.result():  # If port is open, add to the list
                        open_ports.append(port)
                except Exception as e:
                    # Log any errors during scanning
                    logging.error(f"Error scanning port {port} on {host}: {e}")
                pbar.update(1)  # Update the progress bar after each port is scanned

    # Print summary of open ports in CLI
    if open_ports:
        print(f"Open ports on {host}: {open_ports}")
        logging.info(f"Open ports on {host}: {open_ports}")
    else:
        print(f"No open ports found on {host}")
        logging.info(f"No open ports found on {host}")

    return open_ports


def scan_all_ports(host, timeout, max_retries):
    """Scan all ports (1-65535) on the target IP with a progress bar."""
    open_ports = []  # List to store open ports
    with ThreadPoolExecutor(max_workers=10) as executor:
        # Create a progress bar using tqdm for all ports (1-65535)
        with tqdm(total=65535, desc=f"Scanning all ports on {host}", unit="port") as pbar:
            # Submit scan tasks for all ports from 1 to 65535
            futures = {executor.submit(scan_port, host, port, timeout, max_retries): port for port in range(1, 65536)}
            for future in futures:
                port = futures[future]
                try:
                    if future.result():  # If port is open, add to the list
                        open_ports.append(port)
                except Exception as e:
                    # Log any errors during scanning
                    logging.error(f"Error scanning port {port} on {host}: {e}")
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
    # Define the command-line arguments for port scanning
    parser = argparse.ArgumentParser(description="Port Scanner")
    parser.add_argument("host", help="Target IP address")
    parser.add_argument("-s", "--single", type=int, help="Single port to scan")
    parser.add_argument("-r", "--range", nargs=2, type=int, metavar=("START", "END"), help="Range of ports to scan")
    parser.add_argument("-a", "--all", action="store_true", help="Scan all ports")
    parser.add_argument("-l", "--list", nargs="+", type=int, help="List of specific ports to scan")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print detailed output to console")
    parser.add_argument("--timeout", type=int, default=1, help="Timeout for socket connection (default 1 second)")
    parser.add_argument("--workers", type=int, default=10, help="Number of concurrent workers (default 10)")
    
    args = parser.parse_args()
    
    # Ensure the timeout is a positive integer
    if args.timeout <= 0:
        print("Timeout must be a positive integer. Using default (1 second).")
        args.timeout = 1
    
    return args


def main():
    try:
        # Load the config from the file
        config = load_config()

        # Set up logging based on config
        setup_logging(config)

        # Retrieve configuration values for timeout and retries
        timeout = config.get('timeout', 1)
        max_retries = config.get('max_retries', 3)
        workers = config.get('workers', 10)

        # Parse the command-line arguments
        args = parse_args()

        # Scan single port if specified
        if args.single:
            print(f"Scanning port {args.single} on {args.host}...") if args.verbose else None
            scan_port(args.host, args.single, timeout, max_retries)
        
        # Scan port range if specified
        elif args.range:
            start_port, end_port = args.range
            print(f"Scanning {args.host} from port {start_port} to {end_port}...") if args.verbose else None
            scan_port_range(args.host, start_port, end_port, timeout, max_retries)
        
        # Scan all ports if specified
        elif args.all:
            print(f"Scanning all ports on {args.host}...") if args.verbose else None
            scan_all_ports(args.host, timeout, max_retries)

        # Scan specific list of ports if specified
        elif args.list:
            print(f"Scanning the following ports on {args.host}: {args.list}...") if args.verbose else None
            scan_ports(args.host, args.list, timeout, max_retries)
        
        else:
            # If no valid option is selected, prompt user to check options
            print("No valid option selected. Use --help for usage information.")
    
    except KeyboardInterrupt:
        # Handle keyboard interruption gracefully
        print("\nScan interrupted by user.")
        logging.info("Scan interrupted by user.")


if __name__ == "__main__":
    # Entry point for the script execution
    main()
