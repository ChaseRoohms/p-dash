import os
import socket
import threading
import time
import argparse
from queue import Queue
from _socket import getservbyport


# =================================================== Formatting Stuff ================================================
WHITE = '\033[97m'
LG = '\033[0;37m'
GRAY = '\033[1;30m'
BLUE = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
END = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'


# ====================================================== Strings ======================================================
ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'

version = 'v.1.0'

logo = (
    " ██████╗       ██████╗  █████╗ ███████╗██╗  ██╗\n"
    " ██╔══██╗      ██╔══██╗██╔══██╗██╔════╝██║  ██║\n"
    " ██████╔╝█████╗██║  ██║███████║███████╗███████║\n"
    " ██╔═══╝ ╚════╝██║  ██║██╔══██║╚════██║██╔══██║\n"
    " ██║           ██████╔╝██║  ██║███████║██║  ██║\n"
    " ╚═╝           ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝\n"
)


help_string = (
        "<Description>\n" +
        BOLD + "Usage: {} <target IP> [--all]" + END + "\n" +
        "\n" +
        "Commands:\n" +
        "         <target IP>            Scans this IP address\n" +
        "         --version              Print version information and exit\n" +
        "Options:\n" +
        "     -a, --all                  Scans all ports from 1-65535\n"
)


# ===================================================== Functions =====================================================
def logo_format():
    """
    Color shadow symbols ╠ ╣ ╔ ╗ ╚ ╝ ║  light gray, and the letter symbols █ white
    :return:
    """
    formatted_logo = WHITE
    gray = False
    shadowed_symbols = ['╔', '╗', '═', '╚', '╝', '║', '╠', '╣']
    for symbol in logo:  # Process every character
        if symbol in shadowed_symbols:  # Light gray before shadowed symbols
            if not gray:
                formatted_logo += LG
                gray = True
        else:                           # White before letter symbols
            if gray:
                formatted_logo += WHITE
                gray = False
        formatted_logo += symbol        # Add the symbol

    # Add the version below the logo
    formatted_logo += WHITE + BOLD + RED + ('%46s' % ("- " + version)) + END
    return formatted_logo


def print_results(ip_address, open_ports_dict, runtime):
    """
    Pretty print the results of a port scan
    :param ip_address: The IP address scanned to get these results
    :param open_ports_dict: A dictionary of open ports 'port':'service'
    :param runtime: How long the program ran for
    :return:
    """
    print('╔' + '═' * 45 + '╗')
    print('║ ' + ('%-29s%-23s' % ((BOLD + "Target" + END), ip_address)) + '║')
    print('╠' + '═' * 45 + '╣')
    if len(open_ports_dict) == 0:
        print('║ ' + ('%-44s' % 'No open ports found') + '║')
    else:
        print('║ ' + ('%-25s%-23s' % ((BOLD + "Port"), "Service")) + END + '║')
        for port, service in open_ports_dict.items():
            print('║ ' + ('%-21s%-23s' % (port, service)) + '║')
    print('╠' + '═' * 45 + '╣')
    print('║ ' + ('%44s' % (str(round(runtime, 2)) + ' Secs ') + '║'))
    print('╚' + '═' * 45 + '╝')
    print()


def print_error(ip_address, error_message):
    """
    Pretty print the error message
    :param ip_address: The IP address scanned that threw an error
    :param error_message: The error message you wish a user to see
    :return:
    """
    print('╔' + '═' * 45 + '╗')
    print('║ ' + ('%-29s%-23s' % ((BOLD + "Target" + END), ip_address)) + '║')
    print('╠' + '═' * 45 + '╣')
    print('║ ' + ('%-53s' % (BOLD + RED + error_message)) + END + '║')
    print('╚' + '═' * 45 + '╝')


def exiting():
    """
    Exits the program gracefully
    :return:
    """
    print("\r", end="")
    print('Exiting...')
    quit()


def ping_ip(ip_address):
    """
    Tries to ping an ip address to determine if its accessible
    :param ip_address: The IP address to scan
    :return:
    """
    try:
        response = os.popen(f"ping {ip_address} ").read()                       # Ping the address and save the response
        if "Request timed out." in response or "unreachable" in response:       # Not pingable
            print_error(ip_address, "Unable to ping target...")
            return False
        elif "could not find" in response:                                      # Doesn't exist
            print_error(ip_address, "Could not find target...")
            return False
        else:                                                                   # Successful ping
            return True
    except KeyboardInterrupt:
        exiting()


# noinspection PyBroadException
def portscan(ip_address, port_to_scan, open_ports):
    """
    Scans an IP address to see if a port is open, adds it to open_ports if it is
    :param ip_address: The IP address to scan
    :param port_to_scan: The port to check
    :param open_ports: Dictionary of open ports and the services they run 'port':'service'
    :return:
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)       # New socket
    try:
        s.connect((ip_address, port_to_scan))                   # Try to connect to IP and port
        try:
            service = getservbyport(port_to_scan)               # Look for known port - service relationship
        except OSError:
            service = "n/a"                                     # No known service
        open_ports[port_to_scan] = service
        s.close()
    except:
        pass


def threader(ip_address, open_ports):
    """
    The threaded function for parallel processing
    :param ip_address: The IP address to scan
    :param open_ports: Dictionary of open ports and the services they run 'port':'service'
    :return:
    """
    while True:
        port = q.get()                              # Get next port
        portscan(ip_address, port, open_ports)      # Scan that port
        q.task_done()                               # Remove from queue


def scan_ip(ip_address, max_port, thread_count, open_ports):
    """
    Scans an IP address for all open ports between 1 and max_port. Executes on thread_count parallel threads.
    :param ip_address: The IP address to scan
    :param max_port: Maximum number of ports to scan. Scans 1-max_port
    :param thread_count: Maximum number of threads to run in parallel
    :param open_ports: Dictionary of open ports and the services they run 'port':'service'
    :return:
    """
    for x in range(thread_count):  # Create threader with thread_count threads
        t = threading.Thread(target=threader, args=(ip_address, open_ports))    # Feed the threaders >:)
        t.daemon = True
        t.start()

    for port in range(1, max_port):     # Scan ports 1-max_port
        q.put(port)

    q.join()    # BEGIN


def get_arg_parser():
    """
    Creates an argeparse parser to gather CLI arguments
    :return:
    """
    parser = argparse.ArgumentParser(
        prog='p-dash')
    parser.add_argument(
        'ip_address',
        help='IP address to scan')
    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s ' + version)
    parser.add_argument(
        '-a', '--all',
        action='store_const',
        const=True,
        default=False,
        help='scan all ports from 1-65535, default 1-10000')
    parser.add_argument(
        'speed',
        default='--fast',
        const='--fast',
        nargs='?',
        choices=['--fast', '--med', '--slow'],
        help='the speed at which you want to scan (default: %(default)s)')
    return parser


def get_args():
    """
    Gets arguments ip_address, max_port and thread_count and returns them
    :return:
    """
    parser = get_arg_parser()
    args = parser.parse_args()

    ip_address = args.ip_address

    if args.all:
        max_port = 65535
    else:
        max_port = 10000

    match args.speed:
        case '--fast':
            thread_count = 1000
        case '--medium':
            thread_count = 100
        case '--slow':
            thread_count = 10
        case _:
            thread_count = 1

    return ip_address, max_port, thread_count


def run(ip_address, max_port, thread_count):
    """
    Scans an IP address for all open ports, and then pretty prints the results
    :param ip_address:
    :param max_port:
    :param thread_count:
    :return:
    """
    start_time = time.time()

    socket.setdefaulttimeout(0.25)

    open_ports = dict()
    try:
        if ping_ip(ip_address):
            scan_ip(ip_address, max_port, thread_count, open_ports)
            print_results(ip_address, open_ports, time.time() - start_time)
    except KeyboardInterrupt:
        exiting()


# ==================================================== Main Program ===================================================
print_lock = threading.Lock()
q = Queue()

target, port_limit, thread_limit = get_args()

print()
print(logo_format())
print("Scanning...")

run(target, port_limit, thread_limit)
