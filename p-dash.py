import sys
import socket
import threading
import time
import re
from queue import Queue
from _socket import getservbyport

global scan_all
global max_port

ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'

# ====================================================== Strings ======================================================
version = 'v.1.0'

logo = (
    "██████╗       ██████╗  █████╗ ███████╗██╗  ██╗\n"
    "██╔══██╗      ██╔══██╗██╔══██╗██╔════╝██║  ██║\n"
    "██████╔╝█████╗██║  ██║███████║███████╗███████║\n"
    "██╔═══╝ ╚════╝██║  ██║██╔══██║╚════██║██╔══██║\n"
    "██║           ██████╔╝██║  ██║███████║██║  ██║\n"
    "╚═╝           ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝\n"
)

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


def logo_format():
    formatted_logo = WHITE
    gray = False
    shadowed_symbols = ['╗', '╔', '═', '╝', '╚', '║']
    for symbol in logo:
        if symbol in shadowed_symbols:
            if not gray:
                formatted_logo += LG
                gray = True
            formatted_logo += symbol
        else:
            if gray:
                formatted_logo += WHITE
                gray = False
            formatted_logo += symbol

    formatted_logo += WHITE + BOLD + RED + ('%46s' % ("                                  - " + version)) + END
    return formatted_logo


# Prints script usage
def usage():
    print("Usage: " + sys.argv[0] + " <target IP> [--all]")
    print("     --help for more information")


# Prints the --help screen information
def help_screen():
    print()
    print(logo_format())
    print("Description.")
    print(BOLD + "Usage: " + sys.argv[0] + " <target IP> [--all]" + END)
    print()
    print("Commands:")
    print("         <target IP>            Scans this IP address")
    print("         --version              Print version information and exit")
    print("Options:")
    print("     -a, --all                  Scans all ports from 1-65535")


# Prints the --version screen information
def version_screen():
    print()
    print(logo_format())


# Ensures correct args and handles them
def arg_handler(argv):
    global max_port
    max_port = 10000
    arg_count = len(argv)

    match arg_count:

        case 2:                                     # <Program Name> <first_argument>
            match argv[1]:
                case '--version':                       # <Program Name> --version
                    version_screen()                        # Print Version information
                    quit()
                case '--help' | '-h' | 'help':          # <Program Name> <--help or -h or help>
                    help_screen()                           # Print help information
                    quit()

        case 3:                                     # <Program Name> <first_argument> <second_argument>
            match argv[2]:
                case '--all' | '-a':                # <Program Name> <first_argument> <--all or -a>
                    max_port = 65535
                case _:                                 # <Program Name> <first_argument> <invalid argument>
                    usage()                                 # Invalid second argument
                    quit()

        case _:                                     # <Program Name> <wrong amount of arguments>
            print()
            usage()                                     # Invalid number of arguments
            quit()

    if not re.match(ip_pattern, argv[1]):
        print()
        print(RED + "Invalid IP address" + END)
        quit()


socket.setdefaulttimeout(0.25)
print_lock = threading.Lock()
target = re.search(ip_pattern, sys.argv[1]).group(0)


# noinspection PyBroadException
def portscan(port_to_scan):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((target, port_to_scan))
        with print_lock:
            try:
                service = getservbyport(port_to_scan)
            except:
                service = "n/a"
            print('║ ' + ('%-20s%-23s' % (port_to_scan, service)) + '║')
        s.close()
    except:
        pass


def threader():
    while True:
        worker = q.get()
        portscan(worker)
        q.task_done()


arg_handler(sys.argv)
q = Queue()
startTime = time.time()

print()
print(logo_format())
print()
print('╔' + '═' * 44 + '╗')
print('║ ' + ('%-28s%-23s' % ((BOLD + "Target" + END), target)) + '║')
print('╠' + '═' * 44 + '╣')
print('║ ' + ('%-24s%-23s' % ((BOLD + "Open Port"), "Service")) + END + '║')

for x in range(1000):
    t = threading.Thread(target=threader)
    t.daemon = True
    t.start()

for port in range(1, max_port):
    q.put(port)

try:
    q.join()
except KeyboardInterrupt:
    print('║ ' + ('%-43s' % 'Exiting...') + '║')
    print('╚' + '═' * 44 + '╝')
    quit()
except socket.error:
    print('║ ' + ('%-43s' % 'Server not responding...') + '║')

print('╠' + '═' * 44 + '╣')
print('║ ' + ('%-43s' % ('Time taken: ' + str(round((time.time() - startTime), 2)) + ' seconds') + '║'))
print('╚' + '═' * 44 + '╝')
print()

