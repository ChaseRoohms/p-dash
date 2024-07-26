```
 ██████╗       ██████╗  █████╗ ███████╗██╗  ██╗
 ██╔══██╗      ██╔══██╗██╔══██╗██╔════╝██║  ██║
 ██████╔╝█████╗██║  ██║███████║███████╗███████║
 ██╔═══╝ ╚════╝██║  ██║██╔══██║╚════██║██╔══██║
 ██║           ██████╔╝██║  ██║███████║██║  ██║
 ╚═╝           ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
                                       - v.1.0
```
Rapid port scanning, with an option for slow scanning when that is required.

## Usage
p-dash.py \<ip_address\> \[--all\] \[\{--fast, --medium, --slow\}\] 

## Options
ip_address: ip address you wish to scan for open ports
speed: (fast, medium, slow) configures the speed at which to scan by controlling the number of threads the function executes on, default --fast
--all: scan all ports from 1-65535, default 1-10000
--version: prints the version information and then exits
--help: prints usage and help information and then quits
