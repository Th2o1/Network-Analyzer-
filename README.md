# Network Traffic Analyzer

## Description

**Analyzer** is a program that captures and interprets network traffic using the `pcap` library. It supports multiple protocols across different OSI model layers (data link, network, transport, and application).

## Compilation

To compile the program, run:

```sh
make
```

This will generate an executable named `analyseur`.

## Usage

Run the program with different verbosity levels:

```sh
./analyseur -i <interface> -v <verbosity>
```

Example:

```sh
./analyseur -i en0 -v 3  # Capture on interface en0 with verbosity level 3
```

You can also analyze specific `.pcap` capture files:

```sh
./analyseur -o data/arp-storm.pcap -v 3  # Analyze ARP storm data
./analyseur -o data/ipv4.pcap -v 3       # Analyze IPv4 traffic
./analyseur -o data/http.pcap -v 3       # Analyze HTTP traffic
./analyseur -o data/dns.pcapng -v 3      # Analyze DNS traffic
```

## Make Commands

- `make` : Compiles the project and generates the `analyseur` executable.
- `make start` : Runs the analyzer with default verbosity (3).
- `make start1` : Runs with verbosity level 1.
- `make start2` : Runs with verbosity level 2.
- `make start3` : Runs with verbosity level 3.
- `make clean` : Removes all compiled files.
- `make rebuild` : Cleans and recompiles the project.
- `make help` : Displays available make commands.
- `make arp` : Analyzes ARP storm data.
- `make ipv4` : Analyzes IPv4 traffic.
- `make tcp` : Analyzes TCP traffic.
- `make http` : Analyzes HTTP traffic.
- `make dns` : Analyzes DNS traffic.

## Dependencies

- `gcc` for compilation
- `libpcap` for packet capture and analysis

On Debian/Ubuntu, install `libpcap` with:

```sh
sudo apt-get install libpcap-dev
```

On macOS, use:

```sh
brew install libpcap
```

## Project Structure

The project is organized into different layers corresponding to the OSI model:

- **datalink\_layer/** : Data link layer analysis (e.g., Ethernet, ARP)
- **network\_layer/** : Network layer analysis (e.g., IPv4, IPv6, ICMP)
- **transport\_layer/** : Transport layer analysis (e.g., TCP, UDP)
- **application\_layer/** : Application layer analysis (e.g., HTTP, SMTP, FTP)

## Author

Théo Ischia

