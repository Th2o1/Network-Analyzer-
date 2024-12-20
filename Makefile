# Name of the executable
EXEC = analyseur
DATALINK_FOLDER = datalink_layer/
NETWORK_FOLDER = network_layer/
TRANSPORT_FOLDER = transport_layer/
APPLICATION_FOLDER = application_layer/
VERBOSITY = 3
# Source and object files
SRC = analyseur.c packet_parsing.c utils.c $(wildcard $(DATALINK_FOLDER)*.c)  $(wildcard $(NETWORK_FOLDER)*.c) $(wildcard $(TRANSPORT_FOLDER)*.c) $(wildcard $(APPLICATION_FOLDER)*.c) 
OBJ = $(SRC:.c=.o)

# Compilation options
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -D_GNU_SOURCE -g
LDFLAGS = -lpcap  # Linking with the pcap library

# Default rule
all: $(EXEC)

# Build the executable
$(EXEC): $(OBJ)
	$(CC) $(CFLAGS) -o $(EXEC) $(OBJ) $(LDFLAGS) 

# Build object files
%.o: %.c %.h
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up generated files
clean:
	rm -f $(OBJ) $(EXEC)

# Launch the program for testing
start: $(EXEC)
	./$(EXEC) -i en0 -v $(VERBOSITY)
start1: $(EXEC)
	./$(EXEC) -i en0 -v 1
start2: $(EXEC)
	./$(EXEC) -i en0 -v 2
start3: $(EXEC)
	./$(EXEC) -i en0 -v 3

# Rebuild for debugging
rebuild : clean all

# Run specific tests with predefined pcap files
arp: $(EXEC)
	./$(EXEC) -o data/arp-storm.pcap -v $(VERBOSITY)

arp2: $(EXEC)
	./$(EXEC) -o data/rarp_req_reply.pcapng -v $(VERBOSITY)

ipv4: $(EXEC)
	./$(EXEC) -o data/ipv4.pcap -v $(VERBOSITY)

ipopt: $(EXEC)
	./$(EXEC) -o data/ipv4_cipso_option.pcap -v $(VERBOSITY)

tcp: $(EXEC)
	./$(EXEC) -o data/IPv4_TCP.pcapng -v $(VERBOSITY)

smtp: $(EXEC)
	./$(EXEC) -o data/smtp.pcap -v $(VERBOSITY)

http: $(EXEC)
	./$(EXEC) -o data/http.pcap -v $(VERBOSITY)

telnet: $(EXEC)
	./$(EXEC) -o data/telnet-cooked.pcap -v $(VERBOSITY)

ftp: $(EXEC)
	./$(EXEC) -o data/ftp.pcap -v $(VERBOSITY)

imap: $(EXEC)
	./$(EXEC) -o data/imap.cap -v $(VERBOSITY)

pop: $(EXEC)
	./$(EXEC) -o data/pop-ssl.pcapng -v $(VERBOSITY)

icmp: $(EXEC)
	./$(EXEC) -o data/icmp.pcapng -v $(VERBOSITY)

ipv6: $(EXEC)
	./$(EXEC) -o data/v6.pcap -v $(VERBOSITY)

udp: $(EXEC)
	./$(EXEC) -o data/dhcp.pcap -v $(VERBOSITY)

dns: $(EXEC)
	./$(EXEC) -o data/dns.pcapng -v $(VERBOSITY)


# Display help information
help:
	@echo "Available targets:"
	@echo "  all         : Compile the executable."
	@echo "  clean       : Remove all generated files."
	@echo "  rebuild     : Clean and rebuild the project."
	@echo "  start       : Run with default verbosity."
	@echo "  start1      : Run with verbosity level 1."
	@echo "  start2      : Run with verbosity level 2."
	@echo "  start3      : Run with verbosity level 3."
	@echo "  arp         : Test with ARP storm data."
	@echo "  arp2        : Test with RARP request/reply data."
	@echo "  ipv4        : Test with IPv4 data."
	@echo "  ipopt       : Test with IPv4 options."
	@echo "  tcp         : Test with TCP data."
	@echo "  smtp        : Test with SMTP data."
	@echo "  http        : Test with HTTP data."
	@echo "  telnet      : Test with Telnet data."
	@echo "  ftp         : Test with FTP data."
	@echo "  imap        : Test with IMAP data."
	@echo "  pop         : Test with POP data."
	@echo "  icmp        : Test with ICMP data."
	@echo "  ipv6        : Test with IPv6 data."
	@echo "  udp         : Test with UDP data."
	@echo "  dns         : Test with DNS data."
# Declare phony targets to avoid conflicts with files
.PHONY: all clean help start arp ipv4 ipv4_tcp icmp ipv6