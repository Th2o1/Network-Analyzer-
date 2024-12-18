# Name of the executable
EXEC = analyseur
DATALINK_FOLDER = datalink_layer/
NETWORK_FOLDER = network_layer/
TRANSPORT_FOLDER = transport_layer/
APPLICATION_FOLDER = application_layer/
# Source and object files
SRC = analyseur.c packet_parsing.c utils.c $(wildcard $(DATALINK_FOLDER)*.c)  $(wildcard $(NETWORK_FOLDER)*.c) $(wildcard $(TRANSPORT_FOLDER)*.c) $(wildcard $(APPLICATION_FOLDER)*.c) 
OBJ = $(SRC:.c=.o)

# Compilation options
CC = gcc
CFLAGS = -Wall -Wextra -std=c11
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
	./$(EXEC) -i en0

# Run specific tests with predefined pcap files
arp: $(EXEC)
	./$(EXEC) -o data/arp-storm.pcap

arp2: $(EXEC)
	./$(EXEC) -o data/rarp_req_reply.pcapng

ipv4: $(EXEC)
	./$(EXEC) -o data/ipv4.pcap

tcp: $(EXEC)
	./$(EXEC) -o data/IPv4_TCP.pcapng

smtp: $(EXEC)
	./$(EXEC) -o data/smtp.pcap

http: $(EXEC)
	./$(EXEC) -o data/http.pcap

telnet: $(EXEC)
	./$(EXEC) -o data/telnet-cooked.pcap

ftp: $(EXEC)
	./$(EXEC) -o data/ftp.pcap

imap: $(EXEC)
	./$(EXEC) -o data/imap.cap

pop: $(EXEC)
	./$(EXEC) -o data/pop-ssl.pcapng

icmp: $(EXEC)
	./$(EXEC) -o data/icmp.pcapng

ipv6: $(EXEC)
	./$(EXEC) -o data/v6.pcap

udp: $(EXEC)
	./$(EXEC) -o data/dhcp.pcap

dns: $(EXEC)
	./$(EXEC) -o data/dns.pcapng


# Display help information
help:
	@echo "Usage : make [target]"
	@echo
	@echo "Available targets:"
	@echo "  all        : Build the $(EXEC) executable"
	@echo "  start      : Run the program with the 'en0' interface"
	@echo "  arp        : Analyze ARP packets in 'data/arp-storm.pcap'"
	@echo "  ipv4       : Analyze IPv4 packets in 'data/ipv4.pcap'"
	@echo "  ipv4_tcp   : Analyze IPv4 TCP packets in 'data/IPv4_TCP.pcapng'"
	@echo "  icmp       : Analyze ICMP packets in 'data/icmp.pcapng'"
	@echo "  ipv6       : Analyze IPv6 packets in 'data/v6.pcap'"
	@echo "  clean      : Remove object files and the executable"
	@echo "  help       : Display this help message"

# Declare phony targets to avoid conflicts with files
.PHONY: all clean help start arp ipv4 ipv4_tcp icmp ipv6