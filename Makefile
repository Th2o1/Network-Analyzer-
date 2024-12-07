# ./analyseur -i en0
# Nom de l'exécutable
EXEC = analyseur

# Fichiers sources et objets
SRC = analyseur.c link_layer.c transport_layer.c arp_utils.c tcp_utils.c 
OBJ = $(SRC:.c=.o)

# Options de compilation
CC = gcc
CFLAGS = -Wall -Wextra -std=c11
LDFLAGS = -lpcap  #la bibliothèque pcap

# Règle par défaut
all: $(EXEC)

# Compilation de l'exécutable
$(EXEC): $(OBJ)
	$(CC) $(CFLAGS) -o $(EXEC) $(OBJ) $(LDFLAGS)

# Compilation des fichiers objets
%.o: %.c %.h
	$(CC) $(CFLAGS) -c $< -o $@

# Nettoyage des fichiers objets et de l'exécutable
clean:
	rm -f $(OBJ) $(EXEC)

# Test 
start: $(EXEC)
	./$(EXEC) -i en0

arp: $(EXEC)
	./$(EXEC) -o data/arp-storm.pcap
ipv4: $(EXEC)
	./$(EXEC) -o data/ipv4.pcap
ipv4_tcp: $(EXEC)
	./$(EXEC) -o data/IPv4_TCP.pcapng
icmp: $(EXEC)
	./$(EXEC) -o data/icmp.pcapng
ipv6: $(EXEC)
	./$(EXEC) -o data/v6.pcap



.PHONY: test all clean

