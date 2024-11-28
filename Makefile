# ./analyseur -i en0
# Nom de l'exécutable
EXEC = analyseur

# Fichiers sources et objets
SRC = analyseur.c link_layer.c transport_layer.c tcp_utils.c
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
test: $(EXEC)
	./$(EXEC) -i en0

test_arp: $(EXEC)
	./$(EXEC) -o data/arp-storm.pcap



.PHONY: test all clean

