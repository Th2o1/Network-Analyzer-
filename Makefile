# ./analuseyr en0
# Nom de l'exécutable
EXEC = analyseur

# Fichiers sources et objets
SRC = analyseur.c
OBJ = $(SRC:.c=.o)

# Options de compilation
CC = gcc
CFLAGS = -Wall -Wextra -std=c11
LDFLAGS = -lpcap  # Ajout de la bibliothèque pcap

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

.PHONY: all clean

