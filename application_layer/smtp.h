#ifndef SMTP_PARSING
#define SMTP_PARSING

//Include 
#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/tcp.h>
#include "../global_value.h"

int is_smtp(const u_char *payload, size_t size) ;
void parse_smtp(const u_char *packet, size_t offset);
#endif