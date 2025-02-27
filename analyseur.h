#ifndef ANALYSEUR
#define ANALYSEUR

// Include
#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h> // to catch signal
#include <netinet/in.h>
#include <netinet/ip.h> // IP header 
#include <net/ethernet.h> // Detection IPv4 / IPv6 
#include "global_value.h"
#include "packet_parsing.h" // To manage the link layer (IPv4/6, ARP)
#include <sys/time.h> // localtime
#ifdef __linux__
#include <time.h>
#endif



// Function Header

    // Function call by the loop to parse packet
void packet_handler(u_char *verbosity, const struct pcap_pkthdr *pkthdr, const u_char *packet); 

#endif // ANALYSEUR