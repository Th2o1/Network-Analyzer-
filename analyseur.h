#ifndef ANALYSEUR
#define ANALYSEUR

// Include
#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/ip.h> // IP header 
#include <net/ethernet.h> // Detection IPv4 / IPv6 
#include "link_layer.h" // To manage the link layer (IPv4/6, ARP)

// Function Header

    // Function call by the loop to parse packet
void packet_handler(u_char *verbosity, const struct pcap_pkthdr *pkthdr, const u_char *packet); 

#endif // ANALYSEUR