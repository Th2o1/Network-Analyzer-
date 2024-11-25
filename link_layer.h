#ifndef LINK
#define LINK

//All include
#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/ip.h> // IP Header 
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <net/ethernet.h> // Detection IPv4 / IPv6 
#include "transport_layer.h"


//Fonction Header

void parse_packet(const u_char *packet);
/**
 * @brief Parses an IPv4 packet.
 *
 * This function extracts the necessary information from the IPv4 header,
 * prints the source and destination IP addresses, and dispatches the packet
 * to the appropriate protocol handler (TCP, UDP, ICMP, etc.) based on the
 * protocol field in the IPv4 header.
 *
 * @param packet A pointer to the packet data containing the Ethernet and IPv4 headers.
 *
 * @note The function prints basic IPv4 information like the source and destination addresses,
 * and forwards the packet to `parse_protocol` for further protocol-specific handling.
 */
void parse_IPv4(const u_char *packet);
/**
 * @brief Parses an IPv6 packet.
 *
 * This function extracts the necessary information from the IPv6 header,
 * prints the source and destination IP addresses, and dispatches the packet
 * to the appropriate protocol handler (TCP, UDP, ICMP, etc.) based on the
 * Next Hop field in the IPv6 header.
 *
 * @param packet A pointer to the packet data containing the Ethernet and IPv4 headers.
 */
void parse_IPv6(const u_char *packet);
void parse_ARP(const u_char *packet);



#endif // LINK 