#ifndef TRANSPORT_LAYER
#define TRANSPORT_LAYER
//Include 
#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h> 
#include <netinet/icmp6.h>
#include "global_value.h"
#include "tcp_utils.h"


// Function Header 

// Check protocol
// parse_protocol.h

/**
 * @brief Parses the protocol-specific data based on the provided protocol number.
 *
 * This function identifies the protocol of the given packet (such as TCP, UDP, ICMP, or ICMPv6)
 * and calls the respective parsing function to process the packet further.
 * 
 * @param protocol The protocol number from the IP header (e.g., IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP, or IPPROTO_ICMPV6).
 * @param packet A pointer to the packet data that contains the protocol-specific information to be parsed.
 *
 * @note The function works with both IPv4 and IPv6 protocols, delegating to appropriate handlers
 * for each protocol type:
 * - IPPROTO_TCP: TCP protocol
 * - IPPROTO_UDP: UDP protocol
 * - IPPROTO_ICMP: ICMP protocol (for IPv4)
 * - IPPROTO_ICMPV6: ICMPv6 protocol (for IPv6)
 */
void parse_protocol(u_char protocol, const u_char *packet);

void parse_tcp(const u_char *packet);

void parse_udp(const u_char *packet);
void parse_icmp(const u_char *packet);
void check_tcp_flags(uint8_t flags); 

#endif // TRANSPORT_LAYER

