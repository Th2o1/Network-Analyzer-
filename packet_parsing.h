#ifndef PACKET_PARSING
#define PACKET_PARSING

#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/ip.h> // IP Header 
#include <netinet/ip6.h> // IPv6 Header
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h> // Detection IPv4 / IPv6 

// Verbosity 
#include "global_value.h"

// Data link 
#include "datalink_layer/arp.h"
#include "datalink_layer/ethernet.h"

// Network layer
#include "network_layer/ipv4.h"
#include "network_layer/ipv6.h"
#include "network_layer/icmp.h"
#include "network_layer/icmpv6.h"

// Transport
#include "transport_layer/tcp.h"
#include "transport_layer/udp.h"


/**
 * @brief Parse and analyze a captured packet.
 *
 * This function processes the raw packet data to identify and analyze 
 * its contents based on the Ethernet header and encapsulated protocol.
 * 
 * The analysis includes:
 * - Ethernet header parsing.
 * - Protocol-specific parsing (IPv4, IPv6, ARP).
 *
 * For each recognized protocol, the appropriate parsing function 
 * is called to further dissect the packet.
 *
 * @param packet A pointer to the raw packet data.
 *
 * The function assumes the packet starts with an Ethernet header.
 * Detected protocols include IPv4, IPv6, and ARP.
 */
void parse_packet(const u_char *packet);

/**
 * @brief Parse and handle a specific protocol within a packet.
 *
 * This function identifies and processes a protocol encapsulated 
 * within an IPv4 or IPv6 header. Based on the protocol type, it 
 * delegates further parsing to the corresponding protocol handler.
 * 
 * Supported protocols include:
 * - TCP
 * - UDP
 * - ICMP
 * - ICMPv6
 *
 * @param protocol The protocol number as specified in the IP header.
 *                 Example values include IPPROTO_TCP, IPPROTO_UDP.
 * @param packet   A pointer to the raw packet data for the given protocol.
 */
void parse_protocol(u_char protocol, const u_char *packet, size_t header_size);

#endif // PACKET_PARSING