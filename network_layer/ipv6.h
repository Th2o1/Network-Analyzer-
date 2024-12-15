#ifndef IPV6_PARSING
#define IPV6_PARSING

#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <stdlib.h>

#include "../packet_parsing.h"

//IP
#include <netinet/ip.h> // IP Header 
#include <netinet/ip6.h> // IPv6 Header
#include <netinet/ip.h> // IP Header 

// FUNCTION HEADER

/**
 * @brief Parse and display information about an IPv6 packet.
 *
 * This function extracts and displays key fields from the IPv6 header, such as 
 * source and destination addresses, payload length, hop limit, and the next header field.
 * It also calls `parse_protocol` to handle the encapsulated protocol (e.g., TCP, UDP, ICMPv6).
 *
 * @param packet A pointer to the raw packet data captured. The function assumes the Ethernet 
 *               header is located at the beginning of the packet, and the IPv6 header follows it.
 *
 * IPv6 Header Fields Parsed:
 * - **Source Address**: Extracted and displayed in standard IPv6 format (e.g., `2001:db8::1`).
 * - **Destination Address**: Same format as the source address.
 * - **Payload Length**: The length of the IPv6 payload, excluding the header (16-bit field).
 * - **Hop Limit**: Decremented by routers, analogous to the TTL field in IPv4.
 * - **Next Header**: Identifies the protocol encapsulated in the payload (e.g., TCP, UDP, ICMPv6).
 *
 * Example output:
 * ```
 * IPv6 Packet from 2001:db8::1 to 2001:db8::2 Payload length 64 Hops Limits 128 Next Header 6
 * ```
 * 
 */
void parse_IPv6(const u_char *packet);

#endif