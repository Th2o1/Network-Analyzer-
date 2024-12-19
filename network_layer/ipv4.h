#ifndef IPV4_PARSING
#define IPV4_PARSING

#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <stdlib.h>

#include "../packet_parsing.h"

//IP
#include <netinet/ip.h> // IP Header 

#define OPT_EOL   0  // End of Options List
#define OPT_NOP   1  // No Operation
#define OPT_RR    7  // Record Route
#define OPT_TS    68 // Time Stamp
#define OPT_LSR   131 // Loose Source Route
#define OPT_COS   134 // Commercial Security
#define OPT_SSR   137 // Strict Source Route

// FUNCTION DEFINITION

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


#endif