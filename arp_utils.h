#ifndef ARP_PARSE
#define ARP_PARSE

#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h> // IP Header 
#include <netinet/ip6.h> // IPv6 Header
#include <arpa/inet.h>
#include <netinet/if_ether.h>

/**
 * @brief Parse and display the operation type of an ARP packet.
 *
 * @param ar_op The operation code from the ARP header (e.g., ARPOP_REQUEST, ARPOP_REPLY).
 *              This indicates the type of ARP operation.
 */
void parse_ARP_operation(u_short ar_op);

/**
 * @brief Display the protocol address format of an ARP packet.
 *
 * @param ar_pro The protocol address format field from the ARP header.
 *               This represents the type of protocol (e.g., IPv4, IPv6, ARP).
 */
void print_ARP_protocol_format(u_short ar_pro);

/**
 * @brief Display the hardware address format of an ARP packet.
 *
 * @param ar_hrd The hardware address format field from the ARP header.
 *               This indicates the type of hardware used (e.g., Ethernet, Token-ring).
 */
void print_hardware_format(u_short ar_hrd);

#endif // ARP_PARSE