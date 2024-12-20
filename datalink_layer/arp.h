#ifndef ARP_PARSE
#define ARP_PARSE

#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include "ethernet.h"

#ifdef __linux__
#define ARPHRD_FRELAY ARPHRD_DLCI
#define ARPHRD_IEEE1394_EUI64 ARPHRD_IEEE1394
#define ARPOP_REVREQUEST                                                       \
  ARPOP_RREQUEST /* request protocol address given hardware */
#define ARPOP_REVREPLY ARPOP_RREPLY      /* response giving protocol address */
#define ARPOP_INVREQUEST ARPOP_InREQUEST /* request to identify peer */
#define ARPOP_INVREPLY ARPOP_InREPLY     /* response identifying peer */
#endif

/**
 * @brief Parse and display the operation type of an ARP packet.
 *
 * @param ar_op The operation code from the ARP header (e.g., ARPOP_REQUEST, ARPOP_REPLY).
 *              This indicates the type of ARP operation.
 */
void parse_ARP_operation(u_short ar_op, const struct ether_arp *arp_header);

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

/**
 * @brief Parse and display the content of an ARP packet.
 *
 * This function extracts and displays the details of an ARP packet, 
 * including operation type, hardware address format, protocol format, 
 * sender/target MAC and IP addresses, and the size of the MAC address field.
 *
 * @param packet A pointer to the raw packet data captured.
 *
 * The function assumes the packet begins with an Ethernet header 
 * and directly processes the ARP header after the Ethernet portion.
 * 
 * Details displayed:
 * - ARP operation type (e.g., request, reply).
 * - Protocol address format (e.g., IPv4, IPv6).
 * - Hardware address format (e.g., Ethernet).
 * - Sender and target hardware (MAC) and protocol (IP) addresses.
 * - Length of the hardware address field.
 */
void parse_ARP(const u_char *packet);


#endif // ARP_PARSE