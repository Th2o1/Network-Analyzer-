#ifndef BOOTP_DHCP_H
#define BOOTP_DHCP_H


#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <netinet/bootp.h>


#include "../global_value.h"

// ALL DHCP OPTION 



#define DHCP_OPTION_PAD               0   // Padding
#define DHCP_OPTION_SUBNET_MASK       1   // Subnet Mask
#define DHCP_OPTION_ROUTER            3   // Router
#define DHCP_OPTION_DNS_SERVER        6   // Domain Name Server
#define DHCP_OPTION_HOST_NAME        12   // Host Name
#define DHCP_OPTION_REQUESTED_IP     50   // Requested IP Address
#define DHCP_OPTION_LEASE_TIME       51   // IP Address Lease Time
#define DHCP_OPTION_MESSAGE_TYPE     53   // DHCP Message Type
#define DHCP_OPTION_SERVER_ID        54   // DHCP Server Identifier
#define DHCP_OPTION_PARAMETER_LIST   55   // Parameter Request List
#define DHCP_OPTION_RENEWAL_TIME     58   // Renewal Time Value
#define DHCP_OPTION_REBINDING_TIME   59   // Rebinding Time Value
#define DHCP_OPTION_CLIENT_ID        61   // Client identifier 

#define DHCP_OPTION_END             255   // End


// Function declaration for BOOTP/DHCP parsing
/**
 * @brief Parses and processes a BOOTP/DHCP packet.
 *
 * This function extracts key fields from a BOOTP header, such as the operation type,
 * hardware type, client IP address, relay or server addresses, etc. 
 * If the packet contains DHCP options (identified by the DHCP magic cookie), 
 * it parses and processes each option by invoking the `process_dhcp_option` function.
 *
 * @param packet Pointer to the start of the packet data to be parsed.
 *               The packet should include a valid BOOTP header.
 * @param offset Offset in the packet where the BOOTP/DHCP header begins.
 *               This accounts for lower-layer headers (such as Ethernet or IP).
 *
 * @details The function performs the following tasks:
 *          - Displays key BOOTP packet information (operation type, IP addresses, etc.).
 *          - If a DHCP magic cookie is detected, parses and displays DHCP options.
 *          - For each DHCP option, calls `process_dhcp_option` to display detailed
 *            information based on the option type.
 *
 * Example DHCP options that may be supported:
 * - Requested IP Address.
 * - DHCP Message Type.
 * - DHCP Server Identifier.
 *
 * @note Ensure the `process_dhcp_option` function is implemented to handle 
 *       specific DHCP options appropriately.
 *
 * @see process_dhcp_option
 */
void parse_bootp(const u_char *packet, size_t offset);

#endif // BOOTP_DHCP_H