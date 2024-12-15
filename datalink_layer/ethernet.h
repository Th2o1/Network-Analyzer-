#ifndef ETH_PARSING
#define ETH_PARSING

#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <stdlib.h>

// eth
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>

/**
 * @brief Parse and display the source and destination Ethernet (MAC) addresses.
 *
 * This function extracts and prints the source and destination MAC addresses 
 * from an Ethernet header structure. It uses `print_ether_address` to format the addresses.
 *
 * @param eth_header A pointer to the `struct ether_header`, which contains the 
 *                   Ethernet frame information including source and destination addresses.
 *
 * Example output:
 * ```
 * 00:1A:2B:3C:4D:5E > 00:5E:6F:7G:8H:9I
 * ```
 */
void parse_eth(struct ether_header *eth_header);


/**
 * @brief Print the Ethernet (MAC) address in a readable format.
 *
 * This function takes an array of bytes representing a MAC address 
 * and prints it in the standard colon-separated hexadecimal format (e.g., `00:1A:2B:3C:4D:5E`).
 *
 * @param addr A pointer to the array containing the MAC address.
 *             This array is expected to be of length `ETHER_ADDR_LEN` (6 bytes).
 */
void print_ether_address(const u_char* addr);

#endif