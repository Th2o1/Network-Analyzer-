// Define for verbosity 
#include <stdint.h>
#include <stddef.h>
#include <pcap.h>
#include <stdlib.h>
#include <stdint.h> // For uint8_t
#include <sys/types.h>
#include <stdio.h>  // For printf
#include <string.h>
#include <netinet/ip.h> // IP Header 
#include <arpa/inet.h>

#include <netinet/if_ether.h>
#include <net/ethernet.h>

// Low verbosity : very concise
#define LOW 1 
// Medium verbosity : synthetic
#define MEDIUM 2
// high verbosity : complete
#define HIGH 3

// Give the level of verbosity needed (1 : low / 2 : medium / 3 : high)
int verbosity;
// Total lenght of the packet (with all layer)
size_t packet_size;

/**
 * Calculates the Internet Checksum (16-bit one's complement) for a given buffer of data.
 *
 * @param vdata A pointer to the data buffer for which the checksum needs to be calculated.
 *              This buffer should be of type `const void*` to ensure proper type safety.
 * @param length The length of the data buffer in bytes.
 *               It should be a multiple of 2, but the function handles odd-length buffers.
 *
 * @return A 16-bit checksum of the provided data.
 *         This value is the one's complement of the sum of all 16-bit words in the data.
 */
uint16_t checksum_calc(const void *vdata, size_t length);
void print_packet(const unsigned char *packet, int length);
void print_ether_address(const u_char* addr); 
void parse_ascii(const u_char *packet, size_t offset);   