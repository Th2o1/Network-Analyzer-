#include "global_value.h"


void print_ether_address(const u_char* addr) {
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        printf("%02x", addr[i]); // Display octet
        if (i < ETHER_ADDR_LEN - 1) {
            printf(":");
        }
    }
    printf(" ");
}

// Calculation of the chacksums
uint16_t checksum_calc(const void *vdata, size_t length) {
    const uint16_t *data = (const uint16_t *)vdata;
    uint32_t sum = 0;

    // adding every word
    for (; length > 1; length -= 2) {
        sum += *data++;
    }

    // if packet size is odd
    if (length == 1) {
        sum += *(const uint8_t *)data;
    }

    // adding bit 
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // complement to 1
    return ~sum;
}




// Debugging purpose 
void print_packet(const unsigned char *packet, int length) {
    printf("Packet dump (length: %d bytes):\n", length);
    for (int i = 0; i < length; i++) {
        printf("%02x ", packet[i]);
        
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
    if (length % 16 != 0) {
        printf("\n");
    }
    printf("---------------------");
}