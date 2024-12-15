#include "ethernet.h"

void print_ether_address(const u_char* addr) {
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        printf("%02x", addr[i]); // Display octet
        if (i < ETHER_ADDR_LEN - 1) {
            printf(":");
        }
    }
    printf(" ");
}

void parse_eth(struct ether_header *eth_header){
    print_ether_address(eth_header->ether_dhost);
    printf("> ");
    print_ether_address(eth_header->ether_shost);
}