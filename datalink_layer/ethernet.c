#include "ethernet.h"

void parse_eth(struct ether_header *eth_header){
    if(verbosity == 1) return;
    print_ether_address(eth_header->ether_dhost);
    printf("> ");
    print_ether_address(eth_header->ether_shost);
}