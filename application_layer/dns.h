#ifndef DNS_PARSE
#define DNS_PARSE


#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>


typedef enum {
    DNS_SECTION_QUERY, // Query
    DNS_SECTION_ANSWER, // Answer
    DNS_SECTION_AUTHORITY, // Authority
    DNS_SECTION_ADDITIONAL // Additional
} dns_section;

void parse_dns(const u_char *packet, size_t header_size);


#endif