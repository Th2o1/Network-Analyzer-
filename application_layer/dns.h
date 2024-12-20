#ifndef DNS_PARSE
#define DNS_PARSE


#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "../global_value.h"

// DNS Record Types
#define TYPE_A      1   // IPv4 address
#define TYPE_NS     2   // Name server
#define TYPE_CNAME  5   // Canonical name
#define TYPE_SOA    6   // Start of authority
#define TYPE_PTR    12  // Pointer
#define TYPE_MX     15  // Mail exchange
#define TYPE_TXT    16  // Text
#define TYPE_AAAA   28  // IPv6 address
#define TYPE_SRV    33  // Service record

// DNS Classes
#define CLASS_IN    1   // Internet
#define CLASS_CH    3   // Chaos
#define CLASS_HS    4   // Hesiod

typedef enum {
    DNS_SECTION_QUERY, // Query
    DNS_SECTION_ANSWER, // Answer
    DNS_SECTION_AUTHORITY, // Authority
    DNS_SECTION_ADDITIONAL // Additional
} dns_section;

void parse_dns(const u_char *packet, size_t header_size);


#endif