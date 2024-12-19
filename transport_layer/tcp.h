#ifndef TCP_PARSE
#define TCP_PARSE

//Include 
#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/tcp.h>

#include "../global_value.h"
#include "../application_layer/telnet.h"
#include "../application_layer/dns.h"


#ifdef __linux__
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
#define TH_ECE 0x40
#define TH_CWR 0x80
#endif


//Function Header 
/**
 * @brief Prints raw TCP options in hexadecimal format.
 *
 * @param tcp_options Pointer to the start of the TCP options.
 */
void tcp_print_raw(const u_char* tcp_options);

/**
 * @brief Prints all TCP flags present in a packet.
 *
 * @param flags The flags byte from the TCP header.
 *              Possible values include:
 *              - TH_FIN: Finish flag
 *              - TH_SYN: Synchronize flag
 *              - TH_RST: Reset flag
 *              - TH_PUSH: Push flag
 *              - TH_ACK: Acknowledgment flag
 *              - TH_URG: Urgent flag
 *              - TH_ECE: Explicit Congestion Notification Echo flag
 *              - TH_CWR: Congestion Window Reduced flag
 */
void check_tcp_flags(uint8_t flags);

/**
 * @brief Parses and prints all TCP options in a packet.
 *
 * @param tcp_options Pointer to the start of the TCP options.
 * @param options_size The total size of the options in bytes.
 */
void check_tcp_options(const u_char* tcp_options, unsigned int options_size);

/**
 * @brief Displays the TCP header fields in a human-readable format.
 *
 * @param tcp_header Pointer to a `struct tcphdr` containing the TCP header.
 *                   This structure must be filled before calling this function.
 */
void display_tcp_header(struct tcphdr* tcp_header);

void parse_tcp(const u_char *packet, size_t size_header);
#endif // TCP_PARSE