#include "bootp_dhcp.h"

// Function to process and display DHCP option data
void process_dhcp_option(uint8_t option_code, const uint8_t *data, uint8_t length) {
    switch (option_code) {
        case DHCP_OPTION_PAD: // PADDING 
            printf("Padding (Code: %u, Data: None) ", option_code);
            break;

        case DHCP_OPTION_SUBNET_MASK: { // MASK 
            if (length == 4) {
                struct in_addr subnet_mask;
                memcpy(&subnet_mask, data, 4);
                printf("Subnet Mask (Code: %u, Data: %s) ", option_code, inet_ntoa(subnet_mask));
            } else {
                printf("Subnet Mask (Code: %u, Data: Invalid length %u) ", option_code, length);
            }
            break;
        }

        case DHCP_OPTION_ROUTER: { 
            printf("Router (Code: %u, Data: ", option_code);
            if (length % 4 == 0) {
                for (int i = 0; i < length; i += 4) {
                    struct in_addr router;
                    memcpy(&router, data + i, 4);
                    printf("%s ", inet_ntoa(router));
                }
                printf(") ");
            } else {
                printf("Invalid length %u) ", length);
            }
            break;
        }

        case DHCP_OPTION_DNS_SERVER: {
            printf("DNS Server (Code: %u, Data: ", option_code);
            if (length % 4 == 0) {
                for (int i = 0; i < length; i += 4) {
                    struct in_addr dns_server;
                    memcpy(&dns_server, data + i, 4);
                    printf("%s ", inet_ntoa(dns_server));
                }
                printf(") ");
            } else {
                printf("Invalid length %u) ", length);
            }
            break;
        }

        case DHCP_OPTION_HOST_NAME:
            printf("Host Name (Code: %u, Data: %.*s) ", option_code, length, data);
            break;

        case DHCP_OPTION_REQUESTED_IP: {
            if (length == 4) {
                struct in_addr requested_ip;
                memcpy(&requested_ip, data, 4);
                printf("Requested IP (Code: %u, Data: %s) ", option_code, inet_ntoa(requested_ip));
            } else {
                printf("Requested IP (Code: %u, Data: Invalid length %u) ", option_code, length);
            }
            break;
        }

        case DHCP_OPTION_LEASE_TIME:
        case DHCP_OPTION_RENEWAL_TIME:
        case DHCP_OPTION_REBINDING_TIME: {
            if (length == 4) {
                uint32_t time_value;
                memcpy(&time_value, data, 4);
                printf("Time Value (Code: %u, Data: %u seconds) ", option_code, ntohl(time_value));
            } else {
                printf("Time Value (Code: %u, Data: Invalid length %u) ", option_code, length);
            }
            break;
        }

        case DHCP_OPTION_MESSAGE_TYPE:
            if (length == 1) {
                const char *message_type = "Unknown";
                switch (data[2]) {
                    case 1: message_type = "DISCOVER"; break;
                    case 2: message_type = "OFFER"; break;
                    case 3: message_type = "REQUEST"; break;
                    case 4: message_type = "DECLINE"; break;
                    case 5: message_type = "ACK"; break;
                    case 6: message_type = "NAK"; break;
                    case 7: message_type = "RELEASE"; break;
                    case 8: message_type = "INFORM"; break;
                }
                printf("%s (Code: %u) ", message_type,option_code );
            } else {
                printf("DHCP Message Type (Code: %u, Data: Invalid length %u) ", option_code, length);
            }
            break;

        case DHCP_OPTION_SERVER_ID: {
            if (length == 4) {
                struct in_addr server_id;
                memcpy(&server_id, data, 4);
                printf("Server ID (Code: %u, Data: %s) ", option_code, inet_ntoa(server_id));
            } else {
                printf("Server ID (Code: %u, Data: Invalid length %u) ", option_code, length);
            }
            break;
        }

        case DHCP_OPTION_PARAMETER_LIST:
            printf("Parameter List (Code: %u, Data: ", option_code);
            for (int i = 0; i < length; i++) {
                printf("%u ", data[i]);
            }
            printf(") ");
            break;

        case DHCP_OPTION_END:
            printf("End (Code: %u, Data: None) ", option_code);
            break;

        default:
            printf("Unknown (Code: %u, Data: ", option_code);
            for (int i = 0; i < length; i++) {
                printf("%02x ", data[i]);
            }
            printf(") ");
            break;
    }
}

// Function to parse BOOTP/DHCP packets
void parse_bootp(const u_char *packet, size_t offset) {
    // Extract the BOOTP header from the packet
    const struct bootp *bootp_header = (const struct bootp *)(packet + offset);

    printf("BOOTP: ");
    printf("Operation: %s ", bootp_header->bp_op == BOOTREQUEST ? "BOOTREQUEST" : "BOOTREPLY");
    printf("Hardware Type: %u ", bootp_header->bp_htype);
    printf("Hardware Address Length: %u ", bootp_header->bp_hlen);
    printf("Hops: %u ", bootp_header->bp_hops);
    printf("Transaction ID: 0x%08x ", ntohl(bootp_header->bp_xid));
    printf("Seconds Elapsed: %u ", ntohs(bootp_header->bp_secs));
    printf("Client IP Address: %s ", inet_ntoa(bootp_header->bp_ciaddr));
    printf("Your (Client) IP Address: %s ", inet_ntoa(bootp_header->bp_yiaddr));
    printf("Server IP Address: %s ", inet_ntoa(bootp_header->bp_siaddr));
    printf("Relay Agent IP Address: %s ", inet_ntoa(bootp_header->bp_giaddr));
    printf("Client Hardware Address: ");
    print_ether_address(bootp_header->bp_chaddr);
    if(verbosity == HIGH){
        printf("Server Host Name: %.64s ", bootp_header->bp_sname);
    
        printf("Boot File Name: %.128s ", bootp_header->bp_file);
    }
    // Parse vendor-specific area if it's DHCP
    const uint8_t dhcp_magic_cookie[] = {0x63, 0x82, 0x53, 0x63};
    if (memcmp(bootp_header->bp_vend, dhcp_magic_cookie, 4) == 0) { // Compare with magic number
        const u_char *options = bootp_header->bp_vend + 4; // Start after the magic number
        printf("DHCP: ");
        while (*options != 0xFF) { // 0xFF marks the end of DHCP options
            uint8_t option_code = options[0]; // First Octet is the option
            uint8_t option_length = options[1]; // Second one is the length

            process_dhcp_option(option_code, options,option_length);

            options += 2 + option_length; // Move to the next option
        }
    }
}