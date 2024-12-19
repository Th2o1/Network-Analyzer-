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
    int ligne_number = 0;
    char ascii_line[17];
    ascii_line[16] = '\0';
    printf("%04x  ", ligne_number);
    for (int i = 0; i < length; i++) {
        ligne_number++; 
        printf("%02x ", packet[i]);
        // Convert byte to ASCII
        ascii_line[i % 16] = (packet[i] >= 32 && packet[i] <= 126) ? packet[i] : '.';
        
        if ((i + 1) % 16 == 0) {
            printf("\t");
            for(int j = 0; j < 16 ; j++) printf("%c", ascii_line[j]); // Print ascii line
            printf("\n");
            printf("%04x  ", ligne_number);
        }
    }
    if (length % 16 != 0) {
        for(int i = 0 ; i<16 - length % 16; i++){ // PADDING
            printf("   ");
        }
        printf("\t");
        for(int j = 0 ; j<length % 16; j++) printf("%c", ascii_line[j]);
        printf("\n");
    }
}


void parse_ascii(const u_char *packet, size_t offset){

    const u_char *payload = (packet+offset);
    if (packet_size - offset < 4) { // Case -> end transaction
        return;
    }
    int length = packet_size - offset;
    printf("Length: %d \n", length);
    char *payload_data = (char *)malloc((length + 1)*sizeof(char));
    if (!payload_data) {
        fprintf(stderr, "Failed to allocate memory for payload.\n");
        return;
    }
    memcpy(payload_data, payload, length);
    payload_data[length] = '\0';

    for (int i = 0; i < length; i++) {
        char c = payload_data[i];
        if ( !((c >= 32 && c <= 126) || c == 10 || c == 13 )){
            free(payload_data);
            return;// Character is NOT in ASCII (or a space)
        } 
    }   
    // Print the payload line by line
    char *line = strtok(payload_data, "\r\n");
    while (line != NULL) {
        printf("  %s\n", line);
        line = strtok(NULL, "\r\n");
    }

    free(payload_data);
}