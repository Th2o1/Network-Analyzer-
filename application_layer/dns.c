#include "dns.h"

void process_dns_type(uint16_t type) {
    printf("Type: ");
    switch (type) {
        case 1:
            printf("A ");
            break;
        case 2:
            printf("NS ");
            break;
        case 5:
            printf("CNAME ");
            break;
        case 6:
            printf("SOA ");
            break;
        case 12:
            printf("PTR ");
            break;
        case 15:
            printf("MX ");
            break;
        case 16:
            printf("TXT ");
            break;
        case 28:
            printf("AAAA ");
            break;
        case 33:
            printf("SRV ");
            break;
        default:
            printf("Unknown ");
            break;
    }
    printf("(%u), ", type);
}

void process_dns_class(uint16_t class) {
    printf("Class: ");
    switch (class) {
        case 1:
            printf("IN ");
            break;
        case 3:
            printf("CH ");
            break;
        case 4:
            printf("HS ");
            break;
        default:
            printf("Unknown ");
            break;
    }
    printf("(%u)\n", class);
}

int process_dns_flags(uint16_t flags) {
    int is_response = 0;
    // QR : Query (0) or Response (1)
    switch ((flags >> 15) & 0x1) { // Extraire le 1er bit (QR)
        case 0:
            printf("Query ");
            break;
        case 1:
            printf("Response ");
            is_response = 1;
            break;
    }
    if (verbosity == LOW) return is_response;
    printf("[ ");
    // Opcode (bits 1-4)
    switch ((flags >> 11) & 0xF) { 
        case 0:
            printf("QUERY, ");
            break;
        case 1:
            printf("IQUERY ");
            break;
        case 2:
            printf("STATUS ");
            break;
        default:
            printf("Unknown ");
            break;
    }

    // AA : Authoritative Answer (bit 5)
    if ((flags >> 10) & 0x1) {
        printf("AA, ");
    }

    // TC : Truncated (bit 6)
    if ((flags >> 9) & 0x1) {
        printf("TC, ");
    }

    // RD : Recursion Desired (bit 7)
    if ((flags >> 8) & 0x1) {
        printf("RD, ");
    }
    

    // RA : Recursion Available (bit 8)
    if ((flags >> 7) & 0x1) {
        printf("RA, ");
    } 

    // RCODE : Response Code (bits 12-15)
    switch (flags & 0xF) { // Extraire les 4 derniers bits (RCODE)
        case 0:
            printf("No Error");
            break;
        case 1:
            printf("Format Error");
            break;
        case 2:
            printf("Server Failure");
            break;
        case 3:
            printf("Name Error");
            break;
        case 4:
            printf("Not Implemented");
            break;
        case 5:
            printf("Refused");
            break;
        default:
            printf("Unknown");
            break;
    }
    printf("] ");
    return is_response;
}

int get_dns_name(const unsigned char *packet, int offset, char *dns_name) {
    int i = 0, j = 0;
    while (packet[offset + i] != 0) { // 00 mark the end of the dns name 
        int length = packet[offset + i];
        if (length >= 192) { // Indicate a caracter
            int pointer = ((length & 0x3F) << 8) | packet[offset + i + 1];
            get_dns_name(packet, pointer, dns_name + j);
            return i + 2; 
        } else { // Indicate a length so we put a "." for the separation
            if (j > 0) dns_name[j++] = '.'; 
            memcpy(dns_name + j, packet + offset + i + 1, length);
            j += length;
            i += length + 1;
        }
    }
    dns_name[j] = '\0';
    return i + 1; // +1 for the null octet
}

char* get_section_name(dns_section section_type){
    switch (section_type)
    {
    case DNS_SECTION_QUERY:
        return "Queries";
        break;
    
    case DNS_SECTION_ANSWER:
        return "Answer";
        break;
    
    case DNS_SECTION_ADDITIONAL:
        return "Additional";
        break;
    
    case DNS_SECTION_AUTHORITY:
        return "Authority";
        break;
    
    default:
        return "Unknow";
        break;
    }
}

int parse_dns_rr(const unsigned char *dns_header, int offset, int count, dns_section section_type) {
    char dns_name[256]; // Buffer to store the domain name
    if (count <= 0){ // If no section
        return 0;
    }
    for (int i = 0; i < count; i++) {

        // Parse the name
        int name_size = get_dns_name(dns_header, offset, dns_name);
        offset += name_size;
        uint16_t data_length = (dns_header[offset + 8] << 8) | dns_header[offset + 9];
        // Parse the fields
        uint16_t type = (dns_header[offset] << 8) | dns_header[offset + 1];
        uint16_t class = (dns_header[offset + 2] << 8) | dns_header[offset + 3];
        uint32_t ttl = (dns_header[offset + 4] << 24) | (dns_header[offset + 5] << 16) |
                (dns_header[offset + 6] << 8) | dns_header[offset + 7];
        
        if(verbosity>=MEDIUM){    
            printf("\n[%s %d]\n", get_section_name(section_type), i + 1);


            
            // Print details
            printf("Name: %s\n", dns_name);
            process_dns_type(type);
            process_dns_class(class);
            printf("TTL: %u, Data Length: %u\n", ttl, data_length);
            
            // Print the data (could be IP, name, etc., depending on the type)
            printf("Data: ");
        }
        offset += 10; // type (2) + Class (2) + ttl (4) + data length (2)
        for (int j = 0; j < data_length; j += 4) {
        if (j + 3 < data_length) {
            printf("%u.%u.%u.%u ", 
                   dns_header[offset + j], 
                   dns_header[offset + j + 1], 
                   dns_header[offset + j + 2], 
                   dns_header[offset + j + 3]);
        } else {
            for (int k = j; k < data_length; ++k) {
                printf("%u", dns_header[offset + k]);
                if (k < data_length - 1) {
                    printf(".");
                }
            }
        }
        if(verbosity == LOW) return 0; // stop after one rotation to have the data
        }
        printf("\n");
        offset += data_length;
    }
    return offset;
}

void parse_dns(const u_char *packet, size_t header_size){
    const u_char *dns_header = (packet+header_size);
    // We take the first octet then we move from 8 bit and add the 2nd octet with | operation
    //     0b10101011 00000000  (0xAB00)
    // |   0b00000000 11001101 (0x00CD)
    //     -----------------------
    //     0b10101011 11001101  (0xABCD)
    // Other way to do it 
    // uint16_t transaction_id;
    // memcpy(&transaction_id, dns_header, sizeof(uint16_t));
    // transaction_id =  ntohs(transaction_id);
    uint16_t transaction_id = (dns_header[0] << 8) | dns_header[1];

    // Flags
    uint16_t flags = (dns_header[2] << 8) | dns_header[3];

    // Question / Awnsers / Authority / Additional count 
    uint16_t qd_count = (dns_header[4] << 8) | dns_header[5];
    uint16_t an_count = (dns_header[6] << 8) | dns_header[7];
    uint16_t ns_count = (dns_header[8] << 8) | dns_header[9];
    uint16_t ar_count = (dns_header[10] << 8) | dns_header[11];


    size_t offset = 12; // Where we are in the dns
    char dns_name[256]; // To stock the domain name

    printf("TID: 0x%04x ", transaction_id);
    int is_response = process_dns_flags(flags);
    printf("Querie : %u, ", qd_count);
    printf("Answer: %u, ", an_count);
    printf("Authority: %u, ", ns_count);
    printf("Additional: %u, ", ar_count);
    printf("Length: %zu ", packet_size - offset);
    for (int i = 0; i < qd_count; i++) {
        int name_size = get_dns_name(dns_header, offset, dns_name);
        if(verbosity == LOW && !is_response){
            printf("Name: %s\n", dns_name);
            return;
        } 
        if (verbosity == LOW) offset += name_size + 4; // we add the offset even if we not display
        
        
        if (verbosity >= MEDIUM){
            printf("\n");
            printf("\n[Question %d]\n", i + 1);
            offset += name_size;

            uint16_t type = (dns_header[offset] << 8) | dns_header[offset + 1];
            uint16_t class = (dns_header[offset + 2] << 8) | dns_header[offset + 3];
            offset += 4;
            printf("Name: %s\n", dns_name);
            if(verbosity == MEDIUM){ printf("\n"); continue;} 
            process_dns_type(type);
            process_dns_class(class);


        }
    }

    offset += parse_dns_rr(dns_header, offset, an_count, DNS_SECTION_ANSWER);
    if(verbosity == LOW) return;
    offset += parse_dns_rr(dns_header, offset, ns_count, DNS_SECTION_AUTHORITY);
    offset += parse_dns_rr(dns_header, offset, ar_count, DNS_SECTION_ADDITIONAL);


}