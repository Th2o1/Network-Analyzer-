#include "smtp.h"
void parse_smtp(const u_char *packet, size_t offset){

    const u_char *payload = (packet+offset);
    if (strlen((const char *)payload) < 4) { // Case -> end tcp transaction
        return;
    }
    int smtp_length = packet_size - offset;
    printf("SMTP: Length: %d \n", smtp_length);
    char *smtp_data = (char *)malloc(smtp_length + 1);
    if (!smtp_data) {
        fprintf(stderr, "Failed to allocate memory for SMTP payload.\n");
        return;
    }
    memcpy(smtp_data, payload, smtp_length);
    smtp_data[smtp_length] = '\0';

    // Print the payload line by line
    char *line = strtok(smtp_data, "\r\n");
    while (line != NULL) {
        printf("  %s\n", line);
        line = strtok(NULL, "\r\n");
    }

    free(smtp_data);
}
