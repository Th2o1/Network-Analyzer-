#include "global_value.h"


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