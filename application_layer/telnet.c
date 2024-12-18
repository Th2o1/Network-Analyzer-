#include "telnet.h"

void process_telnet_command(uint8_t command) {
    switch (command) {
        case TELNET_SE: printf("SE "); break;
        case TELNET_NOP: printf("NOP "); break;
        case TELNET_DM: printf("DM "); break;
        case TELNET_BRK: printf("BRK "); break;
        case TELNET_IP: printf("IP "); break;
        case TELNET_AO: printf("AO "); break;
        case TELNET_AYT: printf("AYT "); break;
        case TELNET_EC: printf("EC "); break;
        case TELNET_EL: printf("EL "); break;
        case TELNET_GA: printf("GA "); break;
        case TELNET_SB: printf("SB "); break;
        case TELNET_WILL: printf("WILL "); break;
        case TELNET_WONT: printf("WON'T "); break;
        case TELNET_DO: printf("DO "); break;
        case TELNET_DONT: printf("DON'T "); break;
        case TELNET_IAC: printf("IAC "); break;
        default: printf("Unknown (%u) ", command); break;
    }
}

void process_telnet_option(uint8_t option) {
    switch (option) {
        case TELNET_BINARY: printf("Binary Transmission "); break;
        case TELNET_ECHO: printf("Echo "); break;
        case TELNET_RECONNECT: printf("Reconnection "); break;
        case TELNET_SUPPRESS_GA: printf("Suppress Go Ahead "); break;
        case TELNET_APPROX_MSG_SIZE: printf("Approximate Message Size Negotiation "); break;
        case TELNET_STATUS: printf("Status "); break;
        case TELNET_TIMING_MARK: printf("Timing Mark "); break;
        case TELNET_RCTE: printf("Remote Controlled Transmission and Echo "); break;
        case TELNET_OUTPUT_LINE_WIDTH: printf("Output Line Width "); break;
        case TELNET_OUTPUT_PAGE_SIZE: printf("Output Page Size "); break;
        case TELNET_OUTPUT_CR_DISPOSITION: printf("Output Carriage-Return Disposition "); break;
        case TELNET_OUTPUT_HTS: printf("Output Horizontal Tab Stops "); break;
        case TELNET_OUTPUT_HTD: printf("Output Horizontal Tab Disposition "); break;
        case TELNET_OUTPUT_FFD: printf("Output Formfeed Disposition "); break;
        case TELNET_OUTPUT_VTS: printf("Output Vertical Tab Stops "); break;
        case TELNET_OUTPUT_VTD: printf("Output Vertical Tab Disposition "); break;
        case TELNET_OUTPUT_LFD: printf("Output Linefeed Disposition "); break;
        case TELNET_EXT_ASCII: printf("Extended ASCII "); break;
        case TELNET_LOGOUT: printf("Logout "); break;
        case TELNET_BYTE_MACRO: printf("Byte Macro "); break;
        case TELNET_DATA_ENTRY_TERM: printf("Data Entry Terminal "); break;
        case TELNET_SUPDUP: printf("SUPDUP "); break;
        case TELNET_SUPDUP_OUTPUT: printf("SUPDUP Output "); break;
        case TELNET_SEND_LOCATION: printf("Send Location "); break;
        case TELNET_TERMINAL_TYPE: printf("Terminal Type "); break;
        case TELNET_END_OF_RECORD: printf("End of Record "); break;
        case TELNET_TACACS_USER_ID: printf("TACACS User Identification "); break;
        case TELNET_OUTPUT_MARKING: printf("Output Marking "); break;
        case TELNET_TERM_LOC_NUMBER: printf("Terminal Location Number "); break;
        case TELNET_3270_REGIME: printf("Telnet 3270 Regime "); break;
        case TELNET_X3_PAD: printf("X.3 PAD "); break;
        case TELNET_WINDOW_SIZE: printf("Negotiate About Window Size "); break;
        case TELNET_TERM_SPEED: printf("Terminal Speed "); break;
        case TELNET_REMOTE_FLOW_CTRL: printf("Remote Flow Control "); break;
        case TELNET_LINEMODE: printf("Linemode "); break;
        case TELNET_X_DISPLAY_LOC: printf("X Display Location "); break;
        case TELNET_ENV_OPTION: printf("Environment Option "); break;
        case TELNET_AUTH_OPTION: printf("Authentication Option "); break;
        case TELNET_ENCRYPTION_OPTION: printf("Encryption Option "); break;
        case TELNET_NEW_ENV_OPTION: printf("New Environment Option "); break;
        default: printf("Unknown (%u) ", option); break;
    }
}


void parse_telnet(const u_char* packet, size_t offset){
    const u_char* telnet_header = (packet+offset);
    if(telnet_header[0] != TELNET_IAC){ // if he doesnt start with ff its a data packet
        printf("Data: ");
        parse_ascii(packet, offset);
        return;
    }
    size_t telnet_length = packet_size - offset; // Length of the telnet packet
    size_t current_position = 0;
    printf("\n");
    while (current_position < telnet_length) {
        
        if (telnet_header[current_position] == TELNET_IAC) { // We go from 0xff to 0xff
            if (current_position + 1 >= telnet_length) {
                printf("Incomplete Telnet command, stopping.\n");
                break;
            }

            uint8_t command = telnet_header[current_position + 1]; //  get the hexa of the command
            process_telnet_command(command);
            if (command == TELNET_SE){ // if its SE (only 2 octet) no option is needed
                current_position += 2;
                continue;
            }
            if (current_position + 1 >= telnet_length) {
                printf("Incomplete Telnet command, stopping.\n");
                break;
            }
            uint8_t option = telnet_header[current_position + 2]; // get the option
            process_telnet_option(option);
            printf("\n");
            current_position += 3; // move cursor : 0xff cmd option
        } else {
            // Ignore data
            current_position++;
        }
    }
}