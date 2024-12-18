#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "../global_value.h"

// Telnet Command
#define TELNET_SE 240 // Subnegotiation end
#define TELNET_NOP 241 // No operation
#define TELNET_DM 242 // Data Mark
#define TELNET_BRK 243 // Break
#define TELNET_IP 244 // Interrupt Process
#define TELNET_AO 245 // Abort Output
#define TELNET_AYT 246 // Are You There?
#define TELNET_EC 247 // Erase Character
#define TELNET_EL 248 // Erase Line
#define TELNET_GA 249 // Go Ahead
#define TELNET_SB 250 // Subnegotiation begin
#define TELNET_WILL 251 // WILL
#define TELNET_WONT 252 // WON'T
#define TELNET_DO 253 // DO
#define TELNET_DONT 254 // DON'T
#define TELNET_IAC 255 // Interpret As Command

// Telnet Options
#define TELNET_BINARY 0 // Binary Transmission
#define TELNET_ECHO 1 // Echo
#define TELNET_RECONNECT 2 // Reconnection
#define TELNET_SUPPRESS_GA 3 // Suppress Go Ahead
#define TELNET_APPROX_MSG_SIZE 4 // Approx Message Size Negotiation
#define TELNET_STATUS 5 // Status
#define TELNET_TIMING_MARK 6 // Timing Mark
#define TELNET_RCTE 7 // Remote Controlled Transmission and Echo
#define TELNET_OUTPUT_LINE_WIDTH 8 // Output Line Width
#define TELNET_OUTPUT_PAGE_SIZE 9 // Output Page Size
#define TELNET_OUTPUT_CR_DISPOSITION 10 // Output Carriage-Return Disposition
#define TELNET_OUTPUT_HTS 11 // Output Horizontal Tab Stops
#define TELNET_OUTPUT_HTD 12 // Output Horizontal Tab Disposition
#define TELNET_OUTPUT_FFD 13 // Output Formfeed Disposition
#define TELNET_OUTPUT_VTS 14 // Output Vertical Tabstops
#define TELNET_OUTPUT_VTD 15 // Output Vertical Tab Disposition
#define TELNET_OUTPUT_LFD 16 // Output Linefeed Disposition
#define TELNET_EXT_ASCII 17 // Extended ASCII
#define TELNET_LOGOUT 18 // Logout
#define TELNET_BYTE_MACRO 19 // Byte Macro
#define TELNET_DATA_ENTRY_TERM 20 // Data Entry Terminal
#define TELNET_SUPDUP 21 // SUPDUP
#define TELNET_SUPDUP_OUTPUT 22 // SUPDUP Output
#define TELNET_SEND_LOCATION 23 // Send Location
#define TELNET_TERMINAL_TYPE 24 // Terminal Type
#define TELNET_END_OF_RECORD 25 // End of Record
#define TELNET_TACACS_USER_ID 26 // TACACS User Identification
#define TELNET_OUTPUT_MARKING 27 // Output Marking
#define TELNET_TERM_LOC_NUMBER 28 // Terminal Location Number
#define TELNET_3270_REGIME 29 // Telnet 3270 Regime
#define TELNET_X3_PAD 30 // X.3 PAD
#define TELNET_WINDOW_SIZE 31 // Negotiate About Window Size
#define TELNET_TERM_SPEED 32 // Terminal Speed
#define TELNET_REMOTE_FLOW_CTRL 33 // Remote Flow Control
#define TELNET_LINEMODE 34 // Linemode
#define TELNET_X_DISPLAY_LOC 35 // X Display Location
#define TELNET_ENV_OPTION 36 // Environment Option
#define TELNET_AUTH_OPTION 37 // Authentication Option
#define TELNET_ENCRYPTION_OPTION 38 // Encryption Option
#define TELNET_NEW_ENV_OPTION 39 // New Environment Option



void parse_telnet(const u_char* packet, size_t offset);