#ifndef PACKET_HEADERS_H
#define PACKET_HEADERS_H

#include <stdint.h>

#define ETHERNET_ADDR_LEN 6
#define ETHERNET_HEADER_LEN 14
#define IPV4_MIN_HEADER_LEN 20
#define TCP_MIN_HEADER_LEN 20
#define ETHER_TYPE_IPV4 0x0800
#define IPV4_FRAGMENT_OFFSET_MASK 0x1fff

#pragma pack(push, 1)

struct ethernet_header {
    uint8_t destination[ETHERNET_ADDR_LEN];
    uint8_t source[ETHERNET_ADDR_LEN];
    uint16_t ether_type;
};

struct ipv4_header {
    uint8_t version_ihl;
    uint8_t type_of_service;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment_offset;
    uint8_t time_to_live;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t source_address;
    uint32_t destination_address;
};

struct tcp_header {
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t sequence_number;
    uint32_t acknowledgement_number;
    uint8_t data_offset_reserved;
    uint8_t flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
};

#pragma pack(pop)

#endif
