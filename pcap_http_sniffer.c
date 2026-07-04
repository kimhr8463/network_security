#define _DEFAULT_SOURCE

#include <arpa/inet.h>
#include <ctype.h>
#include <getopt.h>
#include <pcap.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "packet_headers.h"

static pcap_t *capture_handle;
static unsigned long packet_number;

static void print_mac_address(const uint8_t address[ETHERNET_ADDR_LEN])
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           address[0], address[1], address[2],
           address[3], address[4], address[5]);
}

static size_t minimum_size(size_t left, size_t right)
{
    return left < right ? left : right;
}

static int starts_with(const uint8_t *data, size_t length, const char *prefix)
{
    size_t prefix_length = strlen(prefix);
    return length >= prefix_length &&
           memcmp(data, prefix, prefix_length) == 0;
}

static int is_likely_http(const uint8_t *payload, size_t length,
                          uint16_t source_port, uint16_t destination_port)
{
    static const char *const start_tokens[] = {
        "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ",
        "PATCH ", "CONNECT ", "TRACE ", "HTTP/"
    };
    static const uint16_t common_http_ports[] = {80, 8000, 8080, 8888};
    size_t index;

    for (index = 0;
         index < sizeof(start_tokens) / sizeof(start_tokens[0]);
         ++index) {
        if (starts_with(payload, length, start_tokens[index])) {
            return 1;
        }
    }

    for (index = 0;
         index < sizeof(common_http_ports) / sizeof(common_http_ports[0]);
         ++index) {
        if (source_port == common_http_ports[index] ||
            destination_port == common_http_ports[index]) {
            return 1;
        }
    }

    return 0;
}

static void print_http_message(const uint8_t *payload, size_t length)
{
    size_t index;

    puts("HTTP Message");
    puts("------------");
    for (index = 0; index < length; ++index) {
        uint8_t byte = payload[index];

        if (byte == '\r' || byte == '\n' || byte == '\t') {
            putchar((int)byte);
        } else if (isprint((unsigned char)byte)) {
            putchar((int)byte);
        } else {
            putchar('.');
        }
    }
    if (length == 0 || payload[length - 1] != '\n') {
        putchar('\n');
    }
    puts("------------");
}

static void process_packet(u_char *user,
                           const struct pcap_pkthdr *capture_header,
                           const u_char *packet)
{
    const struct ethernet_header *ethernet;
    const struct ipv4_header *ip;
    const struct tcp_header *tcp;
    const uint8_t *payload;
    char source_ip[INET_ADDRSTRLEN];
    char destination_ip[INET_ADDRSTRLEN];
    uint16_t ip_total_length;
    uint16_t fragment_information;
    uint16_t source_port;
    uint16_t destination_port;
    size_t ip_header_length;
    size_t tcp_header_length;
    size_t tcp_offset;
    size_t payload_offset;
    size_t wire_payload_length;
    size_t captured_payload_length;

    (void)user;

    if (capture_header->caplen < ETHERNET_HEADER_LEN) {
        fprintf(stderr, "[skip] truncated Ethernet header\n");
        return;
    }

    ethernet = (const struct ethernet_header *)packet;
    if (ntohs(ethernet->ether_type) != ETHER_TYPE_IPV4) {
        return;
    }

    if (capture_header->caplen <
        ETHERNET_HEADER_LEN + IPV4_MIN_HEADER_LEN) {
        fprintf(stderr, "[skip] truncated IPv4 header\n");
        return;
    }

    ip = (const struct ipv4_header *)(packet + ETHERNET_HEADER_LEN);
    if ((ip->version_ihl >> 4) != 4) {
        return;
    }

    ip_header_length = (size_t)(ip->version_ihl & 0x0f) * 4U;
    if (ip_header_length < IPV4_MIN_HEADER_LEN ||
        capture_header->caplen < ETHERNET_HEADER_LEN + ip_header_length) {
        fprintf(stderr, "[skip] invalid or truncated IPv4 header\n");
        return;
    }

    if (ip->protocol != IPPROTO_TCP) {
        return;
    }

    ip_total_length = ntohs(ip->total_length);
    if (ip_total_length < ip_header_length + TCP_MIN_HEADER_LEN) {
        fprintf(stderr, "[skip] invalid IPv4 total length\n");
        return;
    }

    fragment_information = ntohs(ip->flags_fragment_offset);
    if ((fragment_information & IPV4_FRAGMENT_OFFSET_MASK) != 0) {
        fprintf(stderr, "[skip] non-initial IPv4 fragment\n");
        return;
    }

    tcp_offset = ETHERNET_HEADER_LEN + ip_header_length;
    if (capture_header->caplen < tcp_offset + TCP_MIN_HEADER_LEN) {
        fprintf(stderr, "[skip] truncated TCP header\n");
        return;
    }

    tcp = (const struct tcp_header *)(packet + tcp_offset);
    tcp_header_length = (size_t)(tcp->data_offset_reserved >> 4) * 4U;
    if (tcp_header_length < TCP_MIN_HEADER_LEN ||
        capture_header->caplen < tcp_offset + tcp_header_length ||
        ip_total_length < ip_header_length + tcp_header_length) {
        fprintf(stderr, "[skip] invalid or truncated TCP header\n");
        return;
    }

    if (inet_ntop(AF_INET, &ip->source_address,
                  source_ip, sizeof(source_ip)) == NULL ||
        inet_ntop(AF_INET, &ip->destination_address,
                  destination_ip, sizeof(destination_ip)) == NULL) {
        perror("inet_ntop");
        return;
    }

    source_port = ntohs(tcp->source_port);
    destination_port = ntohs(tcp->destination_port);
    payload_offset = tcp_offset + tcp_header_length;
    wire_payload_length =
        (size_t)ip_total_length - ip_header_length - tcp_header_length;
    captured_payload_length = minimum_size(
        wire_payload_length,
        (size_t)capture_header->caplen - payload_offset);
    payload = packet + payload_offset;

    ++packet_number;
    printf("\n========== TCP packet %lu ==========\n", packet_number);
    printf("Captured length : %u bytes\n", capture_header->caplen);
    printf("Ethernet source : ");
    print_mac_address(ethernet->source);
    putchar('\n');
    printf("Ethernet dest.  : ");
    print_mac_address(ethernet->destination);
    putchar('\n');
    printf("IPv4 source     : %s\n", source_ip);
    printf("IPv4 dest.      : %s\n", destination_ip);
    printf("IP header length: %zu bytes\n", ip_header_length);
    printf("TCP source port : %u\n", source_port);
    printf("TCP dest. port  : %u\n", destination_port);
    printf("TCP header len. : %zu bytes\n", tcp_header_length);
    printf("Payload length  : %zu bytes", captured_payload_length);
    if (captured_payload_length < wire_payload_length) {
        printf(" (truncated from %zu bytes)", wire_payload_length);
    }
    putchar('\n');

    if (captured_payload_length == 0) {
        puts("HTTP Message    : [no TCP payload]");
    } else if (is_likely_http(payload, captured_payload_length,
                              source_port, destination_port)) {
        print_http_message(payload, captured_payload_length);
    } else {
        puts("HTTP Message    : [payload is not recognized as HTTP]");
    }
}

static void stop_capture(int signal_number)
{
    (void)signal_number;
    if (capture_handle != NULL) {
        pcap_breakloop(capture_handle);
    }
}

static void print_usage(const char *program)
{
    fprintf(stderr,
            "Usage:\n"
            "  sudo %s -i <interface> [-c packet_count]\n"
            "  %s -r <capture.pcap> [-c packet_count]\n",
            program, program);
}

int main(int argc, char *argv[])
{
    const char *interface_name = NULL;
    const char *pcap_file = NULL;
    int packet_count = -1;
    int option;
    char error_buffer[PCAP_ERRBUF_SIZE];
    struct bpf_program filter_program;
    const char filter_expression[] = "tcp";
    int loop_result;

    while ((option = getopt(argc, argv, "i:r:c:h")) != -1) {
        switch (option) {
        case 'i':
            interface_name = optarg;
            break;
        case 'r':
            pcap_file = optarg;
            break;
        case 'c':
            packet_count = atoi(optarg);
            if (packet_count <= 0) {
                fprintf(stderr, "packet_count must be a positive integer\n");
                return EXIT_FAILURE;
            }
            break;
        case 'h':
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        default:
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    if ((interface_name == NULL) == (pcap_file == NULL)) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (interface_name != NULL) {
        capture_handle = pcap_open_live(
            interface_name, 65535, 1, 1000, error_buffer);
    } else {
        capture_handle = pcap_open_offline(pcap_file, error_buffer);
    }

    if (capture_handle == NULL) {
        fprintf(stderr, "pcap open failed: %s\n", error_buffer);
        return EXIT_FAILURE;
    }

    if (pcap_datalink(capture_handle) != DLT_EN10MB) {
        fprintf(stderr,
                "unsupported data-link type: Ethernet capture is required\n");
        pcap_close(capture_handle);
        return EXIT_FAILURE;
    }

    if (pcap_compile(capture_handle, &filter_program,
                     filter_expression, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "pcap_compile failed: %s\n",
                pcap_geterr(capture_handle));
        pcap_close(capture_handle);
        return EXIT_FAILURE;
    }

    if (pcap_setfilter(capture_handle, &filter_program) == -1) {
        fprintf(stderr, "pcap_setfilter failed: %s\n",
                pcap_geterr(capture_handle));
        pcap_freecode(&filter_program);
        pcap_close(capture_handle);
        return EXIT_FAILURE;
    }
    pcap_freecode(&filter_program);

    signal(SIGINT, stop_capture);
    printf("Capture source: %s\n",
           interface_name != NULL ? interface_name : pcap_file);
    printf("BPF filter    : %s\n", filter_expression);
    puts("Press Ctrl+C to stop a live capture.");

    loop_result =
        pcap_loop(capture_handle, packet_count, process_packet, NULL);
    if (loop_result == -1) {
        fprintf(stderr, "pcap_loop failed: %s\n",
                pcap_geterr(capture_handle));
        pcap_close(capture_handle);
        return EXIT_FAILURE;
    }

    pcap_close(capture_handle);
    capture_handle = NULL;
    printf("\nCapture finished. Parsed TCP packets: %lu\n", packet_number);
    return EXIT_SUCCESS;
}
