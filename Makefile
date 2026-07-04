CC := gcc
CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -O2
LDLIBS := -lpcap
TARGET := pcap_http_sniffer

.PHONY: all clean

all: $(TARGET)

$(TARGET): pcap_http_sniffer.c packet_headers.h
	$(CC) $(CFLAGS) -o $@ pcap_http_sniffer.c $(LDLIBS)

clean:
	rm -f $(TARGET)
