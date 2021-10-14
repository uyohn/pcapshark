#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>

#include "pcap-shark.h"


pcap_t *open_capfile (char *filename) {
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t *handle = pcap_open_offline(filename, errbuf);


	if (handle == NULL) {
		printf("error while opening pcap - %s\n", errbuf);
		exit(FILE_OPEN_ERR);
	}

	return handle;
}

// prints info about a packet in a nice way
void print_pkt (pkt pkt) {
	printf("Frame %d: ", pkt.order);

	printf("%d bytes on wire (%d bits), ", pkt.len + 4, (pkt.len + 4) * 8);
	printf("%d bytes captured (%d bits), ", pkt.len, pkt.len * 8);

	printf("\n");


	// ----------------------------------------------------------------------------------
	// TODO: REFACTOR THIS CODE

	// FIND FRAME FORMAT

	// The max size of eth frame is 1500 bytes,
	// so if > 1500, it has to be eth II
	if ( be16toh(*pkt.eth_type) >= 1500) {
		
		printf("Ethernet II frame");
	
	} else {
		// find the right protocol from file
		FILE *eth_types = fopen("source/eth_types.txt", "r");
		int eth_num = 0;

		char c;

		while(1) {
			fscanf(eth_types, "%d", &eth_num);
			getc(eth_types); // skip one char  (space)

			if (eth_num == be16toh(*pkt.log_header)) { // 802.3 Novell RAW / LLC + SNAP
				
				for (int i = 0; (c = getc(eth_types)) != '\n'; i++)
					printf("%c", c);

				
				break;

			} else if (eth_num == 0) { // 802.3 LLC
				
				for (int i = 0; (c = getc(eth_types)) != '\n'; i++)
					printf("%c", c);

				break;

			} else
                while ( (c = getc(eth_types)) != '\n' );
		}
	}

	// /TODO
	// ----------------------------------------------------------------------------------

	printf("\n");

	printf("Src mac: ");
	print_mac(pkt.src_mac);

	printf(", Dst mac: ");
	print_mac(pkt.dst_mac);
	
	printf("\n");

	printf("\n");
	hexdump(pkt.dst_mac, pkt.len);

	printf("\n\n\n\n");
}

// will print the binary data in nice way
void hexdump (uint8_t *data, unsigned int n) {
	// lines
	for (int line = 0; line <= n; line += CHARS_PER_LINE) {
		// line number
		printf("\033[36m");
		printf("%04x", line);
		printf("\033[0m");
		printf("   ");


		// print hexadecimal blocks
		for (int block = 0; block < CHARS_PER_LINE; block += CHARS_PER_BLOCK) {
			int offset;
			
			for (int word = 0; word < CHARS_PER_BLOCK; word++)
				if ( (offset = line + block + word) < n) {
					printf("\033[90m");
					printf("%02x ", *((uint8_t *)(data + offset)) );
					printf("\033[0m");
				} else
					printf("   ");

			printf("  ");
		}

		// print ASCII interpretation
		printf("    ");
		for (int block = 0; block < CHARS_PER_LINE; block += CHARS_PER_BLOCK) {
			int offset;

			for (int word = 0; word < CHARS_PER_BLOCK; word++) {
				if ( (offset = line + block + word) < n) {
					char c = *((uint8_t *)(data + offset));
					if ( c >= '!' && c <= '~' ) {
						printf("\033[96m");
						printf("%c", *((uint8_t *)(data + offset)) );
						printf("\033[0m");
					} else {
						printf("\033[0;90m");
						printf(".");
						printf("\033[0m");
					}
				} else {
					printf(" ");
				}
			}
		}
		printf("\n");
	}
}

// will print mac address in a nice way - i.e. 00:ab:18:cd:a8:9d
void print_mac (uint8_t *start) {
	int i = 0;

	for (; i < MAC_SIZE - 1; i++)
		printf("%02x:", *(start + i));

	printf("%02x", *(start + i));
}