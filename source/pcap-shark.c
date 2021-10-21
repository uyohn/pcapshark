#include <endian.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <string.h>

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

// load protocols from file
protocol *load_protocols(char *srcfile) {
	// file with protocols
	// 0000-ffff#name of protocol in human readable form\n
	FILE *source = fopen(srcfile, "r");

	// prepare protocols array
	protocol *protocols = malloc(500 * sizeof(protocol));
	int pi = 0;

	char c;
	char *buffer = malloc(300 * sizeof(char));

	// while there are more lines load first number
	while( fscanf(source, "%x", &protocols[pi].n ) != EOF) {
		// if there is - after first num, it is a range, so load second num as well
		if ((c = fgetc(source)) == '-'){
			fscanf(source, "%x", &protocols[pi].nstop);
			c = fgetc(source); // load next char
		} else
			protocols[pi].nstop = -1; // if it is not a range, set nstop to -1
		
		// if next char is #, load protocol name into buffer
		if (c == '#') {
			int i = 0;

			// load chars into buffer until \n
			while((c = fgetc(source)) != '\n')
				buffer[i++] = c;

			// terminate the string
			buffer[i++] = '\0';

			// alloc space for protocol name
			protocols[pi].name = malloc(i * sizeof(char));
			// copy the name
			strcpy(protocols[pi].name, buffer);
		}

		// increment protocol i
		pi++;
	}

	free(buffer);
	return protocols;
}

// TODO: free names of protocols first (at least 2MB leak)
void free_protocols (protocol *protocols) {
	free(protocols);
}

// prints info about a packet in a nice way
void print_pkt (pkt pkt) {
	printf("Frame %d: ", pkt.order);

	printf("%d bytes on wire (%d bits), ", pkt.real_len, pkt.real_len * 8);
	printf("%d bytes captured (%d bits), ", pkt.len, pkt.len * 8);

	printf("\n");


	print_eth_name(pkt);

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

void print_eth_name (pkt pkt) {
	// PRINT FRAME TYPE

	// The max size of eth frame is 1500 bytes,
	// so if > 1500, it has to be ETH II
	if ( *pkt.eth_type >= 1500) {
		
		printf("Ethernet II frame");
	
	} else {
		// find the right protocol from file
		FILE *eth_types = fopen("source/eth_types.txt", "r");
		int eth_num = 0;

		char c;

		while(1) {
			fscanf(eth_types, "%x", &eth_num);
			getc(eth_types); // skip one char  (space)

			if (eth_num == *pkt.eth_type) { // 802.3 Novell RAW / LLC + SNAP
				
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

	printf("\n");
}


// parse different kinds of packets
void parse_link_layer (pkt *pkt) {

	pkt->real_len 	= pkt->len + 4;

	pkt->dst_mac 	= (uint8_t *) (pkt->start);
	pkt->src_mac 	= (uint8_t *) (pkt->start + MAC_SIZE);

	pkt->eth_type	= (uint16_t *) (pkt->start + 2 * MAC_SIZE);
	pkt->log_header	= (uint8_t *) (pkt->start + 2 * MAC_SIZE + 2);

}

void parse_ieee_snap (pkt *pkt) {
	// ETH TYPE AT LOG HEADER + 6B - ETH II COMPATIBLE
	if (be16toh(*(uint16_t *)(pkt->log_header + 6)) == 0x0800) {
		printf("SNAP WITH IP\n");
	}
}


void parse_ethii (pkt *pkt) {
	if (be16toh(*pkt->eth_type) == 0x0800) {
		// ipv4

		// parse data

			// if TCP / UDP parse again

		// stats
	} else {
		// just print subprotocol
	}
}
