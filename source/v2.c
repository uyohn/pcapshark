// github: https://github.com/uyohn/PcapShark
// V2 - version for Winter Semester 2021/2022
// refactor of code from last year

#include <endian.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <sys/types.h>
#include <string.h>

#include "pcap-shark.h"



// -----------------------
// GLOBALS

int pkt_order = 1; 	// frame counter
pcap_t *fp; 		// pointer to capfile file

protocol *ethernetII_protocols,
		 *eth802_3_protocols,
		 *ipv4_protocols,
		 *tcp_protocols,
		 *udp_protocols;

ipv4_stats src_ips[1000000], dst_ips[1000000];
unsigned int *src_ips_count, *dst_ips_count;

node *start = NULL;

// FUNCTION DEFINITIONS
void print_ipv4_stats();

// -----------------------
// FUNCTION DEFINITIONS

void packetHandler ();




int main (int argc, char **argv) {

	// --------------------
	// SET-UP

	// open cap file
	if (argv[1] == NULL) {
		printf("Supply a pcap file path!\nExiting...");
		exit(FILE_OPEN_ERR);
	}

	pcap_t *handle = open_capfile(argv[1]);

	if (handle == NULL)
		exit(FILE_OPEN_ERR);

	fp = handle;


	// load protocols from files
	ethernetII_protocols = load_protocols("source/ethernetII_protocols.txt");
	eth802_3_protocols = load_protocols("source/802-3_protocols.txt");
	ipv4_protocols = load_protocols("source/ipv4_protocols.txt");
	tcp_protocols = load_protocols("source/tcp_protocols.txt");
	udp_protocols = load_protocols("source/udp_protocols.txt");

	// prepare statistics
	//TODO
	src_ips_count = malloc(sizeof(unsigned int));
	dst_ips_count = malloc(sizeof(unsigned int));
	*src_ips_count = 0;
	*dst_ips_count = 0;


	// --------------------
	// MAIN

	// start packet processing loop
	if (pcap_loop(handle, 0, packetHandler, NULL) < 0) {
		printf("pcap_loop() failed: %s\n", pcap_geterr(handle) );
		exit(LOOP_ERR);
	}

	// print ipv4 stats
	print_ipv4_stats();


	// --------------------
	// CLEAN UP

	free_protocols(ethernetII_protocols);
	free_protocols(eth802_3_protocols);
	free_protocols(ipv4_protocols);

	free(src_ips_count);
	free(dst_ips_count);

	return 0;
}

void packetHandler (u_char *serData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {

	// TODO: don't alloc memory for each frame one-by-one
	pkt *current = (pkt *) malloc(sizeof(pkt));

	// TODO: maybe cleanup this?
	current->start 		= packet;
	current->order 		= pkt_order++;
	current->len 		= pkthdr->len;

	// parse the frame layer-by-layer
	parse_link_layer(current);
	print_pkt(current);


	if ( current->eth_type >= 1500) {
		// ETH II frame
		parse_ethii(current, src_ips, dst_ips, src_ips_count, dst_ips_count);


	} else if ( current->ssap == 0xFF ) {
		// 802.3 RAW
		
	} else if ( current->ssap == 0xAA ) {
		// 802.3 LLC + SNAP

		// update eth_type to reflect velue from SNAP header
		//*current->eth_type = 0xAA;

		parse_ieee_snap(current);
	
	} else {
		// 802.3 LLC

	}

	// CLEANUP
	free(current);
}



void print_ipv4_stats() {
	printf("\n\nSource IPv4 Addresses:\n");
	int max = 0;
	for (int i = 0; i < *src_ips_count; i++) {
		printf("%d * %d.%d.%d.%d\n",
				src_ips[i].count,
				*((uint8_t *)(&src_ips[i].ip) + 0),
				*((uint8_t *)(&src_ips[i].ip) + 1),
				*((uint8_t *)(&src_ips[i].ip) + 2),
				*((uint8_t *)(&src_ips[i].ip) + 3));

		if (src_ips[max].count < src_ips[i].count)
			max = i;
	}

	printf("max packets sent: %d by %d.%d.%d.%d\n",
		src_ips[max].count,
		*((uint8_t *)(&src_ips[max].ip) + 0),
		*((uint8_t *)(&src_ips[max].ip) + 1),
		*((uint8_t *)(&src_ips[max].ip) + 2),
		*((uint8_t *)(&src_ips[max].ip) + 3));

	max = 0;
	printf("\n\nDestination IPv4 Addresses:\n");
	for (int i = 0; i < *dst_ips_count; i++) {
		printf("%d * %d.%d.%d.%d\n",
				dst_ips[i].count,
				*((uint8_t *)(&dst_ips[i].ip) + 0),
				*((uint8_t *)(&dst_ips[i].ip) + 1),
				*((uint8_t *)(&dst_ips[i].ip) + 2),
				*((uint8_t *)(&dst_ips[i].ip) + 3));

		if (dst_ips[max].count < dst_ips[i].count)
			max = i;
	}

	printf("max packets received: %d by %d.%d.%d.%d\n",
		dst_ips[max].count,
		*((uint8_t *)(&dst_ips[max].ip) + 0),
		*((uint8_t *)(&dst_ips[max].ip) + 1),
		*((uint8_t *)(&dst_ips[max].ip) + 2),
		*((uint8_t *)(&dst_ips[max].ip) + 3));
}









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
	fclose(source);
	return protocols;
}

// TODO: free names of protocols first (at least 2MB leak)
void free_protocols (protocol *protocols) {
	free(protocols);
}

// prints info about a packet in a nice way
void print_pkt (pkt *pkt) {
	printf("\n\n\nFrame %d: ", pkt->order);

	printf("%d bytes on wire (%d bits), ", pkt->real_len, pkt->real_len * 8);
	printf("%d bytes captured (%d bits), ", pkt->len, pkt->len * 8);

	printf("\n");


	print_eth_name(pkt);

	printf("Src mac: ");
	print_mac(pkt->src_mac);

	printf(", Dst mac: ");
	print_mac(pkt->dst_mac);
	
	printf("\n");

	printf("\n");
	hexdump(pkt->dst_mac, pkt->len);

	printf("\n");
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

void print_eth_name (pkt *pkt) {
	// PRINT FRAME TYPE

	// The max size of eth frame is 1500 bytes,
	// so if > 1500, it has to be ETH II
	if ( pkt->eth_type >= 1500) {
		
		printf("Ethernet II frame");
	
	} else {
		// find the right protocol from file
		FILE *eth_types = fopen("source/eth_types.txt", "r");
		int eth_num = 0;

		char c;

		while(1) {
			fscanf(eth_types, "%x", &eth_num);
			getc(eth_types); // skip one char  (space)


			if (eth_num == pkt->ssap ) { // 802.3 Novell RAW / LLC + SNAP

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

	pkt->eth_type	= be16toh(*(uint16_t *) (pkt->start + 2 * MAC_SIZE));
	pkt->log_header	= (uint8_t *) (pkt->start + 2 * MAC_SIZE + 2);
	pkt->ssap		= *((uint8_t *) (pkt->start + 2 * MAC_SIZE + 2));

}

void parse_ieee_snap (pkt *pkt) {
	// ETH TYPE AT LOG HEADER + 6B - ETH II COMPATIBLE
	if (be16toh(*(uint16_t *)(pkt->log_header + 6)) == 0x0800) {
		printf("SNAP WITH IP\n");
	}
}


void parse_ethii (pkt *pkt, ipv4_stats *src_ips, ipv4_stats *dst_ips, unsigned int *src_ips_count, unsigned int *dst_ips_count) {
	if (pkt->eth_type == 0x0800) {
		// ipv4
		printf("Internet Protocol version 4 (IPv4)\n");

		// parse data
		ip_header header;
		header.ip_header_start = (uint8_t *) pkt->log_header;
		// in ethII packets log header points to first B of data

		header.ttl = (uint8_t *)(header.ip_header_start + 8);
		header.protocol = (uint8_t *)(header.ip_header_start + 9);
		header.src_addr = (uint32_t *)(header.ip_header_start + 12);
		header.dst_addr = (uint32_t *)(header.ip_header_start + 16);

		// stats
		// TODO: THIS IS UTTER SHIT
		// SRC
		if (*src_ips_count == 0) {
			src_ips[*src_ips_count].count = 1;

			if (*src_ips_count < 99) {
				src_ips[(*src_ips_count)++].ip = (*header.src_addr);
			}
		} else {
			int i;
			for (i = 0; i < *src_ips_count; i++)
				if (src_ips[i].ip == (*header.src_addr))
					break;

			if (i == *src_ips_count) {
				if (src_ips[i].ip == (*header.src_addr))
					src_ips[i].count += 1;
				else {
					src_ips[*src_ips_count].count = 1;

					if (*src_ips_count < 99) {
						src_ips[(*src_ips_count)++].ip = (*header.src_addr);
					}
				}
			} else {
				src_ips[i].count += 1;
			}
		}
		
		// DST
		if (*dst_ips_count == 0) {
			dst_ips[*dst_ips_count].count = 1;

			if (*dst_ips_count < 99)
				dst_ips[(*dst_ips_count)++].ip = (*header.dst_addr);
		} else {
			int i;
			for (i = 0; i < *dst_ips_count; i++)
				if (dst_ips[i].ip == (*header.dst_addr))
					break;

			if (i == *dst_ips_count) {
				if (dst_ips[i].ip == (*header.dst_addr))
					dst_ips[i].count += 1;
				else {
					dst_ips[*dst_ips_count].count = 1;

					if (*dst_ips_count < 99)
						dst_ips[(*dst_ips_count)++].ip = (*header.dst_addr);
				}
			} else {
				dst_ips[i].count += 1;
			}
		}
		

		printf("ttl: %d, ", *header.ttl);

		print_ipv4_subprotocol(ipv4_protocols, *((uint8_t *)header.protocol));

		// print tcp protocol
		uint8_t ipv4_header_len = *((uint8_t *)(pkt->log_header)) & 0xf;
		ipv4_header_len *= 2; // 32-bit words
		uint16_t dst_port = be16toh(*((uint16_t *)(pkt->log_header) + ipv4_header_len + 1 ));
		uint16_t src_port = be16toh(*((uint16_t *)(pkt->log_header) + ipv4_header_len ));

		printf(": ");
		if ( *((uint8_t *)header.protocol) == 0x06)
			print_tcp_protocol(tcp_protocols, dst_port);
		else if ( *((uint8_t *)header.protocol) == 0x11)
			print_udp_protocol(udp_protocols, dst_port);

		printf("\nSrc port: %d, Dst port: %d\n", src_port, dst_port);

		printf("Src ip addr: %d.%d.%d.%d, Dst ip addr: %d.%d.%d.%d",
				*((uint8_t *)header.src_addr + 0),
				*((uint8_t *)header.src_addr + 1),
				*((uint8_t *)header.src_addr + 2),
				*((uint8_t *)header.src_addr + 3),
				*((uint8_t *)header.dst_addr + 0),
				*((uint8_t *)header.dst_addr + 1),
				*((uint8_t *)header.dst_addr + 2),
				*((uint8_t *)header.dst_addr + 3));


		// stats
	} else {
		// just print subprotocol
		print_trans_protocol(pkt);
	}
}

void print_trans_protocol (pkt *pkt) {
	int i = 0;
	while (1) {
		if (ethernetII_protocols[i].n < pkt->eth_type) {
			i++;
		} else {
			if (ethernetII_protocols[i].n <= pkt->eth_type &&
				ethernetII_protocols[i].nstop != -1 &&
				ethernetII_protocols[i].nstop >= pkt->eth_type) {
					printf("%s", ethernetII_protocols[i].name);
					return;
			} else if (ethernetII_protocols[i].n <= pkt->eth_type) {
				printf("%s", ethernetII_protocols[i].name);
				return;
			} else {
				printf("subprotocol unnamed");
				return;
			};
		}

		// safestop
		if (i > 0xFFFF)
			break;
	}
}


void print_ipv4_subprotocol (protocol *protocols, uint8_t n) {
	int i = 0;
	while (1) {
		if (protocols[i].n < n) {
			i++;
		} else {
			if (protocols[i].n <= n &&
				protocols[i].nstop != -1 &&
				protocols[i].nstop >= n) {
					printf("%s", protocols[i].name);
					return;
			} else if (protocols[i].n <= n) {
				printf("%s", protocols[i].name);
				return;
			} else {
				printf("subprotocol unnamed");
				return;
			};
		}

		// safestop
		if (i > 0xFF)
			break;
	}
}

void print_tcp_protocol(protocol *protocols, uint16_t port) {
	int i = 0;
	while (protocols[i].n != port) {
		i++;
		if (i > 0xFF) {
			printf("subprotocol not found");
			return;
		}
	}

	printf("%s", protocols[i].name);
}

void print_udp_protocol(protocol *protocols, uint16_t port) {
	int i = 0;
	while (protocols[i].n != port) {
		i++;
		if (i > 0xFF) {
			printf("subprotocol not found");
			return;
		}
	}

	printf("%s", protocols[i].name);
}

