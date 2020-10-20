// github: https://github.com/uyohn/PcapShark

#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <endian.h>
#include <string.h>
#include <sys/types.h>


// ####################
//   CONSTANTS
// ####################

#define MAC_SIZE 6
#define ETH_TYPE_SIZE 2

#define CHARS_PER_LINE 32
#define CHARS_PER_BLOCK 8


// ####################
//   STRUCTS
// ####################

typedef struct pkt {
	// meta
	int order;
	int len;
	int real_len;
	char *eth_type_string;

	// pointers to data
	uint8_t *dst_mac;
	uint8_t *src_mac;
	uint16_t *eth_type;
	uint16_t *log_header;
} pkt;

typedef struct protocol {
	int n;
	int nstop;
	char *name;
} protocol;

typedef struct node {
	uint32_t node_ip;
	unsigned int nreceived;
	struct node *next;
} node;

typedef struct ip_header {
	uint8_t *ip_header_start;
	uint8_t *ttl;
	uint8_t *protocol;
	uint32_t *src_addr;
	uint32_t *dst_addr;
} ip_header;

typedef struct ipv4_stats {
	uint32_t ip;
	unsigned int count;
} ipv4_stats;

// #################
//   GLOBALS
// #################

int frame_no = 1;

protocol *ethernetII_protocols, *eth802_3_protocols, *ipv4_protocols;

ipv4_stats src_ips[100], dst_ips[100];
unsigned int *src_ips_count, *dst_ips_count;

node *start = NULL;


// ####################
//   DEFINITIONS
// ####################

pcap_t *open_capfile (char *filename);
void print_pkt       (pkt packet);
void packetHandler   (u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void print_mac       (uint8_t *start);
void hexdump         (uint8_t *data, unsigned int n);
void print_ethertype (u_int16_t *eth_type, u_int16_t *log_header);

protocol *load_protocols(char *srcfile);
void print_ethernetII_subprotocol(protocol *protocols, uint16_t eth_type);
void print_802_3_subprotocol (protocol *protocols, uint8_t LSAP);
void print_ipv4_subprotocol (protocol *protocols, uint8_t n);
void free_protocols(protocol *protocols);
void print_ipv4_stats();



// ####################
//   MAIN
// ####################

int main (int argc, char **argv) {
	// open capture
	if (argv[1] == NULL) {
		printf("supply pcap file path\n");
		return -1;
	}

	pcap_t *handle = open_capfile(argv[1]);

	if (handle == NULL)
		return -1;

	// load subprotocols
	ethernetII_protocols = load_protocols("source/ethernetII_protocols.txt");
	eth802_3_protocols = load_protocols("source/802-3_protocols.txt");
	ipv4_protocols = load_protocols("source/ipv4_protocols.txt");

	// prepare statistics
	//TODO
	src_ips_count = malloc(sizeof(unsigned int));
	dst_ips_count = malloc(sizeof(unsigned int));
	*src_ips_count = *dst_ips_count = 0;
	

	// start packet processing loop
	if ( pcap_loop(handle, 0, packetHandler, NULL) < 0 ) {
		printf( "pcap_loop() failed: %s\n", pcap_geterr(handle) );
		return -2;
	}

	// print ipv4 stats
	print_ipv4_stats();


	// cleanup
	free_protocols(ethernetII_protocols);
	free_protocols(eth802_3_protocols);
	free_protocols(ipv4_protocols);

	free(src_ips_count);
	free(dst_ips_count);

	return 0;
}


// ####################
//   PACKET HANDLER
// ####################

void packetHandler (u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	
	// parse frame into pkt struct
	
	pkt current;

	current.order      = frame_no++;
	current.len        = pkthdr->len;
	current.dst_mac    = (uint8_t *)  (packet);
	current.src_mac    = (uint8_t *)  (packet + MAC_SIZE);
	current.eth_type   = (uint16_t *) (packet + 2 * MAC_SIZE);
	current.log_header = (uint16_t *) (packet + 2 * MAC_SIZE + 2);
	
	
	// print packet info
	print_pkt(current);
}


// #####################
//   UTILITY FUNCTIONS
// #####################

pcap_t *open_capfile(char *filename) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_offline(filename, errbuf);

	if (handle == NULL)
		printf("Error while opening pcap -  %s\n", errbuf);

	return handle;
}

void print_pkt(pkt packet) {
	// print the info
	printf("Frame %d: ", packet.order);
	printf("%d bytes on wire (%d bits), ",  packet.len + 4, (packet.len + 4) * 8);
	printf("%d bytes captured (%d bits)", packet.len, packet.len * 8);
	printf("\n");

	print_ethertype(packet.eth_type, packet.log_header);

	printf("\nSrc mac: ");
	print_mac(packet.src_mac);

	printf(", Dst mac: ");
	print_mac(packet.dst_mac);
	printf("\n");

	
	// print packet data
	printf("\n");
	hexdump(packet.dst_mac, packet.len);

	printf("\n\n");
}

void print_mac (uint8_t *start) {
	int i = 0;
	for (; i < MAC_SIZE - 1; i++)
		printf("%02x:", *(start + i));

	printf("%02x", *(start + i));
}

// atomic printing of hex - print lines, blocks, words (cycle for group)
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
			
			for    (int word = 0; word < CHARS_PER_BLOCK; word++)
				if ( (offset = line + block + word) < n) {
					printf("\033[90m");
					printf("%02x ", *((uint8_t *)(data + offset)) );
					printf("\033[0m");
				} else
					printf("   ");

			printf("  ");
		}

		// print human readable
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

// TODO: refactor this shit to be more modular
void print_ethertype (uint16_t *eth_type, uint16_t *log_header) {
    FILE *eth_types = fopen("source/eth_types.txt", "r");
    int eth_num = 0;
	
    char c;

    if ( be16toh(*eth_type) >= 1500 ) {
        printf("Ethernet II: ");

		// special behaviour for ipv4 packets:
		if (be16toh(*eth_type) == 0x0800) {
			printf("Internet Protocol version 4 (IPv4)\n");

			ip_header header;
			header.ip_header_start = (uint8_t *) log_header;
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
					printf("ip is: %d\n", src_ips[*src_ips_count - 1].ip);
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
							printf("ip is: %d\n", src_ips[*src_ips_count - 1].ip);
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

			printf("\nSrc ip addr: %d.%d.%d.%d, Dst ip addr: %d.%d.%d.%d",
					*((uint8_t *)header.src_addr + 0),
					*((uint8_t *)header.src_addr + 1),
					*((uint8_t *)header.src_addr + 2),
					*((uint8_t *)header.src_addr + 3),
					*((uint8_t *)header.dst_addr + 0),
					*((uint8_t *)header.dst_addr + 1),
					*((uint8_t *)header.dst_addr + 2),
					*((uint8_t *)header.dst_addr + 3));

		} else
			print_ethernetII_subprotocol(ethernetII_protocols, be16toh(*eth_type));
	}
    else
        while (1) {
            fscanf(eth_types, "%d", &eth_num);

            if ( eth_num == be16toh(*log_header) ) {
				getc(eth_types);  // skip one space

				// print the eth type
				for (int i = 0; (c = getc(eth_types)) != '\n'; i++)
					printf("%c", c);

				printf(": ");
				print_802_3_subprotocol(eth802_3_protocols, eth_num);
				break;
            } else if (eth_num == 0) {
				getc(eth_types);  // skip one space

				for (int i = 0; (c = getc(eth_types)) != '\n'; i++)
					printf("%c", c);

				printf(": ");
				print_802_3_subprotocol(eth802_3_protocols, *((uint8_t *)log_header));
				break;
            }
            else
                while ( (c = getc(eth_types)) != '\n' );
        }
    
    fclose(eth_types);
}

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

// TODO: refactor this mess
void print_ethernetII_subprotocol (protocol *protocols, uint16_t eth_type) {
	int i = 0;
	while (1) {
		if (protocols[i].n < eth_type) {
			i++;
		} else {
			if (protocols[i].n <= eth_type &&
				protocols[i].nstop != -1 &&
				protocols[i].nstop >= eth_type) {
					printf("%s", protocols[i].name);
					return;
			} else if (protocols[i].n <= eth_type) {
				printf("%s", protocols[i].name);
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

void print_802_3_subprotocol (protocol *protocols, uint8_t LSAP) {
	int i = 0;
	while (protocols[i].n != LSAP) {
		i++;
		if (i > 0xFF) {
			printf("subprotocol not found");
			return;
		}
	}

	printf("%s", protocols[i].name);
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

// TODO: free names of protocols first (at least 2MB leak)
void free_protocols (protocol *protocols) {
	free(protocols);
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
