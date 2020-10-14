#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <sys/types.h>

#define MAC_SIZE 6
#define ETH_TYPE_SIZE 2

typedef struct pkt {
	int order;
	int len;
	int real_len;
	const u_char *dst_mac;
	const u_char *src_mac;
	u_int16_t eth_type;
	u_int16_t log_header;
} pkt;

int frame_no = 1;

// definitions
void packetHandler (u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void hexdump(const u_char *packet, unsigned int s, unsigned int n);
void find_ethertype(u_int16_t eth_type, u_int16_t log_header);

int main () {
	printf("\n\tWelcome to PcapShark\n");
	printf("\tFrame analyzer writeen in C, based on lib-pcap\n\n\n");

	// prepare
	char errbuf[PCAP_ERRBUF_SIZE];

	// open capture
	pcap_t *handle = pcap_open_offline("savefile/trace-23.pcap", errbuf);

	if (handle == NULL) {
		printf("Error while opening .pcap: %s\n", errbuf);
		return 1;
	}

	// start packet processing loop (just like live capture)
	if ( pcap_loop(handle, 0, packetHandler, NULL) < 0 ) {
		printf("pcap_loop() failed: %s\n", pcap_geterr(handle));
		return 1;
	}

	return 0;
}

// run this for each frame
void packetHandler (u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	// parse frame into pkt struct
	pkt *current = (pkt *)malloc(sizeof(pkt));

	current->order = frame_no++;
	current->len = pkthdr->len;
	current->dst_mac = packet;
	current->src_mac = packet + MAC_SIZE;
	current->eth_type = (u_int16_t)(packet[12] << 8 | packet[13]);
	current->log_header = (u_int16_t)(packet[14] << 8 | packet[15]);


	// print the info
	printf("\n\n");

	printf("frame %d\n", current->order);
	printf("length: %d\n", current->len);
	printf("real len: %d\n", current->len + 4);

	printf("eth type: %04x\n", current->eth_type);
	find_ethertype(current->eth_type, current->log_header);

	printf("\n");

	printf("\033[0;42;30m");
	hexdump(current->dst_mac, 0, MAC_SIZE);
	printf("\033[0m");

	printf(" dst mac\n");

	printf("\033[0;44;30m");
	hexdump(current->src_mac, 0, MAC_SIZE);
	printf("\033[0m");

	printf(" src mac\n");


	printf("\n");
	
	hexdump(packet, 0, current->len);

	printf("\n\n");

	free(current);
	//getchar();*/
}


// utility
void hexdump(const u_char *packet, unsigned int s, unsigned int n) {
	for (int i = 1; i <= n; i++) {
		printf("%02x ", *(packet + s + i - 1));

		if (i % 8 == 0)
			printf("  ");

		if (i % 16 == 0)
			printf("\n");
	}
}

void find_ethertype (u_int16_t eth_type, u_int16_t log_header) {
    FILE *eth_types = fopen("source/eth_types.txt", "r");
    int eth_num = 0;
    char c;

    if ( eth_type >= 1500 )
        printf("Ethernet II\n");
    else
        while (1) {
            fscanf(eth_types, "%d", &eth_num);
            if (eth_num == log_header) {
				getc(eth_types);  // skip one space

				// print the eth type
                while ( (c = getc(eth_types)) != '\n' )
                    printf("%c", c);

                printf("\n");
                break;
            } else if (eth_num == 0) {
				getc(eth_types);  // skip one space

                while ( (c = getc(eth_types)) != '\n' )
                    printf("%c", c);
                
                printf("\n");
                break;
            }
            else
                while ( (c = getc(eth_types)) != '\n' );
        }
    
    fclose(eth_types);
}
