// github: https://github.com/uyohn/PcapShark
// V2 - version for Winter Semester 2021/2022
// refactor of code from last year

#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <sys/types.h>

#include "pcap-shark.h"



// -----------------------
// GLOBALS

int pkt_order = 1; 	// frame counter
pcap_t *fp; 		// pointer to capfile file




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



	// --------------------
	// MAIN

	// start packet processing loop
	if (pcap_loop(handle, 0, packetHandler, NULL) < 0) {
		printf("pcap_loop() failed: %s\n", pcap_geterr(handle) );
		exit(LOOP_ERR);
	}



	// --------------------
	// CLEAN UP

	return 0;
}

void packetHandler (u_char *serData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	pkt current;

	current.order 		= pkt_order++;
	current.len 		= pkthdr->len;

	current.dst_mac 	= (uint8_t *) (packet);
	current.src_mac 	= (uint8_t *) (packet + MAC_SIZE);

	current.eth_type	= (uint16_t *) (packet + 2 * MAC_SIZE);
	current.log_header	= (uint16_t *) (packet + 2 * MAC_SIZE + 2);

	print_pkt(current);
}


