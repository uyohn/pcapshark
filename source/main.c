#include <stdio.h>
#include <pcap/pcap.h>
#include <sys/types.h>

// pkt handler definition
void packetHandler (u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);

int main () {
	printf("\n\tWelcome to PcapShark\n");
	printf("\tFrame analyzer writeen in C, based on lib-pcap\n\n\n");

	// prepare
	char errbuf[PCAP_ERRBUF_SIZE];

	// open capture
	pcap_t *handle = pcap_open_offline("savefile/eth-2.pcap", errbuf);

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
	printf("captured length: %d B\n", pkthdr->caplen);
	printf("off wire length: %d B = %d bits\n", pkthdr->len, pkthdr->len * 8);

	for (int i = 1; i <= pkthdr->len; i++) {
		// green - for dest mac
		if ( i <= 6)
			printf("\033[0;42;30m");

		// yellow - for src mac
		if ( i > 6 && i <= 12)
			printf("\033[0;44;30m");

		printf("%02x ", *(packet + i - 1));

		// reset color
		printf("\033[0m");

		if (i % 8 == 0)
			printf("  ");

		if (i % 16 == 0)
			printf("\n");
	}

	printf("\n");
	printf(" \033[0;44m \033[0m");
	printf(" source mac\n");
	printf(" \033[0;42m \033[0m");
	printf(" destination mac\n");
	printf("\n\n");
}
