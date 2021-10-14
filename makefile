CC=gcc

SRCDIR=source
BUILDDIR=build

run: main
	./$(BUILDDIR)/main savefile/trace-2.pcap
main:
	gcc -o $(BUILDDIR)/main $(SRCDIR)/v2.c $(SRCDIR)/pcap-shark.c -lpcap
