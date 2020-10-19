CC=gcc

SRCDIR=source
BUILDDIR=build

run: main
	./$(BUILDDIR)/main savefile/trace-1.pcap
main:
	gcc -o $(BUILDDIR)/main $(SRCDIR)/main.c -lpcap
