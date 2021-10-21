CC=gcc

SRCDIR=source
BUILDDIR=build


#run: main
run:
	gcc source/v2.c -lpcap -o build/main
	#./$(BUILDDIR)/main savefile/trace-2.pcap
#main:
	#[ -d "./$(BUILDDIR)" ] || mkdir $(BUILDDIR) # Make sure the build dir exists
	#gcc -o $(BUILDDIR)/main $(SRCDIR)/v2.c $(SRCDIR)/pcap-shark.c -lpcap
