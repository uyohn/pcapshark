CC=gcc

SRCDIR=source
BUILDDIR=build

run: main
	./$(BUILDDIR)/main
main:
	gcc -o $(BUILDDIR)/main $(SRCDIR)/main.c -lpcap
