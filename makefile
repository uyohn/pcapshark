CC=gcc

SRCDIR=source
BUILDDIR=build

run: main
	./$(BUILDDIR)/main
main:
	echo "compile..."
	gcc -o $(BUILDDIR)/main $(SRCDIR)/main.c -lpcap
