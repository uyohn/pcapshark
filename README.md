# PcapShark

visit repo for this project: [uyohn/PcapShark](https://www.github.com/uyohn/PcapShark)

C program for capturing and analyzing packets.

Written by Matej Rastocky

## Building

first clone this repo:

`git clone https://github.com/uyohn/PcapShark`

### Depends on libpcap

build with `gcc <filename> -lpcap`

I wrote a makefile to make it easier - just run: `make`

Program just dumps all output to terminal.
Make it easier to read by piping output into less:

`make | less`
