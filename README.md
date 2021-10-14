# PcapShark

## Update

For Winter Semester 2021/2022 check `v2.c`  
`main.c` is legacy code from last year  
  
makefile is already prepared for compiling `v2.c`  
so all you need to do is run `make` from terminal
 
---
 
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
