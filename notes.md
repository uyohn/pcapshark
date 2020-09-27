# Lib Pcap

## general

`char errbug[PCAP_ERRBUF_SIZE]`
*errbuf* is assumed to be able to hold at least `PCAP_ERRBUF_SIZE`

## finding devices

**read more** `man pcap_findalldevs`

`PCAP_ERRBUF_SIZE` chars.
`pcap_if_t *alldevs`
pointer to first device

`pcap_findalldevs(&alldevs, errbuf`
populate device list
return 0 on success, -1 on failure.
If -1 is returned, *errbuf* is filled with err msg.

`alldevs` is set to point to the first element of the list.
Each element is of type `pcap_if_t` with these members:

- `next` - NULL / nex element in list
- `name` - pointer to string (pass to `pcap_open_live()`)
- `description` - NULL / human-readable description
- `addresses` - ptr to first el of address list for if
- `flags`
- `PCAP_IF_LOOPBACK`

Each element of addresses is `pcap_addr_t` with these members:

- `next` - NULL / next alament
- `addr` - ptr to `struct sockaddr` containing an addr
- `netmask` - NULL / ptr to `struct sockaddr` with netmask for addr
- `broadaddr` - NULL / ptr to broadcast addresses
- `dstaddr` - NULL / ptr to destination address

**all ips are IPv4 or IPv6** - check `sa_family` member
of `struct sockaddr` before interpreting the ip.
