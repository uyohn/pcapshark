# Lib Pcap

## general

`char errbug[PCAP_ERRBUF_SIZE]`
*errbuf* is assumed to be able to hold at least
`PCAP_ERRBUF_SIZE` chars

see `man pcap_geterr`

## finding devices

**read more** `man pcap_findalldevs`

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

to find more info about device, use flags:
`device->flags & PCAP_IF_<flag>`

available flags:

- `PCAP_IF_LOOPBACK`
- `PCAP_IF_UP`
- `PCAP_IF_RUNNING`
- `PCAP_IF_WIRELESS`
- `PCAP_IF_CONNECTION_STATUS`
  - `PCAP_IF_CONNECTION_STATUS_UNKNOWN`
  - `PCAP_IF_CONNECTION_STATUS_CONNECTED`
  - `PCAP_IF_CONNECTION_STATUS_DISCONNECTED`
  - `PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE` (loopback)

## ip and mask

**read more** `man pcap_lookupnet`, `man inet_ntoa`

### find ip and mask

`pcap_lookupnet` - find ip and subnet mask of device
params:

- `device` - name of device
- `&ip_raw` - `bpf_u_int32` (ip as int)
- `&mask_raw` - `bpf_u_int32` (mask as int)
- `errbuf`

returns 0 on success, `PCAP_ERROR` on failure.

### convert to human-readable form

`char ip[13], mask[13];`
`struct in_addr address;`

`address.s_addr = ip_raw;`
`strcpy(ip, inet_ntoa(address));`

`address.s_addr = mask_raw;`
`strcpy(mask, inet_ntoa(address));`

## `pcap_loop`

see `man pcap_loop`
