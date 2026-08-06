#ifndef XDP_FIREWALL_H_
#define XDP_FIREWALL_H_

#define MAX_TCP_HEADER_BYTES 60
#define MAX_PORTS 128
struct tcp_event {
    unsigned int header_len;
    unsigned char header[MAX_TCP_HEADER_BYTES];
};

struct ipv4_lpm_key {
        __u32 prefixlen;
        __u32 addr;
};

struct drop_info {
    __u8 flag;
    __u32 count;
};

#endif /* XDP_FIREWALL_H_ */
