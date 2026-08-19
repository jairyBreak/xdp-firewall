#ifndef XDP_FIREWALL_H_
#define XDP_FIREWALL_H_

#define ETH_P_IP 0x0800
#define MAX_TCP_HEADER_BYTES 60
#define MAX_PORTS 1024
#define CAPACITY 1000 // max token in the bucket
#define REFILL_RATE 1 // 1 token per ms

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

struct t_bucket {
    __u64 token;
    __u64 last_fill_time; 
    struct bpf_spin_lock lock;
};
#endif /* XDP_FIREWALL_H_ */
