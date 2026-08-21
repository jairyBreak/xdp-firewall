#ifndef XDP_FIREWALL_H_
#define XDP_FIREWALL_H_

#define ETH_P_IP 0x0800
#define MAX_TCP_HEADER_BYTES 60
#define MAX_PORTS 1024
#define DEFAULT_REFILL_RATE 10 // 10 packet per ms
#define DEFAULT_CAPACITY 500 

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
    __u64 drop_count; 
    struct bpf_spin_lock lock;
};

struct rate_config {
    __u64 capacity;
    __u64 refill_rate;
};
#endif /* XDP_FIREWALL_H_ */
