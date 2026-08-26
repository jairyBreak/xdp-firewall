#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "xdp-firewall.h"

volatile __u8 verbose_enabled = 0;

// Define the ring buffer map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  // 16 MB buffer
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rate_config);
} rate_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);
    __type(value, struct drop_info);
} src_port_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);
    __type(value, struct drop_info);
} dst_port_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key, __u32);
    __type(value, struct t_bucket);
} bucket_map SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_LPM_TRIE);
        __uint(max_entries, 1024);
        __type(key, struct ipv4_lpm_key);
        __type(value, __u8);
        __uint(map_flags, BPF_F_NO_PREALLOC);
} ipv4_lpm_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} ip_count_map SEC(".maps");

// Helper function to check if the packet is TCP
static bool is_tcp(struct ethhdr *eth, void *data_end)
{
    // Ensure Ethernet header is within bounds
    if ((void *)(eth + 1) > data_end)
        return false;

    // Only handle IPv4 packets
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return false;

    struct iphdr *ip = (struct iphdr *)(eth + 1);

    // Ensure IP header is within bounds
    if ((void *)(ip + 1) > data_end)
        return false;

    // Check if the protocol is TCP
    if (ip->protocol != IPPROTO_TCP)
        return false;

    return true;
}

static int consume_bucket(struct t_bucket *b){
    int result;
    __u32 key = 0;
    __u64 refill_rate, capacity;
    struct rate_config *conf = bpf_map_lookup_elem(&rate_map, &key);

    if(!conf){
        return 0;
    }
    refill_rate = conf->refill_rate;
    capacity = conf->capacity;
    __u64 current_time = bpf_ktime_get_ns(); 

    bpf_spin_lock(&b->lock);
    __u64 elapsed_time = current_time - b->last_fill_time;
    b->last_fill_time = current_time;

    b->token += elapsed_time * refill_rate / 1000000ULL;
    if(b->token > capacity){
        b->token = capacity;
    }
    if(b->token >= 1){
        b->token -= 1;
        result = 0;
    }
    else{
        b->drop_count += 1;
        result = -1;
    }

    bpf_spin_unlock(&b->lock);
    return result;
}

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;

    if (!is_tcp(eth, data_end)) {
        return XDP_PASS;
    }

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    
    int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr)) {
        return XDP_PASS;
    }

    if ((void *)ip + ip_hdr_len > data_end) {
        return XDP_PASS;
    }


    struct tcphdr *tcp = (struct tcphdr *)((unsigned char *)ip + ip_hdr_len);

    if ((void *)(tcp + 1) > data_end) {
        return XDP_PASS;
    }

    __u32 tcp_header_bytes = tcp->doff * 4;
    if (tcp_header_bytes < sizeof(*tcp) || tcp_header_bytes > MAX_TCP_HEADER_BYTES) {
        return XDP_PASS;
    }

    __u32 src_ip = ip->saddr;
    __u16 src_port = bpf_ntohs(tcp->source);
    __u16 dst_port = bpf_ntohs(tcp->dest);

    struct ipv4_lpm_key ip_key;
    ip_key.prefixlen = 32;
    ip_key.addr = src_ip;

    __u8 *ip_check = bpf_map_lookup_elem(&ipv4_lpm_map, &ip_key);
    __u64 *ip_count = bpf_map_lookup_elem(&ip_count_map,&src_ip);
    struct drop_info *src_check = bpf_map_lookup_elem(&src_port_map, &src_port);
    struct drop_info *dst_check = bpf_map_lookup_elem(&dst_port_map, &dst_port);

    int drop_flag = 0;
    if(ip_check && *ip_check == 1){
        drop_flag = 1;
    }
    if(ip_count){
        (*ip_count)++;
    }
    else{
        __u64 init = 1;
        bpf_map_update_elem(&ip_count_map, &src_ip, &init, BPF_ANY);
    }
    if (!drop_flag){
        if(src_check){
            src_check->count++;
            if(src_check->flag == 1){
                drop_flag = 1;
            }
        }
        else if(!src_check){
            struct drop_info src_entry = {0};
            src_entry.flag = 0;
            src_entry.count = 1;
            bpf_map_update_elem(&src_port_map, &src_port, &src_entry, BPF_ANY);
        }
        
        if(dst_check){
            dst_check->count++;
            if(dst_check->flag == 1){
                drop_flag = 1;
            }
        }
        else if(!dst_check){
            struct drop_info dst_entry = {0};
            dst_entry.flag = 0;
            dst_entry.count = 1;
            bpf_map_update_elem(&dst_port_map, &dst_port, &dst_entry, BPF_ANY);
        }
    }

    struct t_bucket *ip_bucket = bpf_map_lookup_elem(&bucket_map,&src_ip);
    if (ip_bucket){
        int consume = consume_bucket(ip_bucket);
        //bpf_printk("TB: ip=%x consume=%d token=%llu", src_ip, consume, ip_bucket->token);

        if(consume < 0){
            drop_flag = 1;
        }
    }
    else{
        struct t_bucket new_bucket = {0};
        __u32 key = 0;
        struct rate_config *conf = bpf_map_lookup_elem(&rate_map, &key);
        new_bucket.token = conf->capacity - 1;
        new_bucket.last_fill_time = bpf_ktime_get_ns();
        new_bucket.drop_count = 0;
        bpf_map_update_elem(&bucket_map, &src_ip, &new_bucket, BPF_ANY);
    }

    if(drop_flag == 1){
        return XDP_DROP;
    }
    
    if (verbose_enabled){
        // Reserve a fixed-size event because bpf_ringbuf_reserve requires a constant size
        struct tcp_event *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
        if (!event) {
            return XDP_PASS;  // If reservation fails, skip processing
        }

        event->header_len = tcp_header_bytes;
        __builtin_memset(event->header, 0, sizeof(event->header));

        // Copy the TCP header bytes into the ring buffer
        // Using a loop to ensure compliance with eBPF verifier
        for (int i = 0; i < MAX_TCP_HEADER_BYTES; i++) {
            if (i >= tcp_header_bytes)
                break;

            if ((void *)tcp + i + 1 > data_end) {
                bpf_ringbuf_discard(event, 0);
                return XDP_PASS;
            }

            // Accessing each byte safely within bounds
            unsigned char byte = *((unsigned char *)tcp + i);
            event->header[i] = byte;
        }

        // Submit the data to the ring buffer
        bpf_ringbuf_submit(event, 0);
    }
    // Optional: Print a debug message (will appear in kernel logs)
    //bpf_printk("Captured TCP header (%u bytes)", tcp_header_bytes);
    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
