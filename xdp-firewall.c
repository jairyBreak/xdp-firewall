#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/tcp.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "xdp-firewall.skel.h"  // Generated skeleton header
#include "xdp-firewall.h"
#include "xdp-firewall-common.h"

volatile sig_atomic_t stop = 0;

void handle_sig(int sig)
{
    stop = 1;
}

// Callback function to handle events from the ring buffer
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    if (data_sz < sizeof(struct tcp_event)) {
        fprintf(stderr, "Received incomplete TCP event\n");
        return 0;
    }

    struct tcp_event *event = data;
    if (event->header_len < 20 || event->header_len > MAX_TCP_HEADER_BYTES) {
        fprintf(stderr, "Invalid TCP header length: %u\n", event->header_len);
        return 0;
    }


    struct tcphdr *tcp = (struct tcphdr *)event->header;

    // Convert fields from network byte order to host byte order
    uint16_t source_port = ntohs(tcp->source);
    uint16_t dest_port = ntohs(tcp->dest);
    uint32_t seq = ntohl(tcp->seq);
    uint32_t ack_seq = ntohl(tcp->ack_seq);
    uint16_t window = ntohs(tcp->window);

    // Extract flags
    uint8_t flags = 0;
    flags |= (tcp->fin) ? 0x01 : 0x00;
    flags |= (tcp->syn) ? 0x02 : 0x00;
    flags |= (tcp->rst) ? 0x04 : 0x00;
    flags |= (tcp->psh) ? 0x08 : 0x00;
    flags |= (tcp->ack) ? 0x10 : 0x00;
    flags |= (tcp->urg) ? 0x20 : 0x00;
    flags |= (tcp->ece) ? 0x40 : 0x00;
    flags |= (tcp->cwr) ? 0x80 : 0x00;

    printf("Captured TCP Header:\n");
    printf("  Source Port: %u\n", source_port);
    printf("  Destination Port: %u\n", dest_port);
    printf("  Sequence Number: %u\n", seq);
    printf("  Acknowledgment Number: %u\n", ack_seq);
    printf("  Data Offset: %u\n", tcp->doff);
    printf("  Flags: 0x%02x\n", flags);
    printf("  Window Size: %u\n", window);
    printf("\n");

    return 0;
}

int main(int argc, char **argv)
{
    struct xdp_firewall_bpf *skel;
    struct ring_buffer *rb = NULL;

    int ifindex;
    __u16 src_port[MAX_PORTS];
    __u16 dst_port[MAX_PORTS];
    struct ipv4_lpm_key ip_key[MAX_PORTS];

    int err;
    int i = 1;
    __u32 key = 0;
    int src_count = 0;
    int dst_count = 0;
    int ip_count = 0;
    __u16 verbose_flag = 0;
    struct rate_config conf;
    conf.refill_rate = DEFAULT_REFILL_RATE;
    conf.capacity = DEFAULT_CAPACITY;

    const char *ifname = NULL;

    signal(SIGINT, handle_sig);
    signal(SIGTERM, handle_sig);

    while (i < argc){
        if (ifname == NULL){
            ifname = argv[i];
            i++;
        }
        else if (strcmp(argv[i], "-sp") == 0){
            i++;
            while (i < argc && argv[i][0] != '-'){
                if(src_count >= MAX_PORTS){
                    fprintf(stderr, "too many port\n");
                    return 1;
                }
                src_port[src_count++] = (__u16)atoi(argv[i]);
                i++;
            }
        }
        else if(strcmp(argv[i], "-dp") == 0){
            i++;
            while (i < argc && argv[i][0] != '-'){
                if(dst_count >= MAX_PORTS){
                    fprintf(stderr, "too many port\n");
                    return 1;
                }
                dst_port[dst_count++] = (__u16)atoi(argv[i]);
                i++;
            }
        }
        else if(strcmp(argv[i], "-ip") == 0){
            i++;
            while (i < argc && argv[i][0] != '-'){
                if(ip_count >= MAX_PORTS){
                    fprintf(stderr, "too many IP rule\n");
                    return 1;
                }
                struct ipv4_lpm_key ip_entry;
                if(parse_ip_address(argv[i], &ip_entry.addr, &ip_entry.prefixlen) != 0){
                    return 1;
                }
                ip_key[ip_count++] = ip_entry;
                i++;
            }
        }
        else if(strcmp(argv[i], "-rate") == 0){
            i++;
            if (i >= argc) {
                fprintf(stderr, "-rate requires a value\n");
                return 1;
            }
            conf.refill_rate = atoi(argv[i]);
            i++;
        }
        else if(strcmp(argv[i], "-cap") == 0){
            i++;
            if (i >= argc) {
                fprintf(stderr, "-cap requires a value\n");
                return 1;
            }
            conf.capacity = atoi(argv[i]);
            i++;
        }
        else if(strcmp(argv[i], "-verbose") == 0){
            verbose_flag = 1;
            i++;
        }
        else{
            fprintf(stderr, "Invalid argument: %s\n", argv[i]);
            return 1;
        }
    }

    if (ifname == NULL) {
        fprintf(stderr, "Usage: %s <ifname> [-sp <port>...] [-dp <port>...]\n", argv[0]);
        return 1;
    }

    ifindex = if_nametoindex(ifname);

    if (ifindex == 0)
    {
        fprintf(stderr, "Invalid interface name %s\n", ifname);
        return 1;
    }

    /* Open and load BPF application */
    skel = xdp_firewall_bpf__open_and_load();
    if (!skel)
    {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    bpf_map_update_elem(bpf_map__fd(skel->maps.rate_map), &key, &conf, BPF_ANY);
    skel->bss->verbose_enabled = verbose_flag ? 1 : 0;

    /* Attach the XDP program to the specified interface */
    skel->links.xdp_pass = bpf_program__attach_xdp(skel->progs.xdp_pass, ifindex);
    if (!skel->links.xdp_pass)
    {
        err = -errno;
        fprintf(stderr, "Failed to attach XDP program: %s\n", strerror(errno));
        goto cleanup;
    }

    printf("Successfully attached XDP program to interface %s\n", ifname);


    /* 
     NOTE: pin/mkdir will fail inside a network namespace created via `ip netns add` 
     — the netns-local /sys/fs/bpf view is mounted read-only in this environment. 
     This is a property of the veth/netns test setup, not a bug in this code. 
     Comment out the block below when reproducing benchmarks inside such an environment; 
     pinning works normally when xdp-firewall is attached to a real network interface outside a netns.
    */
    if (ensure_bpf_fs_dir() != 0) {
        err = -1;
        goto cleanup;
    }

    if (bpf_map__pin(skel->maps.src_port_map, BPF_FS_PATH "/src_port_map") ||
        bpf_map__pin(skel->maps.dst_port_map, BPF_FS_PATH "/dst_port_map") ||
        bpf_map__pin(skel->maps.ipv4_lpm_map, BPF_FS_PATH "/ipv4_lpm_map") ||
        bpf_map__pin(skel->maps.bucket_map, BPF_FS_PATH "/bucket_map") ||
        bpf_map__pin(skel->maps.rate_map, BPF_FS_PATH "/rate_map") ||
        bpf_map__pin(skel->maps.ip_count_map, BPF_FS_PATH "/ip_count_map"))
    {
        fprintf(stderr, "Warning: failed to pin one or more maps: %s\n", strerror(errno));
    }

    for (int j = 0; j < src_count; j++){
        set_rule(bpf_map__fd(skel->maps.src_port_map), src_port[j], 1);
    }

    for (int k = 0; k < dst_count; k++){
        set_rule(bpf_map__fd(skel->maps.dst_port_map), dst_port[k], 1);
    }
    
    for (int l = 0; l < ip_count; l++){
        set_ip_rule(bpf_map__fd(skel->maps.ipv4_lpm_map), ip_key[l], 1);
    }

    /* Set up ring buffer polling */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb)
    {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = -1;
        goto cleanup;
    }

    
    printf("Start polling ring buffer\n");
    /* Poll the ring buffer */
    while (!stop)
    {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR)
            break;
        if (err < 0)
        {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }
    
    printf("\n---map_info---\n");
    print_ip_info(bpf_map__fd(skel->maps.ip_count_map), "IP Rule");
    //print_rule_info(bpf_map__fd(skel->maps.src_port_map), "Source Port");
    print_rule_info(bpf_map__fd(skel->maps.dst_port_map), "Destination Port");
    printf("---bucket drop info---\n");
    print_bucket_info(bpf_map__fd(skel->maps.bucket_map));

cleanup:
    ring_buffer__free(rb);
    xdp_firewall_bpf__destroy(skel);
    return -err;
}
