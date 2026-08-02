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

static void print_rule_info(int map_fd, const char *label)
{
    __u16 key, next_key;
    int ret = bpf_map_get_next_key(map_fd, NULL, &next_key);

    while (ret == 0){
        struct drop_info print_entry;
        if(bpf_map_lookup_elem(map_fd, &next_key, &print_entry) == 0){
            printf("%s: %u, flag: %u, count: %u\n",label, next_key, print_entry.flag, print_entry.count);
        }
        key = next_key;
        ret = bpf_map_get_next_key(map_fd, &key, &next_key);
    }
}

int main(int argc, char **argv)
{
    struct xdp_firewall_bpf *skel;
    struct ring_buffer *rb = NULL;
    struct drop_info src_entry = {0};
    struct drop_info dst_entry = {0};

    int ifindex;
    __u16 src_port;
    __u16 dst_port;
    int err;

    signal(SIGINT, handle_sig);
    signal(SIGTERM, handle_sig);

    if (argc != 4)
    {
        fprintf(stderr, "Usage: %s <ifname> <src_port> <dst_port>\n", argv[0]);
        return 1;
    }

    const char *ifname = argv[1];
    src_port = atoi(argv[2]);
    dst_port = atoi(argv[3]);
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

    /* Attach the XDP program to the specified interface */
    skel->links.xdp_pass = bpf_program__attach_xdp(skel->progs.xdp_pass, ifindex);
    if (!skel->links.xdp_pass)
    {
        err = -errno;
        fprintf(stderr, "Failed to attach XDP program: %s\n", strerror(errno));
        goto cleanup;
    }

    printf("Successfully attached XDP program to interface %s\n", ifname);

    
    int ret1 = bpf_map_lookup_elem(bpf_map__fd(skel->maps.src_port_map), &src_port, &src_entry);
    src_entry.flag = 1;
    if (ret1 != 0){
        src_entry.count = 0;
    }
    bpf_map_update_elem(bpf_map__fd(skel->maps.src_port_map), &src_port, &src_entry, BPF_ANY);

    int ret2 = bpf_map_lookup_elem(bpf_map__fd(skel->maps.dst_port_map), &dst_port, &dst_entry);
    dst_entry.flag = 1;
    if (ret2 != 0){
        dst_entry.count = 0;
    }
    bpf_map_update_elem(bpf_map__fd(skel->maps.dst_port_map), &dst_port, &dst_entry, BPF_ANY); 


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
    print_rule_info(bpf_map__fd(skel->maps.src_port_map), "Source Port");
    print_rule_info(bpf_map__fd(skel->maps.dst_port_map), "Destination Port");
    
cleanup:
    ring_buffer__free(rb);
    xdp_firewall_bpf__destroy(skel);
    return -err;
}
