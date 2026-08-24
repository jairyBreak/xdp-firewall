// common function

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#include "xdp-firewall-common.h"

int parse_ip_address(const char *ip_str, __u32 *ip_addr, __u32 *prefixlen){
    char ip_copy[16];
    __u32 prefixlen_local = 32;

    if(sscanf(ip_str, "%15[^/]/%u", ip_copy, &prefixlen_local) < 1){
        fprintf(stderr, "Invalid CIDR: %s\n", ip_str);
        return -1;
    }
    
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_copy, &addr.s_addr) != 1) {
        fprintf(stderr, "Invalid IP: %s\n", ip_str);
        return -1;
    }

    *ip_addr = addr.s_addr;
    *prefixlen = prefixlen_local;
    return 0;
}

void print_rule_info(int map_fd, const char *label)
{
    int num_cpus = libbpf_num_possible_cpus();
    if (num_cpus <= 0) {
        fprintf(stderr, "Failed to get possible CPU count\n");
        return;
    }
    
    size_t elem_size = sizeof(struct drop_info);
    struct drop_info *print_entry = calloc(num_cpus, elem_size);
    if (!print_entry) {
        fprintf(stderr, "calloc failed\n");
        return;
    }

    __u16 key, next_key;
    int ret = bpf_map_get_next_key(map_fd, NULL, &next_key);

    while (ret == 0){
        if(bpf_map_lookup_elem(map_fd, &next_key, print_entry) == 0){
            __u32 count_sum = 0;
            for(int i = 0;i < num_cpus;i++){
                count_sum += print_entry[i].count;
            }
            printf("%s: %u, flag: %u, count: %u\n",label, next_key, print_entry[0].flag, count_sum);
        }
        key = next_key;
        ret = bpf_map_get_next_key(map_fd, &key, &next_key);
    }

    free(print_entry);
}

void print_ip_info(int map_fd, const char *label)
{   
    int num_cpus = libbpf_num_possible_cpus();
    __u32 key, next_key;
    int ret = bpf_map_get_next_key(map_fd, NULL, &next_key);

    if (num_cpus <= 0) {
        fprintf(stderr, "Failed to get possible CPU count\n");
        return;
    }
    
    size_t elem_size = sizeof(struct drop_info);
    __u64 *print_entry = calloc(num_cpus, elem_size);
    if (!print_entry) {
        fprintf(stderr, "calloc failed\n");
        return;
    }

    
    while (ret == 0){
        __u64 entry_sum = 0;
        if (bpf_map_lookup_elem(map_fd, &next_key, print_entry) == 0){
            char ip_str[INET_ADDRSTRLEN];
            for(int i = 0;i < num_cpus;i++){
                entry_sum += print_entry[i];
            }
            if (inet_ntop(AF_INET, &next_key, ip_str, sizeof(ip_str)) != NULL) {
                printf("%s: %s, count: %llu\n", label, ip_str, entry_sum);
            }
        }
        key = next_key;
        ret = bpf_map_get_next_key(map_fd, &key, &next_key);
    }

    free(print_entry);
}

void print_bucket_info(int map_fd)
{
    __u32 key, next_key;
    int ret = bpf_map_get_next_key(map_fd, NULL, &next_key);

    while (ret == 0) {
        struct t_bucket b;
        if (bpf_map_lookup_elem(map_fd, &next_key, &b) == 0) {
            struct in_addr addr;
            addr.s_addr = next_key; 
            printf("IP %s: token=%llu, dropped=%llu\n",
                   inet_ntoa(addr), b.token, b.drop_count);
        }
        key = next_key;
        ret = bpf_map_get_next_key(map_fd, &key, &next_key);
    }
}

void set_rule(int map_fd, __u16 port, __u8 flag)
{   
    int num_cpus = libbpf_num_possible_cpus();
    if (num_cpus <= 0) {
        fprintf(stderr, "Failed to get possible cpus\n");
        return;
    }
    size_t elem_size = sizeof(struct drop_info);

    struct drop_info *entry = calloc(num_cpus, elem_size);
    if (!entry) {
        fprintf(stderr, "calloc failed\n");
        return;
    }

    int ret1 = bpf_map_lookup_elem(map_fd, &port, entry);
    for (int i = 0;i < num_cpus;i++){
        entry[i].flag = flag;
        if (ret1 != 0){
            entry[i].count = 0;
        }
    }

    bpf_map_update_elem(map_fd, &port, entry, BPF_ANY);

    free(entry);
}

void set_ip_rule(int map_fd, struct ipv4_lpm_key ip_key, __u8 flag)
{
    __u8 entry = flag;
    bpf_map_update_elem(map_fd, &ip_key, &entry, BPF_ANY);
}

int ensure_bpf_fs_dir(void)
{
    struct stat st;
    if (stat(BPF_FS_PATH, &st) == 0) {
        return 0;
    }

    if (mkdir(BPF_FS_PATH, 0700) != 0) {
        fprintf(stderr, "Failed to create %s: %s\n", BPF_FS_PATH, strerror(errno));
        return -1;
    }

    return 0;
}