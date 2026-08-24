// common function
#ifndef XDP_FIREWALL_COMMON_H
#define XDP_FIREWALL_COMMON_H

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "xdp-firewall.h"  

int parse_ip_address(const char *ip_str, __u32 *ip_addr, __u32 *prefixlen);
void print_rule_info(int map_fd, const char *label);
void print_ip_info(int map_fd, const char *label);
void print_bucket_info(int map_fd);
void set_rule(int map_fd, __u16 port, __u8 flag);
void set_ip_rule(int map_fd, struct ipv4_lpm_key ip_key, __u8 flag);
int ensure_bpf_fs_dir(void);

#endif