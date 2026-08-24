#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "xdp-firewall.h"          
#include "xdp-firewall-common.h"   

static void print_help(void)
{
    printf("Available commands:\n");
    printf("  block dst-port <port>       Block a destination port\n");
    printf("  block src-port <port>       Block a source port\n");
    printf("  block ip <cidr>             Block an IP or CIDR range (e.g. 10.0.0.0/24)\n");
    printf("  status                      Show current rules and statistics\n");
    printf("  unpin                       Remove all pinned maps\n");
    printf("  exit / quit                 Exit the CLI\n");
}

static int open_pinned_map(const char *name)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", BPF_FS_PATH, name);

    int fd = bpf_obj_get(path);
    if (fd < 0) {
        fprintf(stderr, "Error: cannot open pinned map '%s': %s\n", path, strerror(errno));
        fprintf(stderr, "Is xdp-firewall running?\n");
    }
    return fd;
}

static void handle_block_dst_port(const char *port_str)
{
    int fd = open_pinned_map("dst_port_map");
    if (fd < 0) return;

    __u16 port = (__u16)atoi(port_str);
    set_rule(fd, port, 1);
    printf("Blocked destination port %u\n", port);

    close(fd);
}

static void handle_block_src_port(const char *port_str)
{
    int fd = open_pinned_map("src_port_map");
    if (fd < 0) return;

    __u16 port = (__u16)atoi(port_str);
    set_rule(fd, port, 1);
    printf("Blocked source port %u\n", port);

    close(fd);
}

static void handle_block_ip(const char *cidr_str)
{
    int fd = open_pinned_map("ipv4_lpm_map");
    if (fd < 0) return;

    struct ipv4_lpm_key key;
    if (parse_ip_address(cidr_str, &key.addr, &key.prefixlen) != 0) {
        close(fd);
        return;
    }

    set_ip_rule(fd, key, 1);
    printf("Blocked IP range %s\n", cidr_str);

    close(fd);
}

static void handle_status(void)
{
    int src_fd = open_pinned_map("src_port_map");
    if (src_fd >= 0) {
        print_rule_info(src_fd, "Source Port");
        close(src_fd);
    }

    int dst_fd = open_pinned_map("dst_port_map");
    if (dst_fd >= 0) {
        print_rule_info(dst_fd, "Destination Port");
        close(dst_fd);
    }

    int ip_fd = open_pinned_map("ipv4_lpm_map");
    if (ip_fd >= 0) {
        print_ip_info(ip_fd, "IP Rule");
        close(ip_fd);
    }

    int bucket_fd = open_pinned_map("bucket_map");
    if (bucket_fd >= 0) {
        print_bucket_info(bucket_fd);
        close(bucket_fd);
    }
}

static void handle_unpin_all(void)
{
    const char *maps[] = {
        "src_port_map",
        "dst_port_map",
        "ipv4_lpm_map",
        "bucket_map",
        "rate_map",
        "ip_count_map",
    };
    int n = sizeof(maps) / sizeof(maps[0]);

    for (int i = 0; i < n; i++) {
        char path[256];
        snprintf(path, sizeof(path), "%s/%s", BPF_FS_PATH, maps[i]);

        if (unlink(path) == 0) {
            printf("Unpinned %s\n", maps[i]);
        } else {
            fprintf(stderr, "Warning: failed to unpin %s: %s\n", maps[i], strerror(errno));
        }
    }
}

static void handle_command(char *line)
{
    char *cmd = strtok(line, " ");
    if (!cmd) return;

    if (strcmp(cmd, "block") == 0) {
        char *target = strtok(NULL, " ");
        char *value = strtok(NULL, " ");

        if (!target || !value) {
            fprintf(stderr, "Usage: block <dst-port|src-port|ip> <value>\n");
            return;
        }

        if (strcmp(target, "dst-port") == 0) {
            handle_block_dst_port(value);
        } else if (strcmp(target, "src-port") == 0) {
            handle_block_src_port(value);
        } else if (strcmp(target, "ip") == 0) {
            handle_block_ip(value);
        } else {
            fprintf(stderr, "Unknown block target: %s\n", target);
        }
    }
    else if (strcmp(cmd, "status") == 0) {
        handle_status();
    }
    else if (strcmp(cmd, "help") == 0) {
        print_help();
    }

    else if (strcmp(line, "unpin") == 0) {
        printf("Remove all pinned maps. The program will lose access\n");
        printf("to set rules until it re-pins them (e.g. on restart xdp-firewall).\n");
        printf("Continue? [Y/N] ");
        fflush(stdout);

        char confirm[16];
        if (fgets(confirm, sizeof(confirm), stdin) && (confirm[0] == 'y' || confirm[0] == 'Y')) {
            handle_unpin_all();
        } else {
            printf("Cancelled.\n");
        }
    }
    else {
        fprintf(stderr, "Unknown command: %s (type 'help' for available commands)\n", cmd);
    }
}


int main(int argc, char **argv)
{
    printf("XDP Firewall Control CLI\n");
    printf("Type 'help' for available commands.\n\n");

    char line[256];
    while (1) {
        printf("xdp-fw> ");
        fflush(stdout);

        if (!fgets(line, sizeof(line), stdin)) {
            break;
        }

        line[strcspn(line, "\n")] = 0;  

        if (strlen(line) == 0) {
            continue;
        }

        if (strcmp(line, "exit") == 0 || strcmp(line, "quit") == 0) {
            break;
        }

        handle_command(line);
    }

    printf("Goodbye.\n");
    return 0;
}