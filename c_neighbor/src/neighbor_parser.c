#include "neighbor_parser.h"
#include <stdio.h>
#include <string.h>

int is_usable_ipv4(const char *address) {
    unsigned int a, b, c, d;
    if (sscanf(address, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 0;
    if (a > 223 || b > 255 || c > 255 || d > 254) return 0;
    if (a == 0 || a == 127 || a >= 224) return 0;
    return 1;
}

int parse_neighbor_line(const char *line, struct neighbor_record *record) {
    char address[64] = {0};
    char mac[32] = {0};
    if (sscanf(line, "%63s %31s", address, mac) != 2) return 0;
    if (!is_usable_ipv4(address)) return 0;
    if (strlen(mac) < 11) return 0;
    strncpy(record->address, address, sizeof(record->address) - 1);
    strncpy(record->mac, mac, sizeof(record->mac) - 1);
    return 1;
}
