#ifndef SENTINELMESH_NEIGHBOR_PARSER_H
#define SENTINELMESH_NEIGHBOR_PARSER_H

#include <stddef.h>

struct neighbor_record {
    char address[64];
    char mac[32];
};

int parse_neighbor_line(const char *line, struct neighbor_record *record);
int is_usable_ipv4(const char *address);

#endif
