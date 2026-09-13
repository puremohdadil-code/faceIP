#include "neighbor_parser.h"
#include <stdio.h>

int main(void) {
    char line[256];
    struct neighbor_record record;
    while (fgets(line, sizeof(line), stdin)) {
        if (parse_neighbor_line(line, &record)) {
            printf("{\"schema_version\":\"1.0\",\"kind\":\"observation\",\"module\":\"c_neighbor\",\"payload\":{\"address\":\"%s\",\"mac\":\"%s\"}}\n", record.address, record.mac);
        }
    }
    return 0;
}
