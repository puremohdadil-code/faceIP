#include "neighbor_parser.h"
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <stdlib.h>
#define popen _popen
#define pclose _pclose
#endif

static int emit(FILE *input) {
    char line[256];
    struct neighbor_record record;
    while (fgets(line, sizeof(line), input)) {
        if (parse_neighbor_line(line, &record)) {
            printf("{\"schema_version\":\"1.0\",\"kind\":\"observation\",\"module\":\"c_neighbor\",\"payload\":{\"address\":\"%s\",\"mac\":\"%s\"}}\n", record.address, record.mac);
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--system") == 0) {
        FILE *system_table = popen("arp -a", "r");
        if (system_table == NULL) return 2;
        int result = emit(system_table);
        pclose(system_table);
        return result;
    }
    return emit(stdin);
}
