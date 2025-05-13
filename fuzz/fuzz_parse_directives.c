#include "c_robots_txt.h"

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const long MAX_FILE_SIZE = sizeof(char) * 1024 * 1024 * 1;
    if (size > MAX_FILE_SIZE) {
        return 0;
    }

    char* c_string_buffer = malloc(sizeof(char) * (size + 1));
    memcpy(c_string_buffer, data, size);
    c_string_buffer[size] = '\0';

    RobotsTxt_Directives* directives = RobotsTxt_parse_directives(c_string_buffer, c_string_buffer);

    free(c_string_buffer);
    RobotsTxt_free_directives(directives);

    return 0;
}

