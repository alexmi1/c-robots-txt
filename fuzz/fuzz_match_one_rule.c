#include "c_robots_txt.h"

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

typedef struct {
    bool matched;
    size_t path_chars_matched;
    size_t rule_chars_matched;
} RuleMatchResult;

RuleMatchResult match_one_rule(const char* path, const char* rule);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const long MAX_FILE_SIZE = sizeof(char) * 1024 * 50 * 1;
    if (size > MAX_FILE_SIZE) {
        return 0;
    }

    size_t path_size = size / 2;
    size_t rule_size = size - (path_size);

    char* path_buffer = malloc(sizeof(char) * (path_size + 1));
    memcpy(path_buffer, data, path_size);
    path_buffer[path_size] = '\0';

    char* rule_buffer = malloc(sizeof(char) * (rule_size + 1));
    memcpy(rule_buffer, data + path_size, rule_size);
    rule_buffer[rule_size] = '\0';

    RuleMatchResult matching_result = match_one_rule(path_buffer, rule_buffer);

    free(path_buffer);
    free(rule_buffer);

    return 0;
}

