#ifndef TEST_UTILS_H
#define TEST_UTILS_H

#include <stdio.h>
#include <stdlib.h>

// no checks in testing code -- we should fail anyway
// don't try this at home!!

// returns a null-terminated string that contains the contents of a robots.txt file
char* Utils_read_robots_file(const char* filename) {
    FILE* robots_txt_file;
    robots_txt_file = fopen(filename, "r");

    fseek(robots_txt_file, 0, SEEK_END);
    long file_size = ftell(robots_txt_file);
    rewind(robots_txt_file);

    char* file_data = malloc(file_size + 1);

    size_t bytes_read = fread(file_data, 1, file_size, robots_txt_file);
    fclose(robots_txt_file);

    file_data[bytes_read] = '\0';

    return file_data;
}


#endif // TEST_UTILS_H
