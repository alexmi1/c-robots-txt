#include "c_robots_txt.h"
#include "test-utils.h"

#include <assert.h>
#include <stdbool.h>

int main(void) {
    char* file_data = Utils_read_robots_file("../tests/test-files/nul-characters.txt");
    RobotsTxt_Directives* directives = RobotsTxt_parse_directives(file_data, "OurCrawler");
    free(file_data);

    RobotsTxt_free_directives(directives);

    // we attempted to parse a file with nul characters, so if we manage to
    // return without any memory corruption bugs, that means we pretty much passed the test

    return 0;
}
