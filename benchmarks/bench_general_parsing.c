#include "c_robots_txt.h"
#include "../tests/test-utils.h"

#include <stdbool.h>

int main(void) {
    // atm on my machine this takes 1.3 seconds, while a popular implementation in C++ takes
    // 5.478 seconds, YMMV of course. also this is not a realistic robots.txt file, but idk if
    // adding random websites' robots.txt files to this repo is allowed

    // I tried a rust port version of said library and it took 22.5 seconds while compiling
    // much slower, having bloated binaries etc etc. yes it was a release build

    // for proper benchmarking, could probably grab robots.txt files from CommonCrawl

    char* file_data = Utils_read_robots_file("../tests/test-files/general-parsing.txt");
    const int ITERATIONS = 1000000;
    for (int i = 0; i < ITERATIONS; ++i) {
        RobotsTxt_Directives* directives = RobotsTxt_parse_directives(file_data, "OurCrawler");
        volatile bool allowed = RobotsTxt_is_path_allowed(directives, "/string");
        RobotsTxt_free_directives(directives);
    }
    free(file_data);

    return 0;
}
