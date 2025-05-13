#include "c_robots_txt.h"
#include "test-utils.h"

#include <assert.h>
#include <stdbool.h>
#include <string.h>

int main(void) {
    char* file_data = Utils_read_robots_file("../tests/test-files/general-parsing.txt");
    RobotsTxt_Directives* directives = RobotsTxt_parse_directives(file_data, "OurCrawler");
    free(file_data);

    // allow has priority over disallow
    bool allow_search = RobotsTxt_is_path_allowed(directives, "/search");
    assert(allow_search == true);

    // /exact$ is more specific than /exact
    bool allow_exact = RobotsTxt_is_path_allowed(directives, "/exact");
    assert(allow_exact == false);

    bool allow_match_and_allow = RobotsTxt_is_path_allowed(directives, "/MATCH_AND_ALLOW");
    assert(allow_match_and_allow == true);

    bool allow_no_match_and_allow = RobotsTxt_is_path_allowed(directives, "/NO_MATCH_AND_ALLOW");
    assert(allow_no_match_and_allow == true);

    // user-agent grouping
    bool allow_group_match_and_disallow = RobotsTxt_is_path_allowed(directives, "/GROUP_MATCH_AND_DISALLOW");
    assert(allow_group_match_and_disallow == false);

    // wasn't matched, but we should allow by default anyway
    bool allow_img = RobotsTxt_is_path_allowed(directives, "/img");
    assert(allow_img == true);

    // /hello (our path) shouldn't match /hello/ (the rule), so we are allowed
    bool allow_hello = RobotsTxt_is_path_allowed(directives, "/hello");
    assert(allow_hello == true);

    // should be allowed because according to the RFC, the * wildcard UA only
    // applies to any agent that's not explicitly mentioned elsewhere
    bool allow_disallow_for_generic_agent = RobotsTxt_is_path_allowed(directives, "/disallow_for_generic_agent");
    assert(allow_disallow_for_generic_agent == true);

    // believe it or not, this should match and be disallowed, according to the spec
    bool allow_number1234 = RobotsTxt_is_path_allowed(directives, "/number1234");
    assert(allow_number1234 == false);

    bool allow_hello_subdir = RobotsTxt_is_path_allowed(directives, "/hello/some_subdirectory");
    assert(allow_hello_subdir == false);

    // test if wildcard matching works
    bool allow_testing_wildcards_hi = RobotsTxt_is_path_allowed(directives, "/testing-wildcards---1-2-3-4-__///h/////hi");
    assert(allow_testing_wildcards_hi == false);

    // test sitemap parsing
    const char* SITEMAPS[] = {
        "https://www.example.com/first_sitemap.xml",
        "https://www.example.com/sitemap.xml",
        "https://www.example.com/some_subdir/sitemap.xml",
        "https://www.example.com/asdf/sitemaps_are_cool/sitemap.xml",
    };
    for (size_t i = 0; i < directives->sitemap_urls.stored_count; ++i) {
        const char* url = directives->sitemap_urls.urls[i];
        int compare_result = strcmp(url, SITEMAPS[i]);
        assert(compare_result == 0);
    }

    RobotsTxt_free_directives(directives);

    return 0;
}
