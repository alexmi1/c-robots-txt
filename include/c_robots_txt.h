#ifndef PARSE_ROBOTS_TXT_H
#define PARSE_ROBOTS_TXT_H

#include <stdbool.h>
#include <stddef.h>

typedef enum {
    ROBOTS_TXT_ALLOW,
    ROBOTS_TXT_DISALLOW,
} RobotsTxt_RuleType;

typedef struct {
    RobotsTxt_RuleType type;
    char* path;
} RobotsTxt_Rule;

typedef struct {
    RobotsTxt_Rule* rules;
    size_t stored_count;
    size_t capacity;
} RobotsTxt_PathRules;

typedef struct {
    char** urls;
    size_t stored_count;
    size_t capacity;
} RobotsTxt_SitemapUrls;

typedef struct {
    RobotsTxt_PathRules allow_rules;
    RobotsTxt_PathRules disallow_rules;
    RobotsTxt_SitemapUrls sitemap_urls;
} RobotsTxt_Directives;

RobotsTxt_Directives* RobotsTxt_parse_directives(const char* data, const char* our_user_agent);
void RobotsTxt_free_directives(RobotsTxt_Directives* directives);
bool RobotsTxt_is_path_allowed(const RobotsTxt_Directives* directives, const char* url_path);

#endif // PARSE_ROBOTS_TXT_H
