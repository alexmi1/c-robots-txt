#include "c_robots_txt.h"

// if this is a tests build, then expose all our normally private functions
// as long as they were marked as TESTABLE instead of static
#ifdef MAKE_TESTS
  #define TESTABLE
#else
  #define TESTABLE static
#endif

// define these macros before #include if you wish to use your own allocation functions
#ifndef C_ROBOTS_TXT_MALLOC
#include <stdlib.h>
#define C_ROBOTS_TXT_MALLOC malloc
#endif
#ifndef C_ROBOTS_TXT_CALLOC
#include <stdlib.h>
#define C_ROBOTS_TXT_CALLOC calloc
#endif
#ifndef C_ROBOTS_TXT_REALLOC
#include <stdlib.h>
#define C_ROBOTS_TXT_REALLOC realloc
#endif
#ifndef C_ROBOTS_TXT_FREE
#include <stdlib.h>
#define C_ROBOTS_TXT_FREE free
#endif

#ifdef ENABLE_DEBUG_PRINT
  #include <stdio.h>
  #define DEBUG_PRINT(format, ...) \
      do { if (ENABLE_DEBUG_PRINT) fprintf(stderr, "DEBUG: " format, ##__VA_ARGS__); } while (0)
#else
  #define DEBUG_PRINT(format, ...) ((void)0)
#endif

// Mostly compliant with RFC 9309, but not 100%
// https://www.rfc-editor.org/rfc/rfc9309.html

// note that since this is not a compiler or anything like that, our job is NOT to validate if the robots.txt file is
// actually correct, but to interpret it as best as we can, ignoring any errors, unexpected tokens or weird stuff in general.
// the only exception to this is the NUL character, but that's ok, that means the file is either malicious or corrupted anyway.
// in that case, we may stop parsing early

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

// internal structs
typedef struct {
    bool should_keep_agent_matched;
    bool was_our_user_agent_matched;        // true even if matching a * wildcard (but won't trigger if we had an exact UA match before)
    bool was_our_user_agent_ever_matched;   // only true if we had an *exact* match before
    RobotsTxt_Directives* directives;
} ParserState;

typedef struct {
    bool matched;
    size_t path_chars_matched;
    size_t rule_chars_matched;
} RuleMatchResult;

typedef struct {
    bool matched;
    size_t longest_path;
} PathRulesMatchResult;

typedef enum {
    ROBOTS_TXT_OK = 0,
    ROBOTS_TXT_OUT_OF_MEMORY,
} RobotsTxt_Error;

// here "failable" means something bad could happen, like running out of memory
typedef struct {
    bool parsed;
    RobotsTxt_Error error;
} FailableParseResult;

// internal functions
static RobotsTxt_Error parse_line(ParserState* parser_state, const char** cursor, const char* our_user_agent);
static RobotsTxt_Error rules_append(RobotsTxt_PathRules* rules, RobotsTxt_RuleType rule_type, const char* path, size_t path_length);
static void rules_free(RobotsTxt_PathRules* rules);         // completely frees the rules object
static void rules_discard(RobotsTxt_PathRules* rules);      // destroys any pre-existing rules, but does not destroy the rules object
static RobotsTxt_Error sitemap_urls_append(RobotsTxt_SitemapUrls* urls, const char* url, size_t url_length);
static void sitemap_urls_free(RobotsTxt_SitemapUrls* urls);
static bool parse_user_agent(ParserState* parser_state, const char** cursor, const char* our_user_agent);
static FailableParseResult parse_allow(ParserState* parser_state, const char** cursor);
static FailableParseResult parse_disallow(ParserState* parser_state, const char** cursor);
static FailableParseResult parse_sitemap_url(ParserState* parser_state, const char** cursor);
static bool try_to_match_string(const char* cursor, const char* string);
static bool try_to_match_char(const char* cursor, const char character);
static void move_cursor_to_next_nonwhitespace(const char** cursor);
static void move_cursor_to_next_line_or_end(const char** cursor);
static PathRulesMatchResult match_rules(const RobotsTxt_PathRules* rules, const char* path);
TESTABLE RuleMatchResult match_one_rule(const char* path, const char* rule);

// NOTE: this assumes data is null-terminated
// parses a robots.txt file and extracts all relevant directives for the specified user agent
RobotsTxt_Directives* RobotsTxt_parse_directives(const char* data, const char* our_user_agent) {
    // point cursor to beginning of data
    const char* cursor = data;

    RobotsTxt_Directives* directives = C_ROBOTS_TXT_CALLOC(1, sizeof(RobotsTxt_Directives));
    if (directives == NULL) { return NULL; }

    ParserState parser_state = { .directives = directives };

    // if for some reason there's a random NUL character in the middle of the data at the start of a line, we would
    // stop parsing prematurely, but that shouldn't cause any major issues or bugs, the data is just malformed and it's
    // not our fault
    while (*cursor != '\0') {
        RobotsTxt_Error err = parse_line(&parser_state, &cursor, our_user_agent);
        if (err == ROBOTS_TXT_OUT_OF_MEMORY) {
            RobotsTxt_free_directives(directives);
            return NULL;
        }
    }

    return directives;
}

void RobotsTxt_free_directives(RobotsTxt_Directives* parsed_directives) {
    rules_free(&parsed_directives->allow_rules);
    rules_free(&parsed_directives->disallow_rules);
    sitemap_urls_free(&parsed_directives->sitemap_urls);
    C_ROBOTS_TXT_FREE(parsed_directives);
}

// path is only the "path" part of a url after the hostname, including the initial / slash
bool RobotsTxt_is_path_allowed(const RobotsTxt_Directives* directives, const char* path) {
    bool should_allow = true;

    DEBUG_PRINT("computing should_allow for %s ...\n", path);

    // I think both the webmaster and web crawler are supposed to use percent encoded urls, and that
    // shouldn't be handled inside here in the parser. hope I'm not wrong

    const RobotsTxt_PathRules* allow_rules = &directives->allow_rules;
    const RobotsTxt_PathRules* disallow_rules = &directives->disallow_rules;

    PathRulesMatchResult allow_rules_match = match_rules(allow_rules, path);
    PathRulesMatchResult disallow_rules_match = match_rules(disallow_rules, path);

    if (!allow_rules_match.matched && !disallow_rules_match.matched) {
        // default to allow. don't really need this assignment again but it's fine
        should_allow = true;
    } else if (allow_rules_match.matched && !disallow_rules_match.matched) {
        should_allow = true;
    } else if (allow_rules_match.matched && disallow_rules_match.matched) {
        // prioritize the rule with the longest path, pick allow if both are equal
        if (allow_rules_match.longest_path >= disallow_rules_match.longest_path) {
            should_allow = true;
        } else {
            should_allow = false;
        }
    } else if (!allow_rules_match.matched && disallow_rules_match.matched) {
        should_allow = false;
    }

    return should_allow;
}

static PathRulesMatchResult match_rules(const RobotsTxt_PathRules* rules, const char* path) {
    bool matched = false;
    size_t current_longest_path = 0;

    for (size_t i = 0; i < rules->stored_count; ++i) {
        // checking length like this is kind of sus, could maybe optimize in the future
        size_t rule_length = strlen(rules->rules[i].path);

        if (current_longest_path > rule_length) {
            // we already matched a more specific path, skip but keep iterating,
            // so that we can know the length of the most specific matching path
            continue;
        }

        RuleMatchResult path_matching_result = match_one_rule(path, rules->rules[i].path);
        DEBUG_PRINT("matched: %d | rule_chars_matched: %zu\n", path_matching_result.matched, path_matching_result.rule_chars_matched);
        DEBUG_PRINT("path: %s\n", path);
        DEBUG_PRINT("rule: %s\n", rules->rules[i].path);
        char rule_current_char = rules->rules[i].path[path_matching_result.rule_chars_matched - 1];
        char path_current_char = path[path_matching_result.path_chars_matched - 1];
        char rule_next_char = rules->rules[i].path[path_matching_result.rule_chars_matched];
        char path_next_char = path[path_matching_result.path_chars_matched];
        // DEBUG_PRINT("next char for rule is: %c\n", rule_next_char);
        if (rule_next_char == '\0' && path_matching_result.matched) {
            matched = true;
            current_longest_path = rule_length;
        } else if (rule_next_char == '$' && path_next_char == '\0' && (rule_current_char == path_current_char)) {
            DEBUG_PRINT("we matched a $\n");
            matched = true;
            current_longest_path = rule_length;
        }
    }

    return (PathRulesMatchResult) { matched, current_longest_path };
}

TESTABLE RuleMatchResult match_one_rule(const char* path, const char* rule) {
    size_t path_offset = 0;
    size_t rule_offset = 0;
    
    int wildcard_pos = -1; // hope you don't pass in a humongously big rule
    size_t wild_matched_path_pos = 0;
    bool was_match_succesful = false;

    while (path[path_offset] != '\0' && rule[rule_offset] != '\0') {
        if ((rule[rule_offset]) && (rule[rule_offset] == path[path_offset])) {
            // normal character match
            path_offset++;
            rule_offset++;
        } else if ((rule[rule_offset]) && rule[rule_offset] == '*') {
            // found * wildcard, save its position and the path position
            wildcard_pos = rule_offset;
            wild_matched_path_pos = path_offset;
            rule_offset++;
        } else if (wildcard_pos != -1) {
            // backtrack to the last * wildcard position and try a different match
            rule_offset = wildcard_pos + 1;
            wild_matched_path_pos++;
            path_offset = wild_matched_path_pos;
        } else {
            // we tried, but we know we can't find a way to match anymore, give up early
            was_match_succesful = false;
            return (RuleMatchResult) { was_match_succesful, path_offset, rule_offset };
        }
    }

    // ignore any remaining * wildcards at the end, they don't really do anything
    while ((rule[rule_offset]) && rule[rule_offset] == '*') {
        rule_offset++;
    }

    // DEBUG_PRINT("%zu %zu %d %zu\n", path_offset, rule_offset, wildcard_pos, wild_matched_path_pos);

    // if both our path and the rule succesfully reached the end of their respective
    // strings, we know it was a match
    was_match_succesful = (rule[rule_offset] == '\0');
    return (RuleMatchResult) { was_match_succesful, path_offset, rule_offset };
}

// NOTE: "path" may or may not be null-terminated here, and "path_length" should NOT include the null terminator
static RobotsTxt_Error rules_append(RobotsTxt_PathRules* rules, RobotsTxt_RuleType rule_type, const char* path, size_t path_length) {
    if (path_length <= 0) { return ROBOTS_TXT_OK; } // empty path, do nothing
    char* copied_path = C_ROBOTS_TXT_MALLOC(sizeof(char) * (path_length + 1));
    if (copied_path == NULL) { return ROBOTS_TXT_OUT_OF_MEMORY; }
    memcpy(copied_path, path, path_length);
    copied_path[path_length] = '\0';

    // DEBUG_PRINT("appending rule: %s\n", path);

    if (rules->stored_count >= rules->capacity) {
        size_t new_capacity = rules->capacity + 10;
        rules->rules = C_ROBOTS_TXT_REALLOC(rules->rules, sizeof(RobotsTxt_Rule) * new_capacity);
        if (rules->rules == NULL) {
            // do NOT free this here, it will be handled further up the call stack
            // C_ROBOTS_TXT_FREE(old_rules);
            // but we should free copied_path as it couldn't be referenced in a new rule yet
            C_ROBOTS_TXT_FREE(copied_path);
            return ROBOTS_TXT_OUT_OF_MEMORY;
        }
        rules->capacity = new_capacity;
    }

    RobotsTxt_Rule new_rule = { .type = rule_type, .path = copied_path };
    rules->rules[rules->stored_count] = new_rule;
    rules->stored_count += 1;

    return ROBOTS_TXT_OK;
}

static void rules_free(RobotsTxt_PathRules* rules) {
    // free path strings from rules
    for (size_t i = 0; i < rules->stored_count; ++i) {
        RobotsTxt_Rule rule = rules->rules[i];
        C_ROBOTS_TXT_FREE(rule.path);
    }

    // free array of rules
    C_ROBOTS_TXT_FREE(rules->rules);

    // reset state
    rules->rules = NULL;
    rules->stored_count = 0;
    rules->capacity = 0;
}

// this does *not* free the PathRules object
static void rules_discard(RobotsTxt_PathRules* rules) {
    // free path strings from rules
    for (size_t i = 0; i < rules->stored_count; ++i) {
        RobotsTxt_Rule rule = rules->rules[i];
        C_ROBOTS_TXT_FREE(rule.path);
    }

    // there's no point in reallocing rules->rules here

    // only reset the internal counter, keep capacity intact
    rules->stored_count = 0;
}

static RobotsTxt_Error sitemap_urls_append(RobotsTxt_SitemapUrls* urls, const char* url, size_t url_length) {
    if (url_length <= 0) { return ROBOTS_TXT_OK; } // empty url, do nothing
    char* copied_url = C_ROBOTS_TXT_MALLOC(sizeof(char) * (url_length + 1));
    if (copied_url == NULL) { return ROBOTS_TXT_OUT_OF_MEMORY; }
    memcpy(copied_url, url, url_length);
    copied_url[url_length] = '\0';

    if (urls->stored_count >= urls->capacity) {
        size_t new_capacity = urls->capacity + 10;
        urls->urls = C_ROBOTS_TXT_REALLOC(urls->urls, sizeof(char*) * new_capacity);
        if (urls->urls == NULL) {
            // do NOT free this here, it will be handled further up the call stack
            // C_ROBOTS_TXT_FREE(old_urls);
            // but we should free copied_url as it couldn't be referenced yet
            C_ROBOTS_TXT_FREE(copied_url);
            return ROBOTS_TXT_OUT_OF_MEMORY;
        }
        urls->capacity = new_capacity;
    }

    urls->urls[urls->stored_count] = copied_url;
    urls->stored_count += 1;

    return ROBOTS_TXT_OK;
}

static void sitemap_urls_free(RobotsTxt_SitemapUrls* urls) {
    // free url strings from urls
    for (size_t i = 0; i < urls->stored_count; ++i) {
        char* url = urls->urls[i];
        C_ROBOTS_TXT_FREE(url);
    }

    // free array of urls
    C_ROBOTS_TXT_FREE(urls->urls);

    // reset state
    urls->urls = NULL;
    urls->stored_count = 0;
    urls->capacity = 0;
}

// NOTE: our cursor is a pointer to some point in the data, but since our functions could modify the cursor,
//       we instead pass a pointer to the cursor, so a const char**. but functions that just want to
//       read the cursor and not modify it will most likely take a const char* instead

// parses all relevant tokens until next line
static RobotsTxt_Error parse_line(ParserState* parser_state, const char** cursor, const char* our_user_agent) {

    bool parsed_user_agent = parse_user_agent(parser_state, cursor, our_user_agent);

    FailableParseResult sitemap_url_result = { 0 }; // init to 0 because I'm scared despite the || down below
    if (!parsed_user_agent) {
        sitemap_url_result = parse_sitemap_url(parser_state, cursor);
        if (sitemap_url_result.error) { return sitemap_url_result.error; }
    }

    bool did_anything_match = parsed_user_agent || sitemap_url_result.parsed;

    // no user-agent or sitemap token found on this line and our agent was matched before, so we should
    // parse any possible allow/disallow rules

    if (!did_anything_match && parser_state->was_our_user_agent_matched) {
        FailableParseResult allow_result = parse_allow(parser_state, cursor);
        if (allow_result.error) { return allow_result.error; }

        FailableParseResult disallow_result = { 0 };
        if (!allow_result.parsed) {
            disallow_result = parse_disallow(parser_state, cursor);
            if (disallow_result.error) { return disallow_result.error; }
        }

        did_anything_match = allow_result.parsed || disallow_result.parsed;
        if (did_anything_match) {
            parser_state->should_keep_agent_matched = false;
        }
    }

    // we couldn't parse anything valid, so our cursor wasn't moved, so let's move it to the next line
    if (!did_anything_match) {
        move_cursor_to_next_line_or_end(cursor);
    }

    return ROBOTS_TXT_OK;
}

static bool parse_user_agent(ParserState* parser_state, const char** cursor, const char* our_user_agent) {
    const char* TOKEN_USER_AGENT = "User-agent:";
    bool user_agent_token_found = try_to_match_string(*cursor, TOKEN_USER_AGENT);
    if (user_agent_token_found) {
        *cursor += strlen(TOKEN_USER_AGENT);

        if (parser_state->should_keep_agent_matched) {
            parser_state->was_our_user_agent_matched = true;
            move_cursor_to_next_line_or_end(cursor);
            return true;
        }

        move_cursor_to_next_nonwhitespace(cursor);
        bool wildcard_found = try_to_match_char(*cursor, '*');
        if (wildcard_found) {
            // if we already found an exact match before, just move on
            if (!parser_state->was_our_user_agent_ever_matched) {
                parser_state->was_our_user_agent_matched = true;
                parser_state->should_keep_agent_matched = true;
            }
            *cursor += 1;
            move_cursor_to_next_line_or_end(cursor);
        } else {
            size_t length = strlen(our_user_agent);
            bool agents_matched = (strncmp(*cursor, our_user_agent, length) == 0);
            if (agents_matched) {
                // discard previous rules, just in case we matched a * wildcard before
                if (!parser_state->was_our_user_agent_ever_matched) {
                    size_t allow_amount = parser_state->directives->allow_rules.stored_count;
                    size_t disallow_amount = parser_state->directives->disallow_rules.stored_count;
                    DEBUG_PRINT("discarding %zu allow and %zu disallow rules\n", allow_amount, disallow_amount);
                    rules_discard(&parser_state->directives->allow_rules);
                    rules_discard(&parser_state->directives->disallow_rules);
                }

                parser_state->was_our_user_agent_matched = true;
                parser_state->should_keep_agent_matched = true;
                parser_state->was_our_user_agent_ever_matched = true;
            } else {
                parser_state->was_our_user_agent_matched = false;
            }
            move_cursor_to_next_line_or_end(cursor);
         }

        return true;
    }

    return false;
}

static FailableParseResult parse_allow(ParserState* parser_state, const char** cursor) {
    FailableParseResult result = { false, ROBOTS_TXT_OK };
    const char* TOKEN_ALLOW = "Allow:";
    bool allow_token_found = try_to_match_string(*cursor, TOKEN_ALLOW);
    if (allow_token_found) {
        *cursor += strlen(TOKEN_ALLOW);
        move_cursor_to_next_nonwhitespace(cursor);
        size_t char_count_until_whitespace_or_comment = strcspn(*cursor, " #\n");
        RobotsTxt_Error err = rules_append(&(parser_state->directives->allow_rules), ROBOTS_TXT_ALLOW, *cursor, char_count_until_whitespace_or_comment);
        if (err) {
            result.error = err;
            return result;
        }
        move_cursor_to_next_line_or_end(cursor);
        result.parsed = true;
    } else {
        result.parsed = false;
    }

    return result;
}

static FailableParseResult parse_disallow(ParserState* parser_state, const char** cursor) {
    FailableParseResult result = { false, ROBOTS_TXT_OK };
    const char* TOKEN_DISALLOW = "Disallow:";
    bool disallow_token_found = try_to_match_string(*cursor, TOKEN_DISALLOW);
    if (disallow_token_found) {
        *cursor += strlen(TOKEN_DISALLOW);
        move_cursor_to_next_nonwhitespace(cursor);
        size_t char_count_until_whitespace_or_comment = strcspn(*cursor, " #\n");
        RobotsTxt_Error err = rules_append(&(parser_state->directives->disallow_rules), ROBOTS_TXT_DISALLOW, *cursor, char_count_until_whitespace_or_comment);
        if (err) {
            result.error = err;
            return result;
        }
        move_cursor_to_next_line_or_end(cursor);
        result.parsed = true;
    } else {
        result.parsed = false;
    }

    return result;
}

static FailableParseResult parse_sitemap_url(ParserState* parser_state, const char** cursor) {
    FailableParseResult result = { false, ROBOTS_TXT_OK };
    const char* TOKEN_SITEMAP = "Sitemap:";
    bool sitemap_token_found = try_to_match_string(*cursor, TOKEN_SITEMAP);
    if (sitemap_token_found) {
        *cursor += strlen(TOKEN_SITEMAP);
        move_cursor_to_next_nonwhitespace(cursor);
        size_t char_count_until_whitespace_or_comment = strcspn(*cursor, " #\n");
        RobotsTxt_Error err = sitemap_urls_append(&(parser_state->directives->sitemap_urls), *cursor, char_count_until_whitespace_or_comment);
        if (err) {
            result.error = err;
            return result;
        }
        move_cursor_to_next_line_or_end(cursor);
        result.parsed = true;
    } else {
        result.parsed = false;
    }

    return result;
}

static bool try_to_match_string(const char* cursor, const char* string) {
    int compare_result = strncmp(cursor, string, strlen(string));
    if (compare_result == 0) {
        return true;
    } else {
        return false;
    }
}

static bool try_to_match_char(const char* cursor, const char character) {
    if (*cursor == character) {
        return true;
    } else {
        return false;
    }
}

// this function does not consider \n as whitespace
static void move_cursor_to_next_nonwhitespace(const char** cursor) {
    size_t spots_to_advance = strspn(*cursor, " \f\r\t\v");
    *cursor += spots_to_advance;
}

static void move_cursor_to_next_line_or_end(const char** cursor) {
    const char* first_newline_char = strchr(*cursor, '\n');
    if (first_newline_char != NULL) {
        *cursor = first_newline_char + 1;
    } else {
        // we found no more newline chars until the end of the entire file, so this means
        // we're on the very last line, so let's move the cursor to the end of the string instead
        while (**cursor != '\0') {
            *cursor += 1;
        }
    }
}
