# c-robots-txt

A parser for [robots.txt](https://en.wikipedia.org/wiki/Robots.txt) files written in C.

- Supports `Allow:`, `Disallow:`, `User-agent:` and `Sitemap:` directives
- Supports `#` comments, `*` wildcards and `$` end-of-match characters
- Mostly complies with [RFC 9309](https://datatracker.ietf.org/doc/rfc9309/), but not entirely
- No dependencies

Due to the nature of robots.txt files, this parser will simply ignore and skip malformed or unexpected data, without communicating any errors.

## Building

Incorporate the corresponding .c and .h files into your build system and you're good to go.

There's a `meson.build` file in this repository, so you can add it as a subproject. For example, to build it as a static library:

```meson
c_robots_txt_proj = subproject('c-robots-txt', default_options: ['default_library=static'])
c_robots_txt_dep = c_robots_txt_proj.get_variable('c_robots_txt_dep')
# ... then use the dependency object
```

## Usage

To keep things simple, the API is currently meant to be used with a single user agent.

```c
#include "c_robots_txt.h"

int main(void) {
    // get the contents of a robots.txt file
    // (on your end, you should probably refuse to read more than X amount of data over the network)
    char* file_data = read_content_from_somewhere();

    // file_data must be a null-terminated string! a NUL character at the middle is ok, but it may stop parsing early
    RobotsTxtDirectives* parsed_directives = RobotsTxt_parse_directives(file_data, "MyUserAgent");
    if (parsed_directives == NULL) {
        // if somehow this operation fails to allocate memory, it will return a null pointer
        return -1;
    }

    // check if a particular path is allowed to be crawled or not
    bool is_allowed = RobotsTxt_is_path_allowed(parsed_directives, "/search");

    // note that you must only pass the "path" part of a url, not the entire url. if you're
    // using this library, you likely already have existing functionality to extract parts of
    // a url, so this library does not provide helper functions for that

    // iterate over sitemap urls found with the "Sitemap:" directive
    for (size_t i = 0; i < parsed_directives->sitemap_urls.stored_count; ++i) {
      // these may be invalid urls! again, you probably have url validation functionality in your application already
      const char* url = parsed_directives->sitemap_urls.urls[i];
      printf("%s\n", url);
    }

    // make sure to call RobotsTxt_free_directives() when you're done
    RobotsTxt_free_directives(parsed_directives);

    return 0;
}
```

## Tests

Parsing tests are added to the `tests` directory. To build and run them:

```sh
meson setup build -Dbuild_tests=true
cd build
meson test

# or if you already have an existing build directory, cd into it and set the option
# meson configure -Dbuild_tests=true
# meson test
```


There are also some fuzz targets included in the `fuzz` directory. To build them for use with [libfuzzer](https://llvm.org/docs/LibFuzzer.html):

```sh
# cd into this repo if you're not already inside
# cd subprojects/c-robots-txt

# NOTE: libfuzzer requires a matching version of clang, so you need to compile the fuzz targets with clang
CC=clang meson setup build -Dbuild_fuzz=true
# if you want to also change the default fuzzing time, set the "fuzzing_time" option:
# CC=clang meson setup build -Dbuild_fuzz=true -Dfuzzing_time=60

# if instead you want to configure the existing build directory, cd into it and run:
# meson configure -Dfuzzing_time=60

# build and run the tests while inside the build directory:
cd build
meson test
```

## Why write this in C?

I like C. Why not?

### Is this safe?

I don't know. Nobody does. It's C. Maybe? Probably? I hope so. This library is fairly small and there are tests and fuzzer targets included, so there's that.

## Known RFC 9309 violations

This is a non-exhaustive list of known non-compliance with RFC 9309. Some of it might be intentional, particularly in cases where the amount of affected websites not being parsed according to spec as a result is deemed to be too low.

- Strict case sensitivity for `User-agent:` directive. The RFC says it must be case-insensitive. Most websites seem to use exactly `User-agent:`, thankfully.
- `2.3.1.5 Crawlers MUST try to parse each line of the robots.txt file.` This is mostly the case with this library, *except* for the NUL character. If a NUL character is found somewhere, parsing may end before reaching the end of the file. In practice, this shouldn't be an issue. Also, the "Invalid characters" part in section 3 makes this ambiguous because of the "reject" verb.
- Section 2.2.1 permits only `a-z`, `A-Z`, `_` and `-` characters for user agents. This parser will consider almost any other character as valid, too.

## License

This library is available under the MIT License. See [LICENSE](LICENSE).

## Contributing

Please open an issue or PR for any suggestions or improvements.
