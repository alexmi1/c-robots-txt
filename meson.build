project('c-robots-txt', 'c')

build_type = get_option('buildtype')
build_fuzz = get_option('build_fuzz')
build_tests = get_option('build_tests')

# not really using this right now
# if build_type == 'debug'
#   add_project_arguments('-DDEBUG', language: 'c')
# elif build_type == 'release'
#   add_project_arguments('-DNDEBUG', language: 'c')
# endif

if build_fuzz or build_tests
  add_project_arguments('-DMAKE_TESTS', language: 'c')
endif

override_opts = []
if (build_fuzz or build_tests) or (build_type == 'debug') or (build_type == 'debugoptimized')
  # this fixes weird linking failures with clang + sanitizers
  override_opts += 'b_lundef=false'
endif

c_robots_txt_include = include_directories('include')
c_robots_txt_lib = library('c-robots-txt',
  'src/c_robots_txt.c',
  include_directories : c_robots_txt_include,
  override_options : override_opts, 
)

c_robots_txt_dep = declare_dependency(
  link_with : c_robots_txt_lib,
  include_directories : c_robots_txt_include,
)

if build_fuzz == true
  fuzzing_time = get_option('fuzzing_time')
  # give them some extra time, like 5 seconds
  test_timeout_time = fuzzing_time + 5
  # for some reason I don't know, libfuzzer returns a 77 exit code on error by default, and 77 signifies "skip this test"
  fuzzing_args = [''.join('-max_total_time=', fuzzing_time.to_string()), '-error_exitcode=1']
  fuzz_c_args =['-fsanitize=fuzzer,address,undefined']
  fuzz_link_args = ['-fsanitize=fuzzer,address,undefined']

  fuzz_parse_directives = executable('test-fuzz-parse-directives', 'fuzz/fuzz_parse_directives.c',
    dependencies: [c_robots_txt_dep],
    c_args : fuzz_c_args,
    link_args : fuzz_link_args,
    override_options : override_opts,
  )
  test('fuzz-parse-directives', fuzz_parse_directives, args : fuzzing_args, timeout : test_timeout_time)

  fuzz_match_one_rule = executable('test-fuzz-match-one-rule', 'fuzz/fuzz_match_one_rule.c',
    dependencies: [c_robots_txt_dep],
    c_args : fuzz_c_args,
    link_args : fuzz_link_args,
    override_options : override_opts,
  )
  test('fuzz-match-one-rule', fuzz_match_one_rule, args : fuzzing_args, timeout : test_timeout_time)
endif

if build_tests == true
  test_c_args = ['-fsanitize=address,undefined']
  test_link_args = ['-fsanitize=address,undefined']

  general_parsing = executable('test-general-parsing', 'tests/general_parsing.c',
    dependencies: [c_robots_txt_dep],
    c_args : test_c_args,
    link_args : test_link_args,
  )
  test('general-parsing', general_parsing)

  nul_characters = executable('test-nul-characters', 'tests/nul_characters.c',
    dependencies: [c_robots_txt_dep],
    c_args : test_c_args,
    link_args : test_link_args,
  )
  test('nul-characters', nul_characters)
endif

