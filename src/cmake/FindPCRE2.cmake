# Quick and dirty module for PCRE2 stuff.


# Use may set ``PCRE2_ROOT` to a pcre2 installation root.

include(FindPackageHandleStandardArgs)

set(_PCRE2_SEARCHES)
if(PCRE2_ROOT)
  set(_PCRE2_SEARCH_ROOT PATHS ${PCRE2_ROOT} NO_DEFAULT_PATH)
  list(APPEND _PCRE2_SEARCHES _PCRE2_SEARCH_ROOT)
endif()

find_path(PCRE2_INCLUDE_DIR pcre2.h DOC "PCRE2 header" PATH_SUFFIXES include)
find_library(PCRE2_8 pcre2-8 DOC "UTF-8 version of PCRE2")
find_library(PCRE2_16 pcre2-16 DOC "UTF-16 version of PCRE2")

mark_as_advanced(PCRE2_INCLUDE_DIR)
find_package_handle_standard_args(Pcre2_8 REQUIRED_VARS
  PCRE2_8 PCRE2_INCLUDE_DIR)
find_package_handle_standard_args(Pcre2_16 REQUIRED_VARS
  PCRE2_8 PCRE2_INCLUDE_DIR)
