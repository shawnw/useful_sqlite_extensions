cmake_minimum_required(VERSION 3.5)
project("Useful Sqlite3 Extensions" LANGUAGES C VERSION 0.2)

include(FindPackageHandleStandardArgs)
set(CMAKE_THREAD_PREFER_PTHREAD 1)
find_package(Threads)
find_package(ZLIB)

find_package(ICU COMPONENTS data uc i18n)
if(ICU_FOUND)
  add_library(string_funcs MODULE icu_extras.c stripaccents.c egc_str_funcs.c
    more_str_funcs.c)
  set_target_properties(string_funcs PROPERTIES C_STANDARD 99
    C_STANDARD_REQUIRED ON)
  target_compile_options(string_funcs PRIVATE -Wall -Wextra)
  target_include_directories(string_funcs PRIVATE ${ICU_INCLUDE_DIRS})
  target_link_libraries(string_funcs ${ICU_LIBRARIES})
endif()

find_package(OpenSSL)
if(OpenSSL_FOUND)
  add_library(blob_funcs MODULE blob_funcs.c)
  set_target_properties(blob_funcs PROPERTIES C_STANDARD 99
    C_STANDARD_REQUIRED ON)
  target_compile_options(blob_funcs PRIVATE -Wall -Wextra)  
  target_include_directories(blob_funcs PRIVATE OpenSSL::Crypto ZLIB::ZLIB ${PROJECT_BINARY_DIR})
  target_link_libraries(blob_funcs OpenSSL::Crypto ZLIB::ZLIB Threads::Threads)
endif()

find_library(PCRE2_8 pcre2-8 DOC "UTF-8 version of PCRE2")
find_library(PCRE2_16 pcre2-16 DOC "UTF-16 version of PCRE2")
find_package_handle_standard_args(Pcre2_8 REQUIRED_VARS PCRE2_8)
find_package_handle_standard_args(Pcre2_16 REQUIRED_VARS PCRE2_16)
if(Pcre2_8_FOUND OR Pcre2_8_FOUND)
  add_library(pcre2_funcs MODULE pcre2_funcs.c)
  set_target_properties(blob_funcs PROPERTIES C_STANDARD 99
    C_STANDARD_REQUIRED ON)
  if(Pcre2_8_FOUND)
    set(HAVE_PCRE2_8 1)
    target_link_libraries(pcre2_funcs ${PCRE2_8})
  endif()
  if(Pcre2_16_FOUND)
    set(HAVE_PCRE2_16 1)
    target_link_libraries(pcre2_funcs ${PCRE2_16})
  endif()
  target_include_directories(pcre2_funcs PRIVATE "${PROJECT_BINARY_DIR}")
endif()

add_library(math_funcs MODULE math_funcs.c)
set_target_properties(math_funcs PROPERTIES C_STANDARD 99
  C_STANDARD_REQUIRED ON)
target_compile_options(math_funcs PRIVATE -Wall -Wextra)

add_library(bloom_filter1 MODULE bloom_filter.c)
set_target_properties(bloom_filter1 PROPERTIES C_STANDARD 99
  C_STANDARD_REQUIRED ON)
target_compile_options(bloom_filter1 PRIVATE -Wall -Wextra -Wno-implicit-fallthrough)

add_library(nss_tables MODULE nss_tables.c passwd.c group.c)
set_target_properties(nss_tables PROPERTIES C_STANDARD 99
  C_STANDARD_REQUIRED ON)
target_compile_options(nss_tables PRIVATE -Wall -Wextra)

add_library(json_funcs MODULE json_funcs.c cJSON.c)
set_target_properties(json_funcs PROPERTIES C_STANDARD 99
  C_STANDARD_REQUIRED ON)
target_compile_options(json_funcs PRIVATE -Wall -Wextra)

configure_file(config.h.in config.h)
