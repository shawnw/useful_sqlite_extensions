cmake_minimum_required(VERSION 3.5)
project("Useful Sqlite3 Extensions" LANGUAGES C VERSION 0.1)

find_package(ICU COMPONENTS data uc)
if(ICU_FOUND)
  add_library(string_funcs MODULE icu_extras.c stripaccents.c)
  set_target_properties(string_funcs PROPERTIES C_STANDARD 99)
  target_compile_options(string_funcs PRIVATE -Wall -Wextra)
  target_include_directories(string_funcs PRIVATE ${ICU_INCLUDE_DIRS})
  target_link_libraries(string_funcs ${ICU_LIBRARIES})
endif()

add_library(math_funcs MODULE math_funcs.c)
set_target_properties(math_funcs PROPERTIES C_STANDARD 99)
target_compile_options(math_funcs PRIVATE -Wall -Wextra)

add_library(nss_tables MODULE nss_tables.c passwd.c group.c)
set_target_properties(nss_tables PROPERTIES C_STANDARD 99)
target_compile_options(nss_tables PRIVATE -Wall -Wextra)
