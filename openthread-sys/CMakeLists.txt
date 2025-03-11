cmake_minimum_required(VERSION 3.16.0)
project(openthread VERSION 1.0.0)

# To avoid name clashes if these C functions are defined by some other library
add_definitions(-Dsnprintf=_support_snprintf -Dvsnprintf=_support_vsnprintf)

# OpenThread itself
add_subdirectory(./openthread)

# Custom C code (only `snprintf`/`vsnprintf` currently)
add_subdirectory(./gen/support)
