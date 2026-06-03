cmake_minimum_required(VERSION 3.10)

project(flutter_eddsa_library VERSION 0.0.1 LANGUAGES C)

include(CheckCCompilerFlag)
include(CheckPrototypeDefinition)

option(USE_STACKCLEAN "Zero secret variables from stack after use" ON)

check_prototype_definition(memset_s
  "errno_t memset_s(void *dest, rsize_t destsz, int ch, rsize_t count)"
  "0" "string.h" HAVE_MEMSET_S)

check_prototype_definition(explicit_bzero
  "void explicit_bzero(void *b, size_t len)"
  "" "string.h" HAVE_EXPLICIT_BZERO)

if(NOT WIN32 AND NOT CYGWIN)
  check_c_compiler_flag("-fvisibility=hidden" HAVE_VISIBILITY)
endif()

set(CRYPTO_SRC
  crypto/fld.c
  crypto/sc.c
  crypto/ed.c
  crypto/sha512.c
  crypto/ed25519-sha512.c
  crypto/x25519.c
)

if(USE_STACKCLEAN)
  list(APPEND CRYPTO_SRC crypto/burn.c crypto/burnstack.c)
endif()

add_library(flutter_eddsa SHARED ${CRYPTO_SRC})

target_include_directories(flutter_eddsa PUBLIC crypto/)

set_target_properties(flutter_eddsa PROPERTIES OUTPUT_NAME "flutter_eddsa")

if(UNIX)
  target_compile_options(flutter_eddsa PRIVATE
    -std=c99 -fwrapv -Wall -Wextra -pedantic -O3)
endif()

target_compile_definitions(flutter_eddsa PRIVATE EDDSA_BUILD DART_SHARED_LIB)

if(USE_STACKCLEAN)
  target_compile_definitions(flutter_eddsa PRIVATE USE_STACKCLEAN)
endif()
if(HAVE_MEMSET_S)
  target_compile_definitions(flutter_eddsa PRIVATE HAVE_MEMSET_S)
endif()
if(HAVE_EXPLICIT_BZERO)
  target_compile_definitions(flutter_eddsa PRIVATE HAVE_EXPLICIT_BZERO)
endif()
if(HAVE_VISIBILITY)
  target_compile_definitions(flutter_eddsa PRIVATE HAVE_VISIBILITY)
  target_compile_options(flutter_eddsa PRIVATE -fvisibility=hidden)
endif()

if(ANDROID)
  target_link_options(flutter_eddsa PRIVATE "-Wl,-z,max-page-size=16384")
endif()
