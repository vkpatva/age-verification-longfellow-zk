cmake_minimum_required(VERSION 3.13)
project(longfellow_cli CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Path to the google/longfellow-zk checkout
set(LF_ROOT "${CMAKE_SOURCE_DIR}/../../longfellow-zk/lib"
    CACHE PATH "Path to google/longfellow-zk/lib")

# ── compiler flags ─────────────────────────────────────────────────────────────
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
  set(ARCH_FLAGS -march=native -maes)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
  set(ARCH_FLAGS -march=armv8-a+crypto)
endif()
add_compile_options(${ARCH_FLAGS} -O2 -DOPENSSL_SUPPRESS_DEPRECATED=1)

# Suppress test-framework macros so the library sources compile without gtest.
add_compile_definitions(TESTING_MAIN_H_=1)

# ── include paths ──────────────────────────────────────────────────────────────
include_directories(${LF_ROOT})

# ── find system libraries ──────────────────────────────────────────────────────
find_library(CRYPTO_LIB  crypto
    PATHS /usr/lib/x86_64-linux-gnu /usr/lib /usr/local/lib
    REQUIRED)
find_library(ZSTD_LIB    zstd
    PATHS /usr/lib/x86_64-linux-gnu /usr/lib /usr/local/lib
    REQUIRED)

# Use Node.js-bundled OpenSSL headers if system dev headers are missing
find_path(OPENSSL_INCLUDE_DIR openssl/sha.h
    PATHS /usr/include
          "$ENV{HOME}/.nvm/versions/node/v22.18.0/include/node"
          "$ENV{HOME}/.cache/node-gyp/22.18.0/include/node")
if(OPENSSL_INCLUDE_DIR)
    include_directories(${OPENSSL_INCLUDE_DIR})
endif()

find_path(ZSTD_INCLUDE_DIR zstd.h
    PATHS /usr/include /usr/local/include)
if(ZSTD_INCLUDE_DIR)
    include_directories(${ZSTD_INCLUDE_DIR})
endif()

# ── collect all .cc sources needed by mdoc_static ─────────────────────────────
# (mirrors the dependency chain: mdoc → flatsha + ec + algebra + util)

file(GLOB ALGEBRA_SRC   ${LF_ROOT}/algebra/*.cc)
file(GLOB EC_SRC        ${LF_ROOT}/ec/*.cc)
file(GLOB UTIL_SRC      ${LF_ROOT}/util/*.cc)
file(GLOB GF2K_SRC      ${LF_ROOT}/gf2k/*.cc)
file(GLOB MERKLE_SRC    ${LF_ROOT}/merkle/*.cc)
file(GLOB ZK_SRC        ${LF_ROOT}/zk/*.cc)
file(GLOB LIGERO_SRC    ${LF_ROOT}/ligero/*.cc)
file(GLOB SUMCHECK_SRC  ${LF_ROOT}/sumcheck/*.cc)
file(GLOB RANDOM_SRC    ${LF_ROOT}/random/*.cc)
file(GLOB CBOR_SRC      ${LF_ROOT}/cbor/*.cc)
file(GLOB SHA_SRC       ${LF_ROOT}/circuits/sha/*.cc)
file(GLOB ECDSA_SRC     ${LF_ROOT}/circuits/ecdsa/*.cc)
file(GLOB LOGIC_SRC     ${LF_ROOT}/circuits/logic/*.cc)
file(GLOB MAC_SRC       ${LF_ROOT}/circuits/mac/*.cc)
file(GLOB CBORP_SRC     ${LF_ROOT}/circuits/cbor_parser/*.cc)
file(GLOB COMPILER_SRC  ${LF_ROOT}/circuits/compiler/*.cc)
file(GLOB MDOC_SRC      ${LF_ROOT}/circuits/mdoc/mdoc_zk.cc
                        ${LF_ROOT}/circuits/mdoc/mdoc_decompress.cc
                        ${LF_ROOT}/circuits/mdoc/mdoc_generate_circuit.cc
                        ${LF_ROOT}/circuits/mdoc/mdoc_circuit_id.cc
                        ${LF_ROOT}/circuits/mdoc/zk_spec.cc)

# Exclude test files
list(FILTER ALGEBRA_SRC  EXCLUDE REGEX ".*_test\\.cc$")
list(FILTER EC_SRC       EXCLUDE REGEX ".*_test\\.cc$")
list(FILTER UTIL_SRC     EXCLUDE REGEX ".*_test\\.cc$")
list(FILTER GF2K_SRC     EXCLUDE REGEX ".*_test\\.cc$")
list(FILTER MERKLE_SRC   EXCLUDE REGEX ".*_test\\.cc$")
list(FILTER ZK_SRC       EXCLUDE REGEX ".*_test\\.cc$")
list(FILTER LIGERO_SRC   EXCLUDE REGEX ".*_test\\.cc$")
list(FILTER SUMCHECK_SRC EXCLUDE REGEX ".*_test\\.cc$")
list(FILTER RANDOM_SRC   EXCLUDE REGEX ".*_test\\.cc$")
list(FILTER CBOR_SRC     EXCLUDE REGEX ".*_test\\.cc$")
list(FILTER SHA_SRC      EXCLUDE REGEX ".*_test\\.cc$")
list(FILTER ECDSA_SRC    EXCLUDE REGEX ".*_test\\.cc$")
list(FILTER LOGIC_SRC    EXCLUDE REGEX ".*_test\\.cc$")
list(FILTER MAC_SRC      EXCLUDE REGEX ".*_test\\.cc$")
list(FILTER CBORP_SRC    EXCLUDE REGEX ".*_test\\.cc$")
list(FILTER COMPILER_SRC EXCLUDE REGEX ".*_test\\.cc$")

set(ALL_LIB_SRC
    ${ALGEBRA_SRC} ${EC_SRC} ${UTIL_SRC} ${GF2K_SRC} ${MERKLE_SRC}
    ${ZK_SRC} ${LIGERO_SRC} ${SUMCHECK_SRC} ${RANDOM_SRC} ${CBOR_SRC}
    ${SHA_SRC} ${ECDSA_SRC} ${LOGIC_SRC} ${MAC_SRC} ${CBORP_SRC}
    ${COMPILER_SRC} ${MDOC_SRC}
)

add_executable(longfellow-cli
    ${CMAKE_SOURCE_DIR}/cli.cc
    ${ALL_LIB_SRC}
)

target_link_libraries(longfellow-cli
    ${CRYPTO_LIB}
    ${ZSTD_LIB}
    pthread
)

install(TARGETS longfellow-cli DESTINATION bin)
