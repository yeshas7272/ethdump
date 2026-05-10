cmake_minimum_required(VERSION 3.16)
project(ethdump C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Prevent in-source builds
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
  message(FATAL_ERROR "In-source builds are not allowed. Run cmake from a build/ directory.")
endif()

set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_C_FLAGS_DEBUG "-g -O2 -Wall -Wextra")

# Find libpcap
find_library(PCAP_LIB pcap REQUIRED)
find_path(PCAP_INCLUDE_DIR pcap.h REQUIRED)

add_subdirectory(ringbuff)
add_subdirectory(capture)
add_subdirectory(parser)

add_executable(ethdump main.c)

target_include_directories(ethdump 
    PRIVATE 
      include 
      utils
      ${PCAP_INCLUDE_DIR})
target_link_libraries(ethdump PRIVATE
    ringbuff
    capture
    parser
    ${PCAP_LIB}
    pthread
)