cmake_minimum_required(VERSION 3.14)
project(NetGuardian VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(net_guardian
    src/main.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/dpi_engine.cpp
)

target_include_directories(net_guardian PRIVATE include)
if(MSVC)
    target_compile_options(net_guardian PRIVATE /W4)
else()
    target_compile_options(net_guardian PRIVATE -Wall -Wextra -O2)
endif()
