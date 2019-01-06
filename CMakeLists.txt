cmake_minimum_required(VERSION 2.6)
project(pcap)

include_directories(${CMAKE_SOURCE_DIR}/include)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR})

include(FindPCAP.cmake)

set(SOURCE_FILES main.cpp PacketParser.cpp)
add_executable(pcap ${SOURCE_FILES})
target_link_libraries(pcap ${PCAP_LIBRARY})
