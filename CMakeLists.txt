cmake_minimum_required(VERSION 3.0)

project(dhcpd)

add_subdirectory(src/dhcp-pkt)

add_subdirectory(src/network)

add_subdirectory(src/dhcp-lease)

add_subdirectory(src/cli)

add_subdirectory(src/main)
