project(tests)

file(COPY fake_data DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

add_subdirectory(pkt)

add_subdirectory(network)

add_subdirectory(lease)

add_subdirectory(cli)

add_subdirectory(main)