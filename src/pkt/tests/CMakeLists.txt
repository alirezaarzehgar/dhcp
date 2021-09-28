project(pkt_tests)

file(COPY fake_data DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/main)

add_subdirectory(pkt)

add_subdirectory(main)