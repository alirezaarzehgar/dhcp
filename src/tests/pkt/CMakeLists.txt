project(pkttest)

add_library(${PROJECT_NAME}
    src/validate_test.c
    src/analyze_test.c
    src/generation_test.c
)

add_library(lib::pkttests ALIAS ${PROJECT_NAME})

target_include_directories(${PROJECT_NAME}
    PUBLIC ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(${PROJECT_NAME}
    lib::pkt
)