project(pkt)

add_library(${PROJECT_NAME}
    src/validate.c
    src/analyze.c
    src/generate.c
    src/core.c
)

add_library(lib::pkt ALIAS ${PROJECT_NAME})

target_include_directories(${PROJECT_NAME}
    PUBLIC ${PROJECT_SOURCE_DIR}/include
)

add_subdirectory(tests)