project(pkttest)

add_library(${PROJECT_NAME}
    src/tests.c
)

add_library(lib::pkttests ALIAS ${PROJECT_NAME})

target_include_directories(${PROJECT_NAME}
    PUBLIC ${PROJECT_SOURCE_DIR}/include
)