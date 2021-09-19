project(networktest)

add_library(${PROJECT_NAME}
    src/tests.c
)

add_library(lib::networktests ALIAS ${PROJECT_NAME})

target_include_directories(${PROJECT_NAME}
    PUBLIC ${PROJECT_SOURCE_DIR}/include
)