add_library(parser STATIC parser.c)

target_include_directories(parser
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE
        ../utils
)

target_link_libraries(parser
    PRIVATE
        ringbuff
)
