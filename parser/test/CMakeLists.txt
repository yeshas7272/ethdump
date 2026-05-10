add_executable(test_parser test_parser.c)

target_link_libraries(test_parser
    PRIVATE
        unity
        parser
        ringbuff
)

target_include_directories(test_parser
    PRIVATE
        ../../utils
)

add_test(NAME test_parser COMMAND test_parser)
