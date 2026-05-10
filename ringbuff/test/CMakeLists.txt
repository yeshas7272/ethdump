add_executable(test_ringbuff test_ringbuff.c)

target_link_libraries(test_ringbuff
    PRIVATE
        unity
        ringbuff
        pthread
)

add_test(NAME test_ringbuff COMMAND test_ringbuff)
