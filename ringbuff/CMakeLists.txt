add_library(ringbuff STATIC ringbuff.c)

target_include_directories(ringbuff
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(ringbuff
    PRIVATE
        pthread
)
