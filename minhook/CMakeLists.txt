cmake_minimum_required(VERSION 3.5)

project(minhook C)

add_library(minhook STATIC
    src/buffer.c
    src/hook.c
    src/trampoline.c
    src/hde/hde32.c
    src/hde/hde64.c
)
target_include_directories(minhook PUBLIC include)
