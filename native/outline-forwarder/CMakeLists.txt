cmake_minimum_required(VERSION 3.22.1)
project(outline_forwarder_probe LANGUAGES C)

add_library(outline_forwarder_probe SHARED src/main/c/outline_forwarder_probe.c)
target_compile_features(outline_forwarder_probe PRIVATE c_std_11)
target_compile_options(outline_forwarder_probe PRIVATE -Wall -Wextra -Werror -fvisibility=hidden)
