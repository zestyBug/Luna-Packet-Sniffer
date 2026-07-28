cmake_minimum_required(VERSION 3.24)

project(LunaPacketSnifferNative LANGUAGES CXX)

set(WINDIVERT_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../third_party/WinDivert/WinDivert-2.2.2-A")

add_library(LunaPacketSniffer.Native SHARED
    src/LunaPacketSnifferNative.cpp
    include/LunaPacketSnifferNative.h)

target_compile_features(LunaPacketSniffer.Native PRIVATE cxx_std_20)
target_compile_definitions(LunaPacketSniffer.Native PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_include_directories(LunaPacketSniffer.Native PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${WINDIVERT_ROOT}/include")
target_link_libraries(LunaPacketSniffer.Native PRIVATE "${WINDIVERT_ROOT}/x64/WinDivert.lib")

set_target_properties(LunaPacketSniffer.Native PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_SOURCE_DIR}/artifacts/native/Debug"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_SOURCE_DIR}/artifacts/native/Release")

add_custom_command(TARGET LunaPacketSniffer.Native POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${WINDIVERT_ROOT}/x64/WinDivert.dll"
        "$<TARGET_FILE_DIR:LunaPacketSniffer.Native>/WinDivert.dll"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${WINDIVERT_ROOT}/x64/WinDivert64.sys"
        "$<TARGET_FILE_DIR:LunaPacketSniffer.Native>/WinDivert64.sys")
