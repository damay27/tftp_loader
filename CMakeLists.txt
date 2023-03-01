cmake_minimum_required(VERSION 3.24)

include(pico_sdk_import.cmake)

project(tftp_loader CXX C ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
pico_sdk_init()

add_executable(tftp_loader
    tftp_loader.c
    tftp.c
    )

target_compile_definitions(tftp_loader PRIVATE
        WIFI_SSID=\"${WIFI_SSID}\"
        WIFI_PASSWORD=\"${WIFI_PASSWORD}\"
        )

pico_enable_stdio_usb(tftp_loader 1)
pico_enable_stdio_uart(tftp_loader 1)

pico_add_extra_outputs(tftp_loader)

target_include_directories(tftp_loader PRIVATE ${CMAKE_CURRENT_LIST_DIR} )

target_link_libraries(tftp_loader pico_cyw43_arch_lwip_threadsafe_background pico_stdlib)
