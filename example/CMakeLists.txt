cmake_minimum_required(VERSION 3.2)

project(printer_status)

add_executable(printer_status main.cpp ../src/cxx_winapi.cpp)

set_target_properties(printer_status PROPERTIES
    CXX_STANDARD 14
    CXX_STANDARD_REQUIRED ON
    COMPILE_OPTIONS "-Wpedantic;-Wall;-Wextra;-Wno-missing-field-initializers"
)

target_link_libraries(printer_status
   setupapi
   winusb
   Advapi32
)

install(TARGETS printer_status DESTINATION bin)

