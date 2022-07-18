file(GLOB SOURCE_EFILE "*.cpp")
file(GLOB SOURCE_AES "aes/aes.c")

add_library(efile_lib STATIC ${SOURCE_EFILE} ${SOURCE_AES})
target_link_libraries(efile_lib photon_static)
target_compile_options(efile_lib PUBLIC -msse4.2)

target_include_directories(efile_lib PUBLIC
    ${PHOTON_INCLUDE_DIR}
)

if (BUILD_TESTING)
    add_subdirectory(test)
endif ()
