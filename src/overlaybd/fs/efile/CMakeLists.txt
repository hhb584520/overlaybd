file(GLOB SOURCE_EFILE "*.cpp")
file(GLOB SOURCE_RSA "rsa/rsa.c")



add_library(efile_lib STATIC  ${SOURCE_EFILE} ${SOURCE_RSA})
target_link_libraries(efile_lib)
target_compile_options(efile_lib PUBLIC -msse4.2)

if (BUILD_TESTING)
    add_subdirectory(test)
endif ()
