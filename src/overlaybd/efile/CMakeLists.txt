file(GLOB SOURCE_EFILE "*.cpp")
file(GLOB SOURCE_PLUGIN "plugin/*.cpp")

add_library(efile_lib STATIC ${SOURCE_EFILE} ${SOURCE_PLUGIN})
target_link_libraries(efile_lib photon_static)
target_compile_options(efile_lib PUBLIC -msse4.2)

target_include_directories(efile_lib PUBLIC
    ${PHOTON_INCLUDE_DIR}
)

if (BUILD_TESTING)
    add_subdirectory(test)
endif ()
