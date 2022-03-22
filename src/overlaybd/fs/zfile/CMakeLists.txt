file(GLOB SOURCE_ZFILE "*.cpp")
file(GLOB SOURCE_LZ4 "lz4/lz4.c")
file(GLOB SOURCE_CRC32 "crc32/crc32c.cpp")

set (CMAKE_CXX_STANDARD 17)
add_custom_command(OUTPUT dml
    PRE_BUILD
    COMMAND rm -rf DML/
    COMMAND git clone --recursive https://github.com/intel/DML.git
    COMMAND cd DML && git checkout 5a2956362d7b1c65d8aee753938ae9bf5cf0b7fd
    COMMAND cd DML && mkdir build && cd build && cmake -DCMAKE_BUILD_TYPE=Release ..
    COMMAND cd DML && cd build && sudo cmake --build . --target install
    VERBATIM
)
add_custom_command(OUTPUT isal
    PRE_BUILD
    COMMAND rm -rf isa-l/
    COMMAND git clone --recursive https://github.com/intel/isa-l.git
    COMMAND cd isa-l && git checkout ad8dce15c6d3f0c7f3d1b486d9c649ed39223b45
    COMMAND cd isa-l && ./autogen.sh
    COMMAND cd isa-l && ./configure
    COMMAND cd isa-l && make
    COMMAND cd isa-l && sudo make install
    VERBATIM
)
add_library(zfile_lib STATIC dml isal ${SOURCE_ZFILE} ${SOURCE_LZ4} ${SOURCE_CRC32})
target_link_libraries(zfile_lib -ldmlhl -ldl -lpci -lisal)
target_compile_options(zfile_lib PUBLIC -msse4.2 -mcrc32 -mavx512f)
set (CMAKE_CXX_STANDARD 14)

if (BUILD_TESTING)
    add_subdirectory(test)
endif ()
