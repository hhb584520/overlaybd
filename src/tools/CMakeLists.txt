add_executable(overlaybd-commit overlaybd-commit.cpp)
target_include_directories(overlaybd-commit PUBLIC ${PHOTON_INCLUDE_DIR})
target_link_libraries(overlaybd-commit photon_static overlaybd_lib)

add_executable(overlaybd-create overlaybd-create.cpp)
target_include_directories(overlaybd-create PUBLIC ${PHOTON_INCLUDE_DIR})
target_link_libraries(overlaybd-create photon_static overlaybd_lib)

add_executable(overlaybd-zfile overlaybd-zfile.cpp)
target_include_directories(overlaybd-zfile PUBLIC ${PHOTON_INCLUDE_DIR})
target_link_libraries(overlaybd-zfile photon_static overlaybd_lib)

add_executable(overlaybd-efile overlaybd-efile.cpp)
target_include_directories(overlaybd-efile PUBLIC ${PHOTON_INCLUDE_DIR})
target_link_libraries(overlaybd-efile photon_static overlaybd_lib)

install(TARGETS
    overlaybd-commit
    overlaybd-create
    overlaybd-zfile
    overlaybd-efile
    DESTINATION /opt/overlaybd/bin
)
