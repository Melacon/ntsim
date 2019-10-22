set (NTSIMULATOR_SOURCES
    ntsimulator-manager.c
    simulator-operations.c
)

include_directories(
    "/usr/include/x86_64-linux-gnu"
    "/usr/local/include/cjson"
)

add_executable(ntsimulator-manager ${NTSIMULATOR_SOURCES})
target_link_libraries(ntsimulator-manager utils)
target_link_libraries(ntsimulator-manager curl)
target_link_libraries(ntsimulator-manager cjson)
target_link_libraries(ntsimulator-manager sysrepo)

install(TARGETS ntsimulator-manager DESTINATION ${CMAKE_INSTALL_BINDIR})