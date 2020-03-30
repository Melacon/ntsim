set (SW_MANAGEMENT_SOURCES
    sw-management-rpc.c
)

include_directories(
    "/usr/include/x86_64-linux-gnu"
    "/usr/local/include/cjson"
    "${PROJECT_SOURCE_DIR}/inc/utils"
)

add_executable(software-management ${SW_MANAGEMENT_SOURCES})
target_link_libraries(software-management utils)
target_link_libraries(software-management sysrepo)
target_link_libraries(software-management pthread)

install(TARGETS software-management DESTINATION ${CMAKE_INSTALL_BINDIR})