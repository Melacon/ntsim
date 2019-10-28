set (VES_MESSAGES_SOURCES
    heartbeat.c
)

include_directories(
    "/usr/include/x86_64-linux-gnu"
    "/usr/local/include/cjson"
    "${PROJECT_SOURCE_DIR}/inc/utils"
)

add_executable(ves-heartbeat ${VES_MESSAGES_SOURCES})
target_link_libraries(ves-heartbeat utils)
target_link_libraries(ves-heartbeat sysrepo)
target_link_libraries(ves-heartbeat curl)
target_link_libraries(ves-heartbeat cjson)

install(TARGETS ves-heartbeat DESTINATION ${CMAKE_INSTALL_BINDIR})