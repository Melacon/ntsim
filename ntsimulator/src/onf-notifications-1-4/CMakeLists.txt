set (NOTIFICATIONS_SOURCES
    onf-notifications.c
)

include_directories(
    "/usr/include/x86_64-linux-gnu"
    "/usr/local/include/cjson"
)

add_executable(onf-notifications ${NOTIFICATIONS_SOURCES})
target_link_libraries(onf-notifications utils)
target_link_libraries(onf-notifications sysrepo)
target_link_libraries(onf-notifications m)
target_link_libraries(onf-notifications curl)
target_link_libraries(onf-notifications cjson)

install(TARGETS onf-notifications DESTINATION ${CMAKE_INSTALL_BINDIR})