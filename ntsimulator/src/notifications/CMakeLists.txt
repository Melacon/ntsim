set (NOTIFICATIONS_SOURCES
    notifications.c
)

include_directories(
    "/usr/include/x86_64-linux-gnu"
    "/usr/local/include/cjson"
)

add_executable(notifications ${NOTIFICATIONS_SOURCES})
target_link_libraries(notifications utils)
target_link_libraries(notifications sysrepo)
target_link_libraries(notifications m)
target_link_libraries(notifications curl)
target_link_libraries(notifications cjson)

install(TARGETS notifications DESTINATION ${CMAKE_INSTALL_BINDIR})