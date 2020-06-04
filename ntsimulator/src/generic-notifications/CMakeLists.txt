set (NOTIFICATIONS_SOURCES
    generic-notifications.c
)

include_directories(
    "/usr/include/x86_64-linux-gnu"
    "/usr/local/include/cjson"
    "/usr/local/include/libyang"
)

add_executable(generic-notifications ${NOTIFICATIONS_SOURCES})
target_link_libraries(generic-notifications utils)
target_link_libraries(generic-notifications sysrepo)
target_link_libraries(generic-notifications m)
target_link_libraries(generic-notifications curl)
target_link_libraries(generic-notifications cjson)
target_link_libraries(generic-notifications yang)

install(TARGETS generic-notifications DESTINATION ${CMAKE_INSTALL_BINDIR})