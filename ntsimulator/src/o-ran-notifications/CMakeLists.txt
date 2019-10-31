set (NOTIFICATIONS_SOURCES
    o-ran-notifications.c
)

include_directories(
    "/usr/include/x86_64-linux-gnu"
    "/usr/local/include/cjson"
)

add_executable(o-ran-notifications ${NOTIFICATIONS_SOURCES})
target_link_libraries(o-ran-notifications utils)
target_link_libraries(o-ran-notifications sysrepo)
target_link_libraries(o-ran-notifications m)
target_link_libraries(o-ran-notifications curl)
target_link_libraries(o-ran-notifications cjson)

install(TARGETS o-ran-notifications DESTINATION ${CMAKE_INSTALL_BINDIR})