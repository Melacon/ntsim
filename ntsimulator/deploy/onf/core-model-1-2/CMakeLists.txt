set(UTILS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/utils")

include_directories(
    "${PROJECT_SOURCE_DIR}/inc/utils" 
    "/usr/include"
)

add_subdirectory(onf-notifications-1-2)
add_subdirectory(generic-notifications)
add_subdirectory(ves-messages)

# sources
set (UTILS_SOURCES
    ${UTILS_DIR}/utils.c
)

add_library(utils STATIC ${UTILS_SOURCES})
set_property(TARGET utils PROPERTY COMPILE_FLAGS "-fPIC")
target_link_libraries(utils m)
target_link_libraries(utils cjson)