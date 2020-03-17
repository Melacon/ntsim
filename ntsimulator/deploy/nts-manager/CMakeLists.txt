cmake_minimum_required(VERSION 2.8.12)
project(ntsimulator)
set(PROJECT_DESC "Network Topology Simulator using sysrepo and netopeer2")
include(GNUInstallDirs)

# setup version
set(NTSIMULATOR_MAJOR_VERSION 1)
set(NTSIMULATOR_MINOR_VERSION 1)
set(NTSIMULATOR_PATCH_VERSION 1)
set(NTSIMULATOR_VERSION ${NTSIMULATOR_MAJOR_VERSION}.${NTSIMULATOR_MINOR_VERSION}.${NTSIMULATOR_PATCH_VERSION})
set(NTSIMULATOR_SOVERSION ${NTSIMULATOR_MAJOR_VERSION}.${NTSIMULATOR_MINOR_VERSION})

# osx specific
set(CMAKE_MACOSX_RPATH TRUE)

# set default build type if not specified by user
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE debug)
endif()
string(TOLOWER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE_LOWER)

set(CMAKE_EXPORT_COMPILE_COMMANDS 1)

set(CMAKE_C_FLAGS         "${CMAKE_C_FLAGS} -Wall -Wpedantic -std=gnu11 -Wno-language-extension-token")
if(CMAKE_COMPILER_IS_GNUCC)
    # disable strict aliasing in GCC, since it produces false alarams in libev
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-strict-aliasing")
endif()
set(CMAKE_C_FLAGS_RELEASE "-DNDEBUG -O2")
set(CMAKE_C_FLAGS_DEBUG   "-g -O0")

if(NOT UNIX)
    message(FATAL_ERROR "Only Unix-like systems are supported.")
endif()

if(NOT DEFINED IS_DEVELOPER_CONFIGURATION)
    if(CMAKE_BUILD_TYPE_LOWER MATCHES "debug" AND NOT CMAKE_BUILD_TYPE_LOWER MATCHES "^rel")
        set(IS_DEVELOPER_CONFIGURATION true)
    else()
        set(IS_DEVELOPER_CONFIGURATION false)
    endif()
endif()

# location of system repository
if(${IS_DEVELOPER_CONFIGURATION})
    set(REPOSITORY_LOC "${CMAKE_BINARY_DIR}/repository" CACHE PATH "System repository location, contains configuration schema and data files.")
else()
    set(REPOSITORY_LOC "/etc/sysrepo" CACHE PATH "System repository location, contains configuration schema and data files.")
endif()

# include custom Modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")
include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories("${CMAKE_CURRENT_SOURCE_DIR}/inc")

# find required libraries
find_package(SYSREPO REQUIRED)
include_directories(${SYSREPO_INCLUDE_DIR})

# add subdirectories
add_subdirectory(src)

### NTS SPECIFIC ###
# Configure install file for NTS Manager
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/deploy/nts-manager/model-install.sh.in" "${PROJECT_BINARY_DIR}/model-install.sh" ESCAPE_QUOTES @ONLY)
### END NTS SPECIFIC ###

# find sysrepoctl
if (NOT SYSREPOCTL_EXECUTABLE)
    find_program(SYSREPOCTL_EXECUTABLE sysrepoctl)
endif()
if (NOT SYSREPOCTL_EXECUTABLE)
    message(FATAL_ERROR "Unable to find sysrepoctl, set SYSREPOCTL_EXECUTABLE manually.")
endif()

# find sysrepocfg
if (NOT SYSREPOCFG_EXECUTABLE)
    find_program(SYSREPOCFG_EXECUTABLE sysrepocfg)
endif()
if (NOT SYSREPOCFG_EXECUTABLE)
    message(FATAL_ERROR "Unable to find sysrepocfg, set SYSREPOCFG_EXECUTABLE manually.")
endif()

# Command line options to be passed to `sysrepoctl` when working with modules
# which should only be accessible by an administrator
if (NOT SYSREPOCTL_ROOT_PERMS)
    set(SYSREPOCTL_ROOT_PERMS "-o root:root -p 600")
endif()

install(CODE "
    set(ENV{SYSREPOCTL} ${SYSREPOCTL_EXECUTABLE})
    set(ENV{SYSREPOCFG} ${SYSREPOCFG_EXECUTABLE})
    set(ENV{SYSREPOCTL_ROOT_PERMS} SYSREPOCTL_ROOT_PERMS)
    execute_process(COMMAND ${PROJECT_BINARY_DIR}/model-install.sh)")



