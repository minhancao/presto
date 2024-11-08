# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

execute_process(
    COMMAND git rev-parse HEAD
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_COMMIT_HASH
    RESULT_VARIABLE GIT_RESULT_HASH
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

execute_process(
    COMMAND git rev-parse --abbrev-ref HEAD
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_BRANCH_NAME
    RESULT_VARIABLE GIT_RESULT_BRANCH
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Fallbacks if Git commands fail or are in detached HEAD
if(NOT GIT_RESULT_HASH EQUAL 0)
    set(GIT_COMMIT_HASH "unknown")
endif()

if(NOT GIT_RESULT_BRANCH EQUAL 0 OR GIT_BRANCH_NAME STREQUAL "HEAD")
    set(GIT_BRANCH_NAME "unknown")
endif()

set(VERSION_HEADER_PATH "${CMAKE_CURRENT_SOURCE_DIR}/Presto_git_build_version.h")
set(GENERATED_HEADER_CONTENT "/* Generated file - do not change */\n#pragma once\n#define BUILD_GIT_COMMIT \"${GIT_COMMIT_HASH}\"\n#define BUILD_GIT_BRANCH \"${GIT_BRANCH_NAME}\"\n")


# Only write the file if content changed
if(EXISTS "${VERSION_HEADER_PATH}")
    file(READ "${VERSION_HEADER_PATH}" EXISTING_HEADER_CONTENT)
else()
    set(EXISTING_HEADER_CONTENT "")
endif()

if(NOT "${EXISTING_HEADER_CONTENT}" STREQUAL "${GENERATED_HEADER_CONTENT}")
    file(WRITE "${VERSION_HEADER_PATH}" "${GENERATED_HEADER_CONTENT}")
endif()

add_library(ibm_signal_handler OBJECT IBMSignalHandler.cpp)
target_link_libraries(ibm_signal_handler presto_server_lib)


if(PRESTO_ENABLE_TESTING)
    add_subdirectory(tests)
endif()
