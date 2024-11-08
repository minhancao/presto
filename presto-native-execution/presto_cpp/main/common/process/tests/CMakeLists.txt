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
add_executable(ibm_signal_handler_test IBMSignalHandlerTest.cpp)

add_test(ibm_signal_handler_test ibm_signal_handler_test)
set_tests_properties(ibm_signal_handler_test PROPERTIES
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/presto_cpp/main/common/process/tests)

target_link_libraries(
  ibm_signal_handler_test
  velox_exception
  velox_exec_test_lib
  GTest::gtest
  GTest::gtest_main)
