/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <boost/filesystem.hpp>
#include <gtest/gtest.h>
#include "boost/process.hpp"
#include "presto_cpp/main/common/Exception.h"
#include "presto_cpp/main/common/Utils.h"
#include "velox/common/base/Exceptions.h"
#include "velox/common/file/File.h"
#include "velox/common/file/FileSystems.h"
#include "velox/exec/tests/utils/TempDirectoryPath.h"
#include "velox/exec/tests/utils/TempFilePath.h"

namespace fs = boost::filesystem;

using namespace facebook::velox;
using namespace facebook::velox::exec::test;

namespace facebook::presto::process {
namespace {
class IBMSignalHandlerTest : public testing::Test {
 protected:
  IBMSignalHandlerTest() {
    facebook::velox::filesystems::registerLocalFileSystem();
    etcDir_ = TempDirectoryPath::create();
    auto etcDirPath = etcDir_->getPath();
    fs_ = facebook::velox::filesystems::getFileSystem(etcDirPath, nullptr);
    writeToEtcFile("config.properties", kConfigPropertiesText_);
    writeToEtcFile("node.properties", kNodePropertiesText_);

    fs_->mkdir(fmt::format("{}/{}", etcDirPath, "catalog"));
    writeToEtcFile("catalog/hive.properties", kHivePropertiesText_);
    writeToEtcFile("catalog/iceberg.properties", kIcebergPropertiesText_);
    writeToEtcFile(
        "catalog/tpchstandard.properties", kTpchStandardPropertiesText_);
  }

  void writeToEtcFile(const std::string& filePath, const std::string& content) {
    auto propertiesFilePath =
        fmt::format("{}/{}", etcDir_->getPath(), filePath);
    auto writeFile = fs_->openFileForWrite(propertiesFilePath);
    writeFile->append(content);
    writeFile->close();
  }

  void start() {
    try {
      std::string prestoServerExecutablePath = findPrestoServerExecutablePath();
      std::vector<std::string> args = {
          "--logtostderr",
          "1",
          "--v",
          "1",
          "--etc_dir",
          etcDir_->getPath(),
          "--stack_dump_dir",
          kStackDumpDir};
      prestoServerProcess_ = std::make_shared<boost::process::child>(
          prestoServerExecutablePath, args);
    } catch (const std::exception& e) {
      LOG(INFO) << "Failed to launch Presto server: " << e.what();
    }
  }

  void stop() {
    if (prestoServerProcess_ && prestoServerProcess_->valid()) {
      prestoServerProcess_->terminate();
      prestoServerProcess_->wait();
    }
  }

  std::string findPrestoServerExecutablePath() {
    const std::string currentPath = fs::current_path().string();
    const std::string nativeBaseString = "/presto-native-execution";

    // Find the position of the "/presto-native-execution" substring.
    size_t pos = currentPath.find(nativeBaseString);

    // If found, extract the path up to "/presto-native-execution" and set to prestissimoTop.
    if (pos != std::string::npos) {
      const std::string prestissimoTop =
          currentPath.substr(0, pos + nativeBaseString.length());
      const std::string paths[] = {
          prestissimoTop +
              "/_build/debug/presto_cpp/main/presto_server",
          prestissimoTop +
              "/_build/release/presto_cpp/main/presto_server",
          prestissimoTop + "/presto_cpp/main/presto_server"};

      for (const auto& path : paths) {
        if (fs::exists(path) && fs::is_regular_file(path)) {
          return path;
        }
      }
    }

    VELOX_FAIL("presto_server executable could not be found.");
  }

  std::string findDumpFileWithPid(const std::string& dumpDir, pid_t pid) {
    for (fs::directory_iterator entry(dumpDir);
         entry != fs::directory_iterator();
         ++entry) {
      if (fs::is_regular_file(entry->status()) &&
          entry->path().filename().string().find(
              "pid" + std::to_string(pid) + "_") != std::string::npos) {
        return entry->path().string();
      }
    }
    return "";
  }

  void sendSignalToProcessAndTest(int signal) {
    start();
    // Wait for PrestoServer process to finish starting up.
    std::this_thread::sleep_for(std::chrono::seconds(10));
    pid_t pid = 0;
    if (prestoServerProcess_) {
      pid = prestoServerProcess_->id();
      kill(pid, signal);
      // Wait for stack dump to be written to file.
      std::this_thread::sleep_for(std::chrono::seconds(20));
    }
    stop();

    std::string dumpFile = findDumpFileWithPid(kStackDumpDir, pid);
    ASSERT_TRUE(!dumpFile.empty());

    // Read the content of the stack dump file and check for the "Signum
    // received: %d" message.
    std::ifstream file(dumpFile);
    ASSERT_TRUE(file.is_open());

    std::ostringstream contentStream;
    contentStream << file.rdbuf();
    std::string fileContent = contentStream.str();

    ASSERT_TRUE(fileContent.find(fmt::format("Signum received: {}", signal)));
  }

  std::shared_ptr<::boost::process::child> prestoServerProcess_;
  std::shared_ptr<facebook::velox::filesystems::FileSystem> fs_;
  std::shared_ptr<facebook::velox::exec::test::TempDirectoryPath> etcDir_;
  const std::string kStackDumpDir = "/tmp";
  const std::string kConfigPropertiesText_ =
      "presto.version=testversion\n"
      "http-server.http.port=7777\n"
      "system-memory-gb=2\n";
  const std::string kNodePropertiesText_ =
      "node.environment=testing\n"
      "node.internal-address=127.0.0.1\n"
      "node.location=testing-location\n";
  const std::string kHivePropertiesText_ = "connector.name=hive\n";
  const std::string kIcebergPropertiesText_ = "connector.name=iceberg\n";
  const std::string kTpchStandardPropertiesText_ = "connector.name=tpch\n";
};

TEST_F(IBMSignalHandlerTest, readStackDumpSIGSEGV) {
  sendSignalToProcessAndTest(SIGSEGV);
}

TEST_F(IBMSignalHandlerTest, readStackDumpSIGILL) {
  sendSignalToProcessAndTest(SIGILL);
}

} // namespace
} // namespace facebook::presto::process
