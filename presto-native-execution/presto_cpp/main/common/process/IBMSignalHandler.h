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

// This file was inspired by the stack dump implementation in Db2.

#pragma once

#include <folly/io/async/AsyncSignalHandler.h>
#include <signal.h> // For siginfo_t.
#include <sys/utsname.h> // For utsname.
#include <sys/ucontext.h> // For uccontext_t
#include <cstdarg> // For valist.
#include <cstdint> // For uint32_t.
#include <string>
#include "presto_cpp/main/TaskManager.h"
#include "velox/common/file/File.h"
#include "velox/common/file/FileSystems.h"

namespace facebook::presto::process {

typedef siginfo_t* siginfo_ptr;
#define INVALID_HANDLE_FD_VALUE -1
#define HANDPARMS int signum, siginfo_ptr sigcode, void *scp
#define HANDARGS signum, sigcode, scp

// Flags to choose what to dump.
/// Dump uname output.
#define STACKDUMP_SYSINFO (((uint32_t)1) << 0)

/// Dump environment variables.
#define STACKDUMP_ENVIRONMENT (((uint32_t)1) << 1)

/// Dump the stack trace.
#define STACKDUMP_STACK (((uint32_t)1) << 2)

/// Dump the registers.
#define STACKDUMP_REGISTERS (((uint32_t)1) << 3)

// When using the glibc backtrace function, we need to provide a buffer
// for storing the return address of each frame. Since we want to avoid doing
// dynamic memory allocation during a stack walk we use this maximum number
// of frames to allocate the buffer.
#define MAX_BACKTRACE_FRAMES_SUPPORTED 100U

#define __ctx(fld) fld

#define TRAPFILE_STACKTRACE_TAG_BEGIN "<StackTrace>\n"
#define TRAPFILE_STACKTRACE_TAG_END "</StackTrace>\n"

#define TRAPFILE_PROCESSOBJECTS_TAG_BEGIN "<ProcessObjects>\n"
#define TRAPFILE_PROCESSOBJECTS_TAG_END "</ProcessObjects>\n"

// HexDump defines.
#define PANIC_ASSERT(e) \
  do {                  \
    if (!(e)) {         \
      goto PANIC;       \
    }                   \
  } while (0);
#define HEXDUMP_INCLUDE_ADDRESS 2
#define NEWLINE "\n"
#define INT64_MAX_HEX_STRING "0xFFFFFFFFFFFFFFFF"
#define INTPTR_MAX_HEX_STRING INT64_MAX_HEX_STRING

#define HEXDUMP_ADDRESS_SIZE \
  (sizeof(INTPTR_MAX_HEX_STRING " : ") - sizeof('\0'))
#define HEXDUMP_BYTES_PER_LINE 16
#define HEXDUMP_HEX_LEN \
  (HEXDUMP_BYTES_PER_LINE * 2 + HEXDUMP_BYTES_PER_LINE / 2)
#define HEXDUMP_NUM_SPACES_BETWEEN 3
#define HEXDUMP_START_OF_CHAR_DATA \
  (HEXDUMP_HEX_LEN + HEXDUMP_NUM_SPACES_BETWEEN)

#define HEXDUMP_LINEBUFFER_SIZE                        \
  (HEXDUMP_ADDRESS_SIZE + HEXDUMP_START_OF_CHAR_DATA + \
   HEXDUMP_BYTES_PER_LINE + sizeof(NEWLINE))

typedef ucontext_t* signalContext;

typedef unsigned char Uint8;
typedef unsigned long Uint32;
typedef long Sint32;
typedef Sint32 Sint;
typedef Uint32 Uint;
typedef Sint SintPtr;
typedef Uint UintPtr;

class IBMSignalHandler {
 public:
  IBMSignalHandler();
  void setTaskManager(TaskManager* taskManager);
  void printTaskInfo(long linuxTid, int signum);

 private:
  void registerSignalHandler(int signo);
  void cleanupThreadFunc();
  void notifySignal();

  static void detailedSignalHandler(int signum, siginfo_t* info, void* context);

 private:
  static TaskManager* taskManager_;
};

class TrapFile {
 public:
  explicit TrapFile(const std::string& trapFilePath);

  void closeTrapFile();
  // Appends at the end of the trapFile_.
  void writeToTrapFile(const std::string& message);

  // Dumps various information (stack trace, environment, ...).
  // On Unix, dump data for any of the following flags:
  // STACKDUMP_SYSINFO
  // STACKDUMP_ENVIRONMENT
  // STACKDUMP_STACK
  // STACKDUMP_REGISTERS

  // HANDPARMS
  //   signum [in]
  //     Signal number.
  //   sigcode [in]
  //     On Unix, sigcode is a siginfo_t structure.
  //   scp [in]
  //     On Unix, scp is a Signal context structure.
  void dump(uint32_t flags, HANDPARMS);

 private:
  std::string filePath_;
  std::shared_ptr<facebook::velox::filesystems::FileSystem> fs_;
  std::unique_ptr<facebook::velox::WriteFile> trapFile_;
};
} // namespace facebook::presto::process
