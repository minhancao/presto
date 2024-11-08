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

#include "presto_cpp/main/common/process/IBMSignalHandler.h"
#include <dlfcn.h> // For dladdr.
#include <execinfo.h> // For glibc backtrace.
#include <fcntl.h> // For open(), O_RDONLY.
#include <folly/Singleton.h>
#include <folly/io/async/EventBaseManager.h>
#include <gflags/gflags.h>
#include <gflags/gflags_declare.h>
#include <stdio.h> // For perror(), SEEK_END.
#include <unistd.h> // For lseek(), close().
#include "presto_cpp/main/common/process/Presto_git_build_version.h"
#include "presto_cpp/main/PrestoServer.h"
#include "presto_cpp/main/common/Utils.h" // For PRESTO_STARTUP_LOG.
#include "velox/common/base/Exceptions.h"

DEFINE_string(stack_dump_dir, "/tmp", "directory for stack dumping");

namespace facebook::presto::process {
TaskManager* IBMSignalHandler::taskManager_ = nullptr;
namespace {

// HANDPARMS
//   signum [in]
//     Signal number.
//   sigcode [in]
//     On Unix, sigcode is a siginfo_t structure.
//   scp [in]
//     On Unix, scp is a Signal context structure.
void dumpSystemInfo(TrapFile& trapFile, HANDPARMS) {
  struct utsname name = {};
  std::string formattedMessage;

  // Dump the UNIX name, release, version, machine and nodename.
  if (-1 == uname(&name)) {
    formattedMessage = "uname: unknown\n";
  } else {
    formattedMessage = fmt::format(
        "uname: S:{} R:{} V:{} M:{} N:{}\n",
        std::string(name.sysname),
        std::string(name.release),
        std::string(name.version),
        std::string(name.machine),
        std::string(name.nodename));
  }

  trapFile.writeToTrapFile(formattedMessage);
}

#if defined(__x86_64__)
void dumpRegistersAMD64(TrapFile& trapFile, HANDPARMS) {
  ucontext_t* uc = reinterpret_cast<ucontext_t*>(scp);

  std::string buffer = fmt::format(
      "Register values:\n"
      "RIP: 0x{:x}\n"
      "RSP: 0x{:x}\n"
      "RBP: 0x{:x}\n"
      "RAX: 0x{:x}\n"
      "RBX: 0x{:x}\n"
      "RCX: 0x{:x}\n"
      "RDX: 0x{:x}\n"
      "RSI: 0x{:x}\n"
      "RDI: 0x{:x}\n"
      "R8:  0x{:x}\n"
      "R9:  0x{:x}\n"
      "R10: 0x{:x}\n"
      "R11: 0x{:x}\n"
      "R12: 0x{:x}\n"
      "R13: 0x{:x}\n"
      "R14: 0x{:x}\n"
      "R15: 0x{:x}\n"
      "Faulting address: 0x{:x}\n",
      uc->uc_mcontext.gregs[REG_RIP],
      uc->uc_mcontext.gregs[REG_RSP],
      uc->uc_mcontext.gregs[REG_RBP],
      uc->uc_mcontext.gregs[REG_RAX],
      uc->uc_mcontext.gregs[REG_RBX],
      uc->uc_mcontext.gregs[REG_RCX],
      uc->uc_mcontext.gregs[REG_RDX],
      uc->uc_mcontext.gregs[REG_RSI],
      uc->uc_mcontext.gregs[REG_RDI],
      uc->uc_mcontext.gregs[REG_R8],
      uc->uc_mcontext.gregs[REG_R9],
      uc->uc_mcontext.gregs[REG_R10],
      uc->uc_mcontext.gregs[REG_R11],
      uc->uc_mcontext.gregs[REG_R12],
      uc->uc_mcontext.gregs[REG_R13],
      uc->uc_mcontext.gregs[REG_R14],
      uc->uc_mcontext.gregs[REG_R15],
      reinterpret_cast<unsigned long>(sigcode->si_addr));

  trapFile.writeToTrapFile(buffer);
}
#endif // __x86_64__

#if defined(__aarch64__)
void dumpRegistersARM64(TrapFile& trapFile, HANDPARMS) {
  ucontext_t* uc = reinterpret_cast<ucontext_t*>(scp);

  std::string buffer = fmt::format(
      "Register values:\n"
      "PC:  0x{:016x}\n"
      "SP:  0x{:016x}\n"
      "PSTATE: 0x{:016x}\n"
      "X0:  0x{:016x}\n"
      "X1:  0x{:016x}\n"
      "X2:  0x{:016x}\n"
      "X3:  0x{:016x}\n"
      "X4:  0x{:016x}\n"
      "X5:  0x{:016x}\n"
      "X6:  0x{:016x}\n"
      "X7:  0x{:016x}\n"
      "X8:  0x{:016x}\n"
      "X9:  0x{:016x}\n"
      "X10: 0x{:016x}\n"
      "X11: 0x{:016x}\n"
      "X12: 0x{:016x}\n"
      "X13: 0x{:016x}\n"
      "X14: 0x{:016x}\n"
      "X15: 0x{:016x}\n"
      "X16: 0x{:016x}\n"
      "X17: 0x{:016x}\n"
      "X18: 0x{:016x}\n"
      "X19: 0x{:016x}\n"
      "X20: 0x{:016x}\n"
      "X21: 0x{:016x}\n"
      "X22: 0x{:016x}\n"
      "X23: 0x{:016x}\n"
      "X24: 0x{:016x}\n"
      "X25: 0x{:016x}\n"
      "X26: 0x{:016x}\n"
      "X27: 0x{:016x}\n"
      "X28: 0x{:016x}\n"
      "X29 (FP): 0x{:016x}\n"
      "X30 (LR): 0x{:016x}\n"
      "Faulting address: 0x{:016x}\n",
      uc->uc_mcontext.pc,
      uc->uc_mcontext.sp,
      uc->uc_mcontext.pstate,
      uc->uc_mcontext.regs[0],
      uc->uc_mcontext.regs[1],
      uc->uc_mcontext.regs[2],
      uc->uc_mcontext.regs[3],
      uc->uc_mcontext.regs[4],
      uc->uc_mcontext.regs[5],
      uc->uc_mcontext.regs[6],
      uc->uc_mcontext.regs[7],
      uc->uc_mcontext.regs[8],
      uc->uc_mcontext.regs[9],
      uc->uc_mcontext.regs[10],
      uc->uc_mcontext.regs[11],
      uc->uc_mcontext.regs[12],
      uc->uc_mcontext.regs[13],
      uc->uc_mcontext.regs[14],
      uc->uc_mcontext.regs[15],
      uc->uc_mcontext.regs[16],
      uc->uc_mcontext.regs[17],
      uc->uc_mcontext.regs[18],
      uc->uc_mcontext.regs[19],
      uc->uc_mcontext.regs[20],
      uc->uc_mcontext.regs[21],
      uc->uc_mcontext.regs[22],
      uc->uc_mcontext.regs[23],
      uc->uc_mcontext.regs[24],
      uc->uc_mcontext.regs[25],
      uc->uc_mcontext.regs[26],
      uc->uc_mcontext.regs[27],
      uc->uc_mcontext.regs[28],
      uc->uc_mcontext.regs[29], // FP
      uc->uc_mcontext.regs[30], // LR
      reinterpret_cast<uintptr_t>(sigcode->si_addr));

  trapFile.writeToTrapFile(buffer);
}
#endif // __aarch64__

// HANDPARMS
//   signum [in]
//     Signal number.
//   sigcode [in]
//     On Unix, sigcode is a siginfo_t structure.
//   scp [in]
//     On Unix, scp is a Signal context structure.
void dumpRegisters(TrapFile& trapFile, HANDPARMS) {
  #if defined(__x86_64__)
    dumpRegistersAMD64(trapFile, HANDARGS);
  #elif defined(__aarch64__)
    dumpRegistersARM64(trapFile, HANDARGS);
  #else
    trapFile.writeToTrapFile("Unsupported architecture for reading registers.\n");
  #endif
}

void readWriteProcPidMaps(TrapFile& trapFile) {
  std::string mapsFilePathStr = fmt::format("/proc/{}/maps", getpid());

  // Not using Velox's filesystem to open proc maps file
  // since it is a non-seekable file and its file size can change.
  int mapsFd = open(mapsFilePathStr.c_str(), O_RDONLY);
  if (-1 != mapsFd) {
    char readbuf[4096];

    do {
      ssize_t rc = read(mapsFd, readbuf, sizeof(readbuf));

      if (rc > 0) {
        trapFile.writeToTrapFile(readbuf);
      } else {
        break;
      }
    } while (true);
  } else {
    trapFile.writeToTrapFile("Unable to open proc pid maps file.\n");
  }

  close(mapsFd);
}

// Given an address somewhere within the function's body, reports
// the function's name and the address's offset within the function,
// and otherwise reports an error.
void traceFunction(
    void* address,
    TrapFile& trapFile,
    std::string_view pretty_print) {
  Dl_info dlip;
  std::string buf;

  if (!address) {
    buf = fmt::format("\n");
  } else {
    int rc = dladdr(address, &dlip);

    if (rc) {
      const char* symbol_name = dlip.dli_sname;
      if (!symbol_name) {
        symbol_name = "";
      }

      const char* object_name = dlip.dli_fname;
      if (!object_name) {
        object_name = "";
      }

      if (dlip.dli_saddr) {
        uintptr_t instruction_offset = reinterpret_cast<uintptr_t>(address) -
            reinterpret_cast<uintptr_t>(dlip.dli_saddr);

        buf = fmt::format(
            " address: 0x{:x} ; dladdress: 0x{:x} ; offset in lib: 0x{:x} ; {}({})\n",
            reinterpret_cast<UintPtr>(address),
            reinterpret_cast<UintPtr>(dlip.dli_fbase),
            reinterpret_cast<char*>(address) -
                reinterpret_cast<char*>(dlip.dli_fbase),
            pretty_print,
            object_name);
      } else {
        // dladdr() could not find the symbol address. It probably couldn't
        // figure out the symbol name either. Print the address we were given,
        // and the address the object was loaded at (dli_fbase). If dli_fbase
        // is not 0, then (address-dli_fbase) is an offset that can be used,
        // along with "nm libdb2e.so.1 | sort | less", to find the symbol,
        // calculate and offset, and locate the line of code.
        buf = fmt::format(
            " address: 0x{:x} ; dladdress: 0x{:x} ; offset in lib: 0x{:x} ; {}({})\n",
            reinterpret_cast<UintPtr>(address),
            reinterpret_cast<UintPtr>(dlip.dli_fbase),
            reinterpret_cast<char*>(address) -
                reinterpret_cast<char*>(dlip.dli_fbase),
            pretty_print,
            object_name);
      }
    } else {
      buf = fmt::format(" address: {}\n", address);
    }
  }

  trapFile.writeToTrapFile(buf);
}

std::string mCode(unsigned long instruction) {
  uint32_t instructionLower = static_cast<uint32_t>(instruction);
  char mcode[4];
  memcpy(
      mcode,
      &instructionLower,
      sizeof(mcode)); // Safe: sizeof(mcode) is 4 bytes

  return fmt::format(
      "{:02X}{:02X}{:02X}{:02X}",
      0xff & mcode[0],
      0xff & mcode[1],
      0xff & mcode[2],
      0xff & mcode[3]);
}

Uint alignX(Uint i, Uint X) {
  return ((i + (X - 1)) & ~static_cast<Uint>(X - 1));
}

void hexDumpLine(
    std::string& outBuf,
    const void* inptr,
    size_t len,
    Uint flags) {
  const unsigned char* pc = static_cast<const unsigned char*>(inptr);
  bool includeAddress = (flags & HEXDUMP_INCLUDE_ADDRESS) != 0;
  size_t curOff = HEXDUMP_START_OF_CHAR_DATA;

  outBuf.clear();
  if (len <= 0 || len > HEXDUMP_BYTES_PER_LINE) {
    outBuf += "Could not hexdump line to buffer.";
    return;
  }

  if (includeAddress) {
    outBuf += fmt::format("0x{:x} : ", reinterpret_cast<uintptr_t>(pc));
  }

  // Hexadecimal representation.
  for (size_t j = 0; j < len; j++) {
    outBuf += fmt::format("{:02X}", static_cast<unsigned>(pc[j]));
    if (j < len - 1) {
      outBuf += ' ';
    }
  }

  // Append ASCII representation
  for (size_t j = 0; j < len; j++, curOff++) {
    if (pc[j] >= ' ' && pc[j] <= '~') {
      outBuf += pc[j];
    } else {
      outBuf += '.';
    }
  }

  outBuf += '\n';

  // Ensure the output length does not exceed the buffer size if necessary.
  PANIC_ASSERT(outBuf.size() <= HEXDUMP_LINEBUFFER_SIZE);

  PANIC_ASSERT(!outBuf.empty());

PANIC:
  abort();
  return;
}

void hexDumpToBuffer(
    const void* inptr,
    size_t len,
    std::string& outBuf,
    const char* szPrefix,
    Uint flags) {
  outBuf.clear();

  if (len == 0) {
    return;
  }

  size_t prefixLength = szPrefix ? strlen(szPrefix) : 0;
  Uint totalLines =
      alignX(len, HEXDUMP_BYTES_PER_LINE) / HEXDUMP_BYTES_PER_LINE;
  const char* pc = static_cast<const char*>(inptr);

  for (Uint curLine = 0; curLine < totalLines;
       curLine++, pc += HEXDUMP_BYTES_PER_LINE) {
    size_t curLen = (curLine + 1 == totalLines)
        ? (len - curLine * HEXDUMP_BYTES_PER_LINE)
        : HEXDUMP_BYTES_PER_LINE;

    std::string lineBuf;
    hexDumpLine(lineBuf, pc, curLen, flags);

    // Check if adding this line will exceed the buffer.
    if (outBuf.size() + lineBuf.size() + prefixLength + 2 <=
        HEXDUMP_LINEBUFFER_SIZE) {
      // Copy prefix first.
      if (prefixLength) {
        outBuf.append(szPrefix, prefixLength);
      }
      outBuf.append(lineBuf);
    } else {
      return;
    }
  }
}

// HANDPARMS
//   signum [in]
//     Signal number.
//   sigcode [in]
//     On Unix, sigcode is a siginfo_t structure.
//   scp [in]
//     On Unix, scp is a Signal context structure.
void dumpStackTraceInternal(
    TrapFile& trapFile,
    HANDPARMS,
    uint32_t flags,
    uint32_t stackTop) {
  signalContext pScp = static_cast<signalContext>(scp);
  Uint8* rip = nullptr;
  #if defined(__x86_64__)
    greg_t* r = pScp->uc_mcontext.gregs;
    rip = reinterpret_cast<Uint8*>(r[REG_RIP]);
  #elif defined(__aarch64__)
    rip = reinterpret_cast<Uint8*>(pScp->uc_mcontext.pc);
  #else
    trapFile.writeToTrapFile("Unsupported architecture for reading instruction pointer.\n");
  #endif
  
  void* syms[MAX_BACKTRACE_FRAMES_SUPPORTED];
  int cnt = 0;
  int i = 0;
  
  UintPtr* rsp = nullptr;
  #if defined(__x86_64__)
    rsp = reinterpret_cast<UintPtr*>(r[REG_RSP]);
  #elif defined(__aarch64__)
    rsp = reinterpret_cast<UintPtr*>(pScp->uc_mcontext.sp);
  #else
    trapFile.writeToTrapFile("Unsupported architecture for reading stack pointer.\n");
  #endif

  UintPtr returnAddress = 0;
  Dl_info dlip = {0};
  UintPtr address = 0U;
  UintPtr endAddress = 0U;
  std::string formattedMsg;
  int kAddressStepSize16 = 16;
  int kAddressStepSize128 = 128;
  int kMaxAddressSteps = 256;
  int rc = 0;

  // Attempt backtrace if instruction pointer register is not pointing
  // to same address as the signal's address or if signal received is SIGILL or
  // SIGFPE.
  bool attemptBacktrace =
      ((rip != sigcode->si_addr) || (signum == SIGILL) || (signum == SIGFPE));

  // Bail out if the signal info pointer is NULL.
  if (!sigcode) {
    trapFile.writeToTrapFile(
        "Unable to provide point of failure disassembly:"
        " signal info pointer is NULL\n");
  } else {
    address = reinterpret_cast<UintPtr>(rip);
    if (!attemptBacktrace) {
      // Return address could be at current stack pointer location
      // if the signal was caused by a call through a bad function ptr.
      returnAddress = reinterpret_cast<UintPtr>(*rsp);
      rc = dladdr(reinterpret_cast<void*>(returnAddress), &dlip);
      if (rc) {
        address = returnAddress;
      } else {
        address = 0U;
      }
    }

    if (0 != address) {
      traceFunction(reinterpret_cast<void*>(address), trapFile, "\t");
      formattedMsg = fmt::format(
          "\n\t0x{:x} : {}",
          address,
          mCode(*reinterpret_cast<unsigned long*>(address)));

      trapFile.writeToTrapFile(formattedMsg);

      formattedMsg = fmt::format(
          "{}\n", mCode(*reinterpret_cast<unsigned long*>(address + 4)));

      trapFile.writeToTrapFile(formattedMsg);
    } else {
      trapFile.writeToTrapFile(
          "Signal address equal to instruction pointer and "
          "valid return address could not be determined.\n");
    }
  }

  trapFile.writeToTrapFile(TRAPFILE_STACKTRACE_TAG_BEGIN);

  if (attemptBacktrace) {
    cnt = backtrace(syms, MAX_BACKTRACE_FRAMES_SUPPORTED);

    // Convert addresses to symbolic names.
    char** symbols = backtrace_symbols(syms, cnt);
    if (symbols == NULL) {
      trapFile.writeToTrapFile("backtrace_symbols returned NULL.");
    }

    else {
      for (int i = 0; i < cnt; i++) {
        traceFunction(syms[i], trapFile, "\n\t\t");

        Dl_info dl_info;
        if (dladdr(syms[i], &dl_info) && dl_info.dli_fname) {
          // Print raw stack trace symbol.
          formattedMsg = fmt::format("{}\n", symbols[i]);
          trapFile.writeToTrapFile(formattedMsg);
          // Print additional details if available.
          if (dl_info.dli_fname) {
            formattedMsg = fmt::format("\tFile: {}\n", dl_info.dli_fname);
            trapFile.writeToTrapFile(formattedMsg);
          }
          if (dl_info.dli_sname) {
            formattedMsg = fmt::format("\n\tFunction: {}", dl_info.dli_sname);
            trapFile.writeToTrapFile(formattedMsg);
          }

          if (dl_info.dli_fbase) {
            uintptr_t offset = reinterpret_cast<uintptr_t>(syms[i]) -
                reinterpret_cast<uintptr_t>(dl_info.dli_fbase);
            formattedMsg = fmt::format("\n\tOffset: 0x{:x}", offset);
            trapFile.writeToTrapFile(formattedMsg);
          }

          // Use addr2line to get line number.
          std::string command = fmt::format(
              "addr2line -e {} 0x{:x}",
              dl_info.dli_fname,
              reinterpret_cast<uintptr_t>(syms[i]));

          FILE* addr2line_output = popen(command.c_str(), "r");
          if (addr2line_output) {
            char line[256];
            if (fgets(line, sizeof(line), addr2line_output)) {
              formattedMsg = fmt::format("\n\tLocation: {}", line);
              trapFile.writeToTrapFile(formattedMsg);
            }
            pclose(addr2line_output);
          } else {
            std::string errorMsg = "\n\tError: Unable to run addr2line";
            trapFile.writeToTrapFile(errorMsg);
          }
        }
      }
    }

    free(symbols);

  } else {
    // DB2 and system libraries are not compiled with frame pointers so
    // we must attempt to use rsp here. If the trap was due to a bad
    // function pointer then the return address should be located at the
    // stack pointer location at the time of the signal. That means we
    // can try to dump the name of the function and offset where the bad
    // function pointer call was made.
    if (rc) {
      std::string headerMsg =
          "-----FUNC-ADDR---- ------FUNCTION + OFFSET------\n";
      trapFile.writeToTrapFile(headerMsg);

      std::string addressMsg = fmt::format("0x{:x} [RSP]", returnAddress);
      trapFile.writeToTrapFile(addressMsg);
      traceFunction(reinterpret_cast<void*>(returnAddress), trapFile, "\n\t");
    }

    // We cannot walk the stack easily here because the code is not compiled
    // with frame pointers. Let's dump a portion of stack so that the stack
    // traceback can be determined manually if needed.
    formattedMsg =
        fmt::format("\nRaw stack dump. Stack top is at 0x{:x}.\n", stackTop);
    trapFile.writeToTrapFile(formattedMsg);

    // Start dumping stack around stack pointer.
    address = reinterpret_cast<UintPtr>(rsp);

    // Round down to a multiple of 16.
    address &= (~(kAddressStepSize16 - 1));

    // If stackTop is non-zero then it is the end of stack address.
    // Otherwise, we will do the safe thing and only dump the current
    // page of the stack.
    if (stackTop) {
      endAddress = stackTop;
    } else {
      endAddress = (address | 4095) + 1;
    }

    // Dump 16 bytes at a time until the next 128 byte boundary is reached.
    for (; 0 != (address & (kAddressStepSize128 - 1));
         address += kAddressStepSize16) {
      std::string dumpOutput;
      hexDumpToBuffer(
          reinterpret_cast<const void*>(address),
          kAddressStepSize128,
          dumpOutput,
          "",
          HEXDUMP_INCLUDE_ADDRESS);
      trapFile.writeToTrapFile(dumpOutput);
    }

    // Dump 128 bytes at a time until the last 128 byte boundary before
    // the end address is reached or
    // until 32K of stack memory has been dumped.
    for (i = 0; (address < (endAddress & (~(kAddressStepSize128 - 1)))) &&
         (i < kMaxAddressSteps);
         address += kAddressStepSize128, ++i) {
      std::string dumpOutput;
      hexDumpToBuffer(
          reinterpret_cast<const void*>(address),
          kAddressStepSize128,
          dumpOutput,
          "",
          HEXDUMP_INCLUDE_ADDRESS);
      trapFile.writeToTrapFile(dumpOutput);
    }

    if (i < kMaxAddressSteps) {
      // Dump 16 bytes at a time until the end address is reached.
      for (; address < endAddress; address += kAddressStepSize16) {
        std::string dumpOutput;
        hexDumpToBuffer(
            reinterpret_cast<const void*>(address),
            kAddressStepSize16,
            dumpOutput,
            "",
            HEXDUMP_INCLUDE_ADDRESS);
        trapFile.writeToTrapFile(dumpOutput);
      }
    }
  }

  trapFile.writeToTrapFile(TRAPFILE_STACKTRACE_TAG_END);

  trapFile.writeToTrapFile(TRAPFILE_PROCESSOBJECTS_TAG_BEGIN);
  if ((SIGUSR1 != signum) && (SIGUSR2 != signum)) {
    readWriteProcPidMaps(trapFile);
  }
  trapFile.writeToTrapFile(TRAPFILE_PROCESSOBJECTS_TAG_END);
}

// Function to convert signal number to string.
std::string signalToString(int signo) {
  switch (signo) {
    case SIGSEGV:
      return "SIGSEGV";
    case SIGILL:
      return "SIGILL";
    default:
      return "Unknown Signal";
  }
}

} // namespace

IBMSignalHandler::IBMSignalHandler() {
  registerSignalHandler(SIGSEGV);
  registerSignalHandler(SIGILL);
}

void IBMSignalHandler::registerSignalHandler(int signo) {
  struct sigaction sa = {};
  sa.sa_sigaction = &IBMSignalHandler::detailedSignalHandler;
  sa.sa_flags = SA_SIGINFO;
  sigemptyset(&sa.sa_mask);

  // Register signals for detailed handling
  if (sigaction(signo, &sa, NULL) == -1) {
    PRESTO_STARTUP_LOG(INFO)
        << "Error setting up sigaction for " << signalToString(signo);
  } else {
    PRESTO_STARTUP_LOG(INFO)
        << "Custom signal handler for " << signalToString(signo)
        << " is successfully registered.";
  }
}

void IBMSignalHandler::detailedSignalHandler(
    int signum,
    siginfo_t* info,
    void* context) {
  auto signalStr = strsignal(signum);

  LOG(INFO) << fmt::format("Signal {} {} received\n", signum, signalStr);

  ucontext_t* uc = reinterpret_cast<ucontext_t*>(context);
  #if defined(__x86_64__)
    void* rip = reinterpret_cast<void*>(uc->uc_mcontext.gregs[REG_RIP]);
    LOG(INFO) << fmt::format("Instruction pointer (RIP): {}\n", rip);
  #elif defined(__aarch64__)
    void* pc = reinterpret_cast<void*>(uc->uc_mcontext.pc);
    LOG(INFO) << fmt::format("Program counter (pc): {}\n", pc);
  #else
    LOG(INFO) << "Unsupported architecture for reading instruction pointer register.\n";
  #endif

  LOG(INFO) << fmt::format("Faulting address (SI_ADDR): {}\n", info->si_addr);

  // Get process ID and thread ID.
  pid_t pid = getpid();
  pthread_t posixTid = pthread_self();
  auto linuxTid = syscall(SYS_gettid);

  LOG(INFO) << fmt::format("Linux thread ID: {}\n", linuxTid);

  // Get current date and time.
  std::time_t now = std::time(nullptr);
  std::tm* tm_now = std::localtime(&now);

  // Create a string stream for the filename.
  std::ostringstream oss;
  oss << FLAGS_stack_dump_dir << "/stack_dump_"
      << std::put_time(tm_now, "%Y%m%d_%H%M%S") << "_pid" << pid << "_linux_tid"
      << linuxTid << ".txt";

  std::string filePathStr = oss.str();
  TrapFile trapFile(filePathStr);
  trapFile.writeToTrapFile("BEGIN: Dumping related info\n");

  std::string gitInfo = fmt::format(
      "Git branch: {}\n"
      "Git commit hash: {}\n",
      BUILD_GIT_BRANCH,
      BUILD_GIT_COMMIT);

  trapFile.writeToTrapFile(gitInfo);

  // uname dump.
  trapFile.dump(STACKDUMP_SYSINFO, signum, info, context);

  std::string message = fmt::format(
      "Signum received: {}\n"
      "Process id: {}\n"
      "Linux Thread id: {}\n"
      "POSIX Thread id: {}\n",
      signum,
      pid,
      linuxTid,
      static_cast<unsigned long>(posixTid));

  trapFile.writeToTrapFile(message);

  // Print task information here.
  if (taskManager_) {
    auto taskMap = taskManager_->tasks();

    for (auto& pair : taskMap) {
      const protocol::TaskId& prestoTaskId = pair.first;
      std::shared_ptr<PrestoTask>& prestoTask = pair.second;
      std::shared_ptr<facebook::velox::exec::Task>& veloxTask =
          prestoTask->task;
      if (veloxTask != nullptr && veloxTask->isRunning()) {
        std::vector<facebook::velox::exec::Task::OpCallInfo> stuckCalls;
        const std::chrono::milliseconds lockTimeoutMs(0);
        veloxTask->getLongRunningOpCalls(lockTimeoutMs, 0, stuckCalls);
        for (const auto& callInfo : stuckCalls) {
          int32_t linuxTidInt32 = static_cast<int32_t>(linuxTid);
          if (linuxTidInt32 == callInfo.tid) {
            std::string message = fmt::format(
                "Presto Task ID: {}\n"
                "Velox Task ID: {}\n"
                "Query ID: {}\n"
                "Signal thread ID: {}\n"
                "Task thread ID: {}\n",
                prestoTaskId,
                veloxTask->taskId(),
                veloxTask->queryCtx()->queryId(),
                linuxTid,
                callInfo.tid);
            trapFile.writeToTrapFile(message);

            auto planFragmentStr =
                veloxTask->planFragment().planNode->toString(true, true);
            message = fmt::format(
                "Velox plan fragment: \n"
                "{}",
                planFragmentStr);
            trapFile.writeToTrapFile(message);

            // This is to update task to be an error task so the Presto
            // coordinator can see it and update accordingly.
            auto signalStr = strsignal(signum);
            auto ex = std::make_exception_ptr(
                std::runtime_error(
                    fmt::format(
                        "Exception caused by {} signal.",
                        signalStr ? signalStr : "Unknown")));
            taskManager_->createOrUpdateErrorTask(
                veloxTask->taskId(), ex, true, 0);
          }
        }
      }
    }
  }

  trapFile.writeToTrapFile(
      "Dump of register values at time of bad instruction: \n");
  trapFile.dump(STACKDUMP_REGISTERS, signum, info, context);

  trapFile.writeToTrapFile("Disassembly of bad instructions: \n");
  trapFile.dump(STACKDUMP_STACK, signum, info, context);

  trapFile.writeToTrapFile("END: Dumping related info finished\n");
  trapFile.closeTrapFile();

  VELOX_FAIL(fmt::format("Signal {} {} received.", signum, signalStr));
}

TrapFile::TrapFile(const std::string& trapFilePath) {
  filePath_ = trapFilePath;
  fs_ = facebook::velox::filesystems::getFileSystem(trapFilePath, nullptr);
  trapFile_ = fs_->openFileForWrite(trapFilePath);
}

void TrapFile::closeTrapFile() {
  trapFile_->close();
}

void TrapFile::writeToTrapFile(const std::string& message) {
  trapFile_->append(message);
}

// HANDPARMS
//   signum [in]
//     Signal number.
//   sigcode [in]
//     On Unix, sigcode is a siginfo_t structure.
//   scp [in]
//     On Unix, scp is a Signal context structure.
void TrapFile::dump(uint32_t flags, HANDPARMS) {
  if (flags & STACKDUMP_SYSINFO) {
    dumpSystemInfo(*this, HANDARGS);
  }

  if (flags & STACKDUMP_REGISTERS) {
    dumpRegisters(*this, HANDARGS);
  }

  if (flags & STACKDUMP_STACK) {
    dumpStackTraceInternal(*this, HANDARGS, flags, 0);
  }
}

void IBMSignalHandler::setTaskManager(TaskManager* taskManager) {
  taskManager_ = taskManager;
}

folly::Singleton<IBMSignalHandler> signalHandler([]() -> IBMSignalHandler* {
  return std::make_unique<facebook::presto::process::IBMSignalHandler>()
      .release();
});

} // namespace facebook::presto::process
