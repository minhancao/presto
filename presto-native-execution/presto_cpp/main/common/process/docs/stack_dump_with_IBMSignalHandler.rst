************************************************
Stack Dump Debugging with IBMSignalHandler Guide
************************************************

Background
----------

This guide is intended for debugging with IBMSignalHandler's stack dump. When a bad 
signal such as SIGSEGV or SIGILL is hit by the `presto_server` process, information 
will be logged to a file that helps debug what caused the bad signal. The 
IBMSignalHandler is currently registered to handle SIGSEGV and SIGILL signals.

NOTE: This stack dump functionality is meant to work on Linux only.

The stack dump filename will look like:

::

    stack_dump_20250711_150902_pid172318_linux_tid172398.txt

The stack dump file contains the following information:

::

    Git branch
    Git commit hash
    uname
    Signal number received
    Process id
    Linux Thread id
    POSIX Thread id
    Presto Task ID
    Velox Task ID
    Query ID
    Signal thread ID
    Task thread ID
    Velox plan fragment
    Dump of register values at time of bad instructions
    Disassembly of bad instructions (stack trace)
    Process PID Map

Configuration
-------------

To specify what directory the stack dump files should be logged into, you can provide 
the `presto_server` executable with the `--stack_dump_dir` flag and set it to the 
directory that you would like the stack dump files to be in.

If no directory is specified, IBMSignalHandler will log to `/tmp` by default.

Example:

::

    presto_server --logtostderr=1 --v=1 --etc-dir=/root/presto_home/velox-etc --stack_dump_dir=/root/stack_dump_dir

How to use for debugging
------------------------

To demonstrate debugging with IBMSignalHandler, the following example scenario is provided.

In this scenario, some code was purposely inserted into `TableScan.cpp` to cause a 
SIGSEGV signal, simulating a crash during a query execution.

Video Guide: `stack_dump_demo_08042025 <https://ibm-my.sharepoint.com/:v:/p/mcao/ETL845D3VMVKo0e2JOIBLiwB_qo5-b8d_HAnRKQVcVQLNg?e=fgYf7j&nav=eyJyZWZlcnJhbEluZm8iOnsicmVmZXJyYWxBcHAiOiJTdHJlYW1XZWJBcHAiLCJyZWZlcnJhbFZpZXciOiJTaGFyZURpYWxvZy1MaW5rIiwicmVmZXJyYWxBcHBQbGF0Zm9ybSI6IldlYiIsInJlZmVycmFsTW9kZSI6InZpZXcifX0%3D>`_

Scenario
--------

1. User runs a basic select query from a table, which hits a SIGSEGV.

2. IBMSignalHandler detects the SIGSEGV and logs debugging information to a stack 
   dump file in the specified directory.

3. A VELOX_FAIL() is invoked and presto_server process terminates.

Debug workflow:

1. Open and view the stack dump log file.

   .. image:: images/stack_dump_file.png

2. Look for useful information in the file.

3. The "Velox plan fragment" section may indicate that `TableScan` is the potential source.

4. Look at the "Disassembly of bad instructions" section for the crashing instruction.  
   For example: `address: 0x4a0ce35`.

5. Run the following commands to disassemble the `presto_server` binary:

   ::

       objdump -d --demangle --section=.text presto_server > disasm_presto_server.txt
       grep -C 10 4a0ce35 disasm_presto_server.txt

   Sample output:

   ::

       [root@mcaoprestocentos1 _build]# grep -C 10 4a0ce35 /root/stack_dump_dir/disasm_release_no_flags_sigsegv.txt
       4a0ce06:       48 8b 94 24 b0 00 00    mov    0xb0(%rsp),%rdx
       4a0ce0d:       00 
       4a0ce0e:       48 89 50 20             mov    %rdx,0x20(%rax)
       4a0ce12:       e9 23 fb ff ff          jmpq   4a0c93a <facebook::velox::exec::TableScan::getOutput()+0x10a>
       4a0ce17:       66 0f 1f 84 00 00 00    nopw   0x0(%rax,%rax,1)
       4a0ce1e:       00 00 
       4a0ce20:       48 8d 3d f9 cc ae 01    lea    0x1aeccf9(%rip),%rdi        # 64f9b20 <...>
       4a0ce27:       e8 64 4e 61 00          callq  5021c90 <...>
       4a0ce2c:       0f 1f 40 00             nopl   0x0(%rax)
       4a0ce30:       e8 3b ee ff ff          callq  4a0bc70 <...>
       4a0ce35:       8b 04 25 00 00 00 00    mov    0x0,%eax
       4a0ce3c:       0f 0b                   ud2    
       4a0ce3e:       66 90                   xchg   %ax,%ax
       4a0ce40:       48 c7 44 24 10 00 00    movq   $0x0,0x10(%rsp)
       4a0ce49:       00 00 
       4a0ce4b:       48 c7 44 24 18 00 00    movq   $0x0,0x18(%rsp)
       4a0ce52:       00 00 
       4a0ce54:       e9 66 fc ff ff          jmpq   4a0cabd <...>

   You can see that the SIGSEGV occurred at ``4a0ce35:       8b 04 25 00 00 00 00    mov    0x0,%eax``, and the context suggests 
   the SIGSEGV signal happened in ``TableScan::getOutput()``.

6. To pinpoint the exact line of source code in `TableScan.cpp`, follow these steps:

   Commands to run in terminal:

   ::

       cd presto/presto-native-execution
       export CXXFLAGS="-S -fverbose-asm"
       mkdir test_cmake
       cd test_cmake
       cmake ..
       cd velox/velox/exec
       make TableScan.cpp.s
       as -a ./CMakeFiles/velox_exec.dir/TableScan.cpp.s > TableScan.cpp.s.cod 2>&1
       grep -C 10 8B0425 TableScan.cpp.s.cod

   Expected output:

   ::

       [root@mcaoprestocentos1 velox_exec.dir]# grep -C 10 8B0425 /root/stack_dump_dir/TableScan.cpp.s.cod
       47229                  .LEHE392:
       47230 43fc 0F1F4000            .p2align 4,,10
       47231                          .p2align 3
       47232                  .L6472:
       47233                  .LEHB393:
       47234                  # /root/presto_oss/presto/presto-native-execution/velox/velox/exec/TableScan.cpp:127:       const a
       47235 4400 E8000000            call    _ZN8facebook5velox4exec9TableScan8getSplitEv@PLT        #
       47235      00
       47236                  .LEHE393:
       47237                  # /root/presto_oss/presto/presto-native-execution/velox/velox/exec/TableScan.cpp:129:       int val
       47238 4405 8B042500            movl    0, %eax # MEM[(volatile int *)0B], value
       47239 440c 0F0B                ud2
       47240 440e 6690                .p2align 4,,10
       47241                          .p2align 3
       47242                  .L6408:
       47243                  # /root/presto_oss/presto/presto-native-execution/velox/velox/exec/TableScan.cpp:153:     std::opti
       47244 4410 48C74424            movq    $0, 16(%rsp)    #, %sfp
       47245 4419 48C74424            movq    $0, 24(%rsp)    #, %sfp 

    
   Looking at the expected output above, you can see:

   ::

       47237                  # /root/presto_oss/presto/presto-native-execution/velox/velox/exec/TableScan.cpp:129:       int val
       47238 4405 8B042500            movl    0, %eax # MEM[(volatile int *)0B], value

   This is showing that TableScan.cpp at line 129 is the code that caused the SIGSEGV signal.

   .. image:: images/TableScanCode.png
