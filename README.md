# stateful_pass
### 1. call instrument
This folder wants to extract the function set during every fuzzing state. The call instrument folder contains three files: `afl-fuzz.c`  `afl-llvm-pass.so.cc` `afl-llvm-rt.o.c`.


`afl-llvm-pass.so.cc` is an LLVM pass writen in LLVM version 10.0. It instrument IR instructions at every function entry. The inserted IR function will extract what function is being called, write infomation to share memory created by `afl-fuzz.c` (not the share memory to store coverage info). `afl-llvm-rt.o.c` contains functions called by inserted IR and code for SUT to work with AFL fuzzer.  

`afl-llvm-pass.so.cc` also instrument to monitor programe state change from perspective of stateful fuzzer works. For each tested work, the file will instrument at the point that state transforms. 

Until April 1st, 2025, the instrument  only support for AFL-based work.  

#### 1.1 for AFLNET
AFLNET uses response code to observe state changes. So instrument should be placed in network send function.  
You can build the environment by following steps.  

```shell
git clone https://github.com/aflnet/aflnet.git
git clone https://github.com/Emiya404/stateful_pass.git

# new version AFLNET test failed, so change the version 
cd aflnet
git checkout 0f51f9edf837c2f3d8f0ea98dc3b6c19b4562732

cd ..
cp stateful_pass/call_instrument/afl-llvm* aflnet/llvm_mode/
cp stateful_pass/call_instrument/afl-fuzz.c aflnet/

#specify the llvm config in EVN $LLVM_CONFIG
cd aflnet
make clean all
cd llvm_mode
make
```

After compiling the AFLNET, we compile the target by setting the $CC to afl-clang-fast of AFLNET.  

For example openssl
```shell
git clone 
cd openssl
CC=afl-clang-fast ./config no-shared --with-rand-seed=none && \    
CC=afl-clang-fast make include/openssl/configuration.h include/openssl/opensslv.h include/crypto/bn_conf.h include/crypto/dso_conf.h &&   \  
AFL_USE_ASAN=1 CC=afl-clang-fast make apps/openssl $MAKE_OPT
```  

Then there will be two files `func_list.txt` and `func_count.txt`  in $HOME dir, describing all functions of openssl. **Do not** delete them until the next compile.  

Finally, run AFLNET and get function set in output dir.  