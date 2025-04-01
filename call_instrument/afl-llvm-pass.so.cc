#include <llvm/IR/Constants.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/Instructions.h>
#define AFL_LLVM_PASS
#define AFLNET_STATE_AWARE
#include "../config.h"
#include "../debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace {
class AFLCoverage : public ModulePass {
public:
  static char ID;
  AFLCoverage() : ModulePass(ID) {}
  bool runOnModule(Module &M) override;
};
} // namespace
char AFLCoverage::ID = 0;
bool AFLCoverage::runOnModule(Module &M) {
  /*
    1. afl-part of the instrument pass
    afl should behave normally on this instrument to make AFL based fuzzer
    normally run
  */
  LLVMContext &C = M.getContext();
  IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);

  /* Show a banner */
  char be_quiet = 0;

  if (isatty(2) && !getenv("AFL_QUIET")) {

    SAYF(cCYA "afl-llvm-pass " cBRI VERSION cRST
              " by <lszekeres@google.com>\n");

  } else
    be_quiet = 1;
  /* Decide instrumentation ratio */
  char *inst_ratio_str = getenv("AFL_INST_RATIO");
  unsigned int inst_ratio = 100;

  if (inst_ratio_str) {

    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
        inst_ratio > 100)
      FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");
  }

  /* Get globals for the SHM region and the previous location. Note that
     __afl_prev_loc is thread-local. */

  GlobalVariable *AFLMapPtr =
      new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");

  GlobalVariable *AFLPrevLoc = new GlobalVariable(
      M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc", 0,
      GlobalVariable::GeneralDynamicTLSModel, 0, false);

  /* Instrument all the things! */

  int inst_blocks = 0;

  for (auto &F : M)
    for (auto &BB : F) {

      BasicBlock::iterator IP = BB.getFirstInsertionPt();
      IRBuilder<> IRB(&(*IP));

      if (AFL_R(100) >= inst_ratio)
        continue;

      /* Make up cur_loc */

      unsigned int cur_loc = AFL_R(MAP_SIZE);

      ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cur_loc);

      /* Load prev_loc */

      LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);
      PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, IRB.getInt32Ty());

      /* Load SHM pointer */

      LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
      MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *MapPtrIdx =
          IRB.CreateGEP(MapPtr, IRB.CreateXor(PrevLocCasted, CurLoc));

      /* Update bitmap */

      LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
      Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *Incr = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
      IRB.CreateStore(Incr, MapPtrIdx)
          ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      /* Set prev_loc to cur_loc >> 1 */

      StoreInst *Store =
          IRB.CreateStore(ConstantInt::get(Int32Ty, cur_loc >> 1), AFLPrevLoc);
      Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      inst_blocks++;
    }

  /* Say something nice. */

  if (!be_quiet) {

    if (!inst_blocks)
      WARNF("No instrumentation targets found.");
    else
      OKF("Instrumented %u locations (%s mode, ratio %u%%).", inst_blocks,
          getenv("AFL_HARDEN")
              ? "hardened"
              : ((getenv("AFL_USE_ASAN") || getenv("AFL_USE_MSAN"))
                     ? "ASAN/MSAN"
                     : "non-hardened"),
          inst_ratio);
  }

  /*
     2. instrument of all function
     we do not return here, AFL pass has done instrument at every BasicBlock
     we will go on to instrument on every first bb of every function
     this do not create extra brach or new BasicBlock
  */
  // return true;

  int func_count_fd = open("/home/ubuntu/func_count.txt", O_RDWR | O_CREAT, 0666);
  if(func_count_fd < 0){
    errs() << "[!] function list fd failed \n";
  }
  char buf[100];
  memset(buf, 0x0, 100);
  lseek(func_count_fd, 0, SEEK_SET);
  read(func_count_fd, buf, 100);
  u32 counter = atoi(buf);
  int func_list_fd = open("/home/ubuntu/func_list.txt", O_WRONLY | O_CREAT | O_APPEND, 0666);
  if(func_list_fd < 0){
    errs() << "[!] function list fd failed \n";
  }
  FunctionType *fstate_extract_type =
    FunctionType::get(Int32Ty, ArrayRef<Type *>(), false);
#ifdef NEED_TRACE_INFO
  /* 
    25-3-31
    when we need the call order, define NEED_TRACE_INFO
    the store of fstate map is a linear table
    |  fstate  |  func code  |
    |  fstate  |  func code  |
    ...
    it takes more mem space but get more info of call order

    fname_store(func_index)
  */
  FunctionType *fname_store_function =
      FunctionType::get(Int32Ty, {Int32Ty}, false);
#else
  /* 
    25-3-31
    when we only need the call set, undefine NEED_TRACE_INFO (default)
    the store of fstate map is some buckets, buckets are only created when fstate change
    | fstate |        bucket           |
    | fstate |        bucket           |
    it takes less mem space but lost info of call order

    fname_store(func_index, bucket_index);
  */
  FunctionType *fname_store_function = 
      FunctionType::get(Int32Ty, {Int32Ty, Int32Ty}, false);
#endif



  GlobalVariable *fstate_shm_ptr =
      new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                        GlobalValue::ExternalLinkage, 0, "__fstate_shm_ptr");
#ifndef NEED_TRACE_INFO
  GlobalVariable *fstate_bucket_count =
      new GlobalVariable(M, Int32Ty, false,
                        GlobalValue::ExternalLinkage, 0, "__fstate_bucket_count");
  GlobalVariable *fstate_current_state =
      new GlobalVariable(M, Int32Ty, false,
                        GlobalValue::ExternalLinkage, 0, "__fstate_current_state");
#endif

  auto em_fstate_extract =
      M.getOrInsertFunction("fstate_extract", fstate_extract_type);
  auto em_fname_store =
      M.getOrInsertFunction("fname_store", fname_store_function);

  // iter all functions to instrument at first site of function
  for (Function &F : M) {
    if (F.isDeclaration())
      continue;
    BasicBlock &entry_block = F.front();
    IRBuilder<> IRB(&*entry_block.getFirstInsertionPt());
    if (F.getName().find("llvm", 0) != StringRef::npos)
      continue;

#ifdef NEED_TRACE_INFO
    CallInst *fstate_call =
      IRB.CreateCall(em_fstate_extract, None, "fuzzer_state");

   
    LoadInst *obj_ptr = IRB.CreateLoad(fstate_shm_ptr);
      obj_ptr->setMetadata(M.getMDKindID("nosanitize"),
                            MDNode::get(C, None));
    Value *cast_obj = IRB.CreateBitCast(
      obj_ptr, PointerType::get(Int32Ty, 0), "casted_ptr");
    IRB.CreateStore(fstate_call, cast_obj)
      ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      
    /*
      update pointer
    */
   
    Value *add_res = IRB.CreateGEP(
      Int8Ty, obj_ptr, ConstantInt::get(Int32Ty, 4), "moved ptr");
    IRB.CreateStore(add_res, fstate_shm_ptr)
      ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      
    /*
      store fname
    */
#endif

    counter++;
    char record[0x100];
    memset(record, 0x0, 0x100);
    sprintf(record, "%d %s\n", counter, F.getName().str().c_str());
    write(func_list_fd, record, strlen(record));

    std::vector<Value *> fname_store_args;
    ConstantInt *fname_code = ConstantInt::get(Int32Ty, counter);
    fname_store_args.push_back(fname_code);
#ifndef NEED_TRACE_INFO
    LoadInst *state_count = IRB.CreateLoad(fstate_bucket_count);
    state_count->setMetadata(M.getMDKindID("nosanitize"),
                              MDNode::get(C, None));
    fname_store_args.push_back(state_count);
#endif

    IRB.CreateCall(em_fname_store, fname_store_args, "fname_store");
    
  }
  char count_str[100];
  memset(count_str, 0x0, 100);
  sprintf(count_str, "%d", counter);
  lseek(func_count_fd, 0, SEEK_SET);
  write(func_count_fd, count_str, 100);
  close(func_list_fd);
  close(func_count_fd);
  /*
    3.fuzzer state extraction
  */

#ifdef AFLNET_STATE_AWARE
  /*
    3.1 for AFLNET, we should be aware of state change as soon as the response sent
    not until the client receive the response

    3.1.1 For openssl
    on linux platform, openssl send network messages by write (BIO_write implementation)
    However, write is too general. We decided to instrument at sock_write in bss_sock.c
    aflnet_openssl_extract(buf, len);
  */
  FunctionType* aflnet_openssl_extract_type = FunctionType::get(Int32Ty, {PointerType::get(Int8Ty, 0), Int32Ty}, false);
  auto aflnet_openssl_extract_func = M.getOrInsertFunction("aflnet_openssl_extract", aflnet_openssl_extract_type);

  for(auto &F : M){
    if(F.isDeclaration()) continue;
  /*
    openssl
  */
    if(F.getName() == "sock_write"){
      BasicBlock &entry_block = F.front();
      IRBuilder<> IRB(&*entry_block.getFirstInsertionPt());
      Argument* send_buf = F.getArg(1);
      Argument* send_len = F.getArg(2);
      std::vector<Value *> aflnet_openssl_extract_args;
      aflnet_openssl_extract_args.push_back(send_buf);
      aflnet_openssl_extract_args.push_back(send_len);
      IRB.CreateCall(aflnet_openssl_extract_func, aflnet_openssl_extract_args, "aflnet_openssl_result");
    }
  }
  
#endif

#ifdef STATEAFL_STATE_AWARE
  /* 
    for STATEAFL, we can not get accurate state code when running
    we record abstract state code
    at the end, map the abstract code to the accurate state code
  */
  /*
    3.1 implement STATEAFL instrument it self
  */
 
#endif
  return true;
}
static void registerAFLPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {

  PM.add(new AFLCoverage());
}

static RegisterStandardPasses
    RegisterAFLPass(PassManagerBuilder::EP_ModuleOptimizerEarly,
                    registerAFLPass);

static RegisterStandardPasses
    RegisterAFLPass0(PassManagerBuilder::EP_EnabledOnOptLevel0,
                     registerAFLPass);
