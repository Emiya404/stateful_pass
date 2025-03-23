#include <llvm/IR/Constants.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/Instructions.h>
#define AFL_LLVM_PASS

#include "../config.h"
#include "../debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

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
     afl-part of the instrument pass
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
     we do not return here, AFL pass has done instrument at every BasicBlock
     we will go on to instrument on every call
     this do not create extra brach or new BasicBlock
  */
  // return true;

  FunctionType *fstate_extract_type =
      FunctionType::get(Int32Ty, ArrayRef<Type *>(), false);
  FunctionType *fname_store_function =
      FunctionType::get(Int32Ty, {PointerType::get(Int8Ty, 0)}, false);

  // ptr for shm to store call trace
  GlobalVariable *fstate_shm_ptr =
      new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__fstate_shm_ptr");

  // new function to extract fuzzer state
  auto em_fstate_extract =
      M.getOrInsertFunction("fstate_extract", fstate_extract_type);
  auto em_fname_store =
      M.getOrInsertFunction("fname_store", fname_store_function);
  // iter all instructions to get all call site
  for (Function &F : M) {
    if (F.isDeclaration())
      continue;
    for (BasicBlock &B : F) {
      for (Instruction &I : B) {
        if (auto *CI = dyn_cast<CallInst>(&I)) {
          /*
             call fstate_extract to extract state of statefuzzer
             result is int32 Type
             %fuzzer_state value stored in the callinst
          */
          if (CI->getCalledFunction()->getName() == "fstate_extract" ||
              CI->getCalledFunction()->getName() == "fname_store" ||
              CI->getCalledFunction()->getName().startswith("llvm"))
            continue;
          int fn_len = CI->getCalledFunction()->getName().size() + 4;
          IRBuilder<> IRB(CI);
          CallInst *fstate_call =
              IRB.CreateCall(em_fstate_extract, None, "fuzzer_state");
          /*
            store the total length of state code and function name to shm
            |  length  | state code |    callee function    |

            fstate_shm_ptr is a variable that stores ptr
            its name specifies not the addr ptr points-to but the addr itself
            we should first read it from variable

         */
          LoadInst *obj_ptr = IRB.CreateLoad(fstate_shm_ptr);
          obj_ptr->setMetadata(M.getMDKindID("nosanitize"),
                               MDNode::get(C, None));
          Value *cast_obj = IRB.CreateBitCast(
              obj_ptr, PointerType::get(Int32Ty, 0), "casted_ptr");
          IRB.CreateStore(ConstantInt::get(Int32Ty, fn_len), cast_obj)
              ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
          /*
             update pointer
          */
          Value *add_res = IRB.CreateGEP(
              Int8Ty, obj_ptr, ConstantInt::get(Int32Ty, 4), "moved ptr");
          IRB.CreateStore(add_res, fstate_shm_ptr)
              ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
          /*
             Store the fstate
          */
          obj_ptr = IRB.CreateLoad(fstate_shm_ptr);
          obj_ptr->setMetadata(M.getMDKindID("nosanitize"),
                               MDNode::get(C, None));
          cast_obj = IRB.CreateBitCast(obj_ptr, PointerType::get(Int32Ty, 0),
                                       "casted_ptr");
          IRB.CreateStore(fstate_call, cast_obj)
              ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
          /*
             update pointer
          */
          add_res = IRB.CreateGEP(Int8Ty, obj_ptr, ConstantInt::get(Int32Ty, 4),
                                  "moved ptr");
          IRB.CreateStore(add_res, fstate_shm_ptr)
              ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
          /*
             store fname
          */
          std::vector<Value *> fname_store_args;
          Value *fname_str =
              IRB.CreateGlobalStringPtr(CI->getCalledFunction()->getName());
          fname_store_args.push_back(fname_str);
          IRB.CreateCall(em_fname_store, fname_store_args, "fname_store");
        }
      }
    }
  }
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
