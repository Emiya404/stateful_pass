#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/CallSite.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/IRBuilder.h"
#include <set>

using namespace llvm;


namespace {
struct CallTransform : public ModulePass {
    static char ID;
    CallTransform() : ModulePass(ID) {}

    bool runOnModule(Module &M) override {
        //ready for all the type to instument
        LLVMContext& ctx = M.getContext();
        IntegerType* i8_type = IntegerType::get(ctx, 8);
        IntegerType* i64_type = IntegerType::get(ctx, 64);
        FunctionType* fstate_extract_type = FunctionType::get(i64_type,ArrayRef<Type*>(),false);

        //ptr for shm to store call trace
        M.getOrInsertGlobal("em_calltrace_shm", PointerType::get(i8_type, 0));
        GlobalVariable* globalVariable = M.getNamedGlobal("em_calltrace_shm");
        
        //new function to extract fuzzer state
        auto em_fstate_extract = M.getOrInsertFunction("fstate_extract", fstate_extract_type);

        //iter all instructions to get all call site
        for(Function &F : M){
            if(F.isDeclaration()) continue;
            for(BasicBlock &B : F){
                for(Instruction &I : B){
                    if(auto* CI = dyn_cast<CallInst>(&I)){
                        
                        //--get call function name
                        /*
                        */
                       IRBuilder<> builder(CI);
                       builder.CreateCall(em_fstate_extract, None, "fuzzer_state");
                       builder.CreateLoad()
                        //--get fuzzzer instrument state
                        /*
                        */
                        
                    }
                }
            }
        }
        return false;
    }
};

char CallTransform::ID = 0;
static RegisterPass<CallTransform> X("call-func-instrument", "do instrument in SUT to extract call trace", false, false);
} // namespace
