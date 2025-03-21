#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/CallSite.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/CFLAndersAliasAnalysis.h"
#include "llvm/Analysis/MemoryLocation.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/LLVMContext.h"
#include <set>

using namespace llvm;
#define HPA_DEBUG_PASS

namespace {
struct CrossFunctionHeapAnalysis : public ModulePass {
    static char ID;
    CrossFunctionHeapAnalysis() : ModulePass(ID) {}

    void getAnalysisUsage(AnalysisUsage &AU) const override {
        AU.addRequired<CFLAndersAAWrapperPass>();
        AU.setPreservesAll();
    }

    std::map<Function *, std::set<Value *>> FunctionToHeapVars;
    std::map<Value*, Value*> call_sites;
    

    bool isAlloc(StringRef fn){
        return fn == "my_malloc" || fn == "operator new" || fn == "calloc" || fn == "realloc";
    }

    Value* getAllocSize(CallInst* CI){
        StringRef fn = CI->getCalledFunction()->getName();
        if(fn == "my_malloc"){
            Value* allocSize = CI->getOperand(0);
            if(ConstantInt* consti = dyn_cast<ConstantInt>(allocSize)){
                return consti;
            }
        }
        else if(fn == "realloc"){
            Value* allocSize = CI->getOperand(1);
            if(ConstantInt* consti = dyn_cast<ConstantInt>(allocSize)){
                return consti;
            }
        }
        else{
            return nullptr;
        }
    }

    bool runOnModule(Module &M) override {
        CFLAndersAAResult &AA = getAnalysis<CFLAndersAAWrapperPass>().getResult();
        
        //1. iter all instructions to get all alloc site
        for(Function &F : M){
            if(F.isDeclaration()) continue;
            for(BasicBlock &B : F){
                for(Instruction &I : B){
                    if(auto* CI = dyn_cast<CallInst>(&I)){
                        Function* callee = CI->getCalledFunction();
                        if(isAlloc(callee->getName())){
                                if(CI->getType()->isPointerTy()){
                                    Value* allocSize = getAllocSize(CI);
                                    if(allocSize != nullptr){
                                        call_sites.insert({CI, allocSize});
                                    }
                                }else{
                                    #ifdef HPA_DEBUG_PASS
                                        errs()<< "alloc space not ptr" << *CI << "\n";
                                    #endif
                                }
                                #ifdef HPA_DEBUG_PASS
                                    errs() << "found alloc func =>" << callee->getName() << " in " << F.getName() << " " << *CI <<"\n" ;
                                #endif
                        }
                    }
                }
            }
        }

        //2. iter all instructions to do alais analysis
        //assumption: functions in the module can access heap vars in many ways
        AAQueryInfo QI =AAQueryInfo();
        for(Function &F : M){
            if(F.isDeclaration()) continue;
            for(BasicBlock &B : F){
                for(Instruction &I : B){
                    if(auto* LI = dyn_cast<LoadInst>(&I)){
                        
                        //LLVM IR is SSA, so load destination is the instruction itself
                        if(LI->getType()->isPointerTy()){
                            
                            for(auto CIp : call_sites){
                                MemoryLocation cli=MemoryLocation(CIp.first,LocationSize(*(((ConstantInt*)(CIp.second))->getValue().getRawData())));
                                AliasResult AS = AA.alias(cli, MemoryLocation(LI), QI);
                                #ifdef HPA_DEBUG_PASS
                                    errs() << "CI ptr => " << *CIp.first <<" size=> "<< cli.Size << " LI ptr => " << MemoryLocation(LI).Ptr << "\n";
                                    errs() << "alias result is  =>" << AS <<"\n";
                                #endif
                            }
                        }
                        #ifdef HPA_DEBUG_PASS
                        #endif
                        

                    }
                }
            }
        }
        return false;
    }
};

char CrossFunctionHeapAnalysis::ID = 0;
static RegisterPass<CrossFunctionHeapAnalysis> X("cross-heap-analysis", "Cross-Function Heap Analysis using CFL-Anders", false, false);
} // namespace
