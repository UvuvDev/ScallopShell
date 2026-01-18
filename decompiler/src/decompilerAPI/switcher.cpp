#include "switcher.hpp"

#include "iostream"
#include <stdexcept>

#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CodeGen.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Object/ObjectFile.h"
#include "llvm/Object/ELFObjectFile.h"
#include <cstdint>
#include <fstream>
#include <string>

namespace {
std::vector<uint8_t> extractFunctionBytesFromFile(const std::string& path,
                                                  const std::string& symbolName) {
    auto bufferOrError = llvm::MemoryBuffer::getFile(path);
    if (!bufferOrError) {
        throw std::runtime_error("Failed to read object file: " + path);
    }
    std::unique_ptr<llvm::MemoryBuffer> buffer = std::move(*bufferOrError);

    auto objOrError = llvm::object::ObjectFile::createObjectFile(buffer->getMemBufferRef());
    if (!objOrError) {
        throw std::runtime_error("Failed to parse object file: " +
                                 llvm::toString(objOrError.takeError()));
    }
    llvm::object::ObjectFile* obj = objOrError->get();

    uint64_t symAddr = 0;
    uint64_t symSize = 0;
    llvm::object::SectionRef symSection;
    bool found = false;

    for (const auto& sym : obj->symbols()) {
        auto nameOrErr = sym.getName();
        if (!nameOrErr) {
            continue;
        }
        llvm::StringRef name = *nameOrErr;
        if (name == symbolName || name == ("_" + symbolName)) {
            auto addrOrErr = sym.getAddress();
            if (!addrOrErr) {
                continue;
            }
            symAddr = *addrOrErr;

            if (auto* elfObj = llvm::dyn_cast<llvm::object::ELFObjectFileBase>(obj)) {
                llvm::object::ELFSymbolRef elfSym(sym);
                symSize = elfSym.getSize();
            } else {
                symSize = 0;
            }

            auto secOrErr = sym.getSection();
            if (!secOrErr || *secOrErr == obj->section_end()) {
                continue;
            }
            symSection = **secOrErr;
            found = true;
            break;
        }
    }

    if (!found) {
        throw std::runtime_error("Symbol not found with section: " + symbolName);
    }

    uint64_t secAddr = symSection.getAddress();

    auto contentOrErr = symSection.getContents();
    if (!contentOrErr) {
        throw std::runtime_error("Failed to get section contents: " +
                                 llvm::toString(contentOrErr.takeError()));
    }
    llvm::StringRef secData = *contentOrErr;

    uint64_t offsetInSection = symAddr - secAddr;
    if (symSize == 0) {
        symSize = secData.size() - offsetInSection;
    }

    if (offsetInSection + symSize > secData.size()) {
        throw std::runtime_error("Symbol bounds exceed section size");
    }

    const uint8_t* start = reinterpret_cast<const uint8_t*>(secData.data() + offsetInSection);
    return std::vector<uint8_t>(start, start + symSize);
}
} // namespace

std::vector<uint8_t> emitSwitcherStub(
    const std::string& targetTriple,
    uint64_t counterAddr,
    uint64_t tableAddr,
    uint64_t variantCount) {
    llvm::InitializeAllTargets();
    llvm::InitializeAllTargetMCs();
    llvm::InitializeAllAsmPrinters();
    llvm::InitializeAllAsmParsers();

    std::string error;
    const llvm::Target* target = llvm::TargetRegistry::lookupTarget(targetTriple, error);
    if (!target) {
        throw std::runtime_error("LLVM target lookup failed: " + error);
    }

    llvm::TargetOptions opt;
    auto targetMachine = std::unique_ptr<llvm::TargetMachine>(
        target->createTargetMachine(
            targetTriple, "generic", "", opt, llvm::Reloc::Static,
            llvm::CodeModel::Small, llvm::CodeGenOptLevel::Default));
    if (!targetMachine) {
        throw std::runtime_error("Failed to create LLVM TargetMachine");
    }

    llvm::LLVMContext context;
    auto module = std::make_unique<llvm::Module>("scallop_switcher", context);
    module->setTargetTriple(targetTriple);
    module->setDataLayout(targetMachine->createDataLayout());

    llvm::IRBuilder<> builder(context);
    auto* i64 = builder.getInt64Ty();
    auto* i64ptr = llvm::PointerType::getUnqual(i64);
    auto* voidTy = builder.getVoidTy();
    auto* fnType = llvm::FunctionType::get(voidTy, {}, false);
    auto* fn = llvm::Function::Create(fnType, llvm::Function::ExternalLinkage,
                                      "scallop_switcher", module.get());

    auto* entry = llvm::BasicBlock::Create(context, "entry", fn);
    builder.SetInsertPoint(entry);

    llvm::Value* counterPtr = builder.CreateIntToPtr(
        builder.getInt64(counterAddr), i64ptr, "counter_ptr");
    llvm::Value* tablePtr = builder.CreateIntToPtr(
        builder.getInt64(tableAddr), i64ptr, "table_ptr");
    llvm::Value* countVal = builder.getInt64(variantCount);

    llvm::Value* idx = builder.CreateLoad(i64, counterPtr, "idx");
    llvm::Value* next = builder.CreateAdd(idx, builder.getInt64(1), "next");
    builder.CreateStore(next, counterPtr);

    llvm::Value* last = builder.CreateSub(countVal, builder.getInt64(1), "last");
    llvm::Value* clamp = builder.CreateICmpUGE(idx, last, "clamp");
    llvm::Value* sel = builder.CreateSelect(clamp, last, idx, "sel");

    llvm::Value* slot = builder.CreateInBoundsGEP(i64, tablePtr, sel, "slot");
    llvm::Value* targetVal = builder.CreateLoad(i64, slot, "target");
    auto* calleeTy = llvm::FunctionType::get(voidTy, {}, false);
    llvm::Value* calleePtr = builder.CreateIntToPtr(
        targetVal, llvm::PointerType::getUnqual(calleeTy), "callee");
    auto* call = builder.CreateCall(calleeTy, calleePtr, {});
    call->setTailCallKind(llvm::CallInst::TCK_Tail);
    builder.CreateRetVoid();

    llvm::SmallString<128> tempPath;
    int fd = -1;
    if (auto ec = llvm::sys::fs::createTemporaryFile("scallop_switcher", "o", fd, tempPath)) {
        throw std::runtime_error("Failed to create temp object file");
    }
    {
        llvm::raw_fd_ostream objStream(fd, true);
        llvm::legacy::PassManager pm;
        if (targetMachine->addPassesToEmitFile(pm, objStream, nullptr,
                                               llvm::CodeGenFileType::ObjectFile)) {
            throw std::runtime_error("LLVM TargetMachine cannot emit object file");
        }
        pm.run(*module);
        objStream.flush();
        objStream.close();
    }

    const std::string tempPathStr = tempPath.str().str();
    auto bytes = extractFunctionBytesFromFile(tempPathStr, "scallop_switcher");
    llvm::sys::fs::remove(tempPath);
    return bytes;
}
