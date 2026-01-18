#include "switcher.hpp"

#include "iostream"
#include <stdexcept>

#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
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
#include <climits>
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

            if (llvm::isa<llvm::object::ELFObjectFileBase>(obj)) {
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
    uint64_t stubAddr,
    uint64_t counterAddr,
    const std::vector<uint64_t>& variantAddrs) {
    if (targetTriple.rfind("x86_64", 0) == 0) {
        std::vector<uint8_t> bytes;
        auto emit8 = [&](uint8_t b) { bytes.push_back(b); };
        auto emit32 = [&](uint32_t v) {
            bytes.push_back(static_cast<uint8_t>(v & 0xFF));
            bytes.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
            bytes.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
            bytes.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
        };
        auto emit64 = [&](uint64_t v) {
            emit32(static_cast<uint32_t>(v & 0xFFFFFFFFu));
            emit32(static_cast<uint32_t>((v >> 32) & 0xFFFFFFFFu));
        };

        // mov rax, imm64
        emit8(0x48); emit8(0xB8); emit64(counterAddr);
        // mov rcx, [rax]
        emit8(0x48); emit8(0x8B); emit8(0x08);
        // lea rdx, [rcx+1]
        emit8(0x48); emit8(0x8D); emit8(0x51); emit8(0x01);
        // mov [rax], rdx
        emit8(0x48); emit8(0x89); emit8(0x10);

        // Compare chain against rcx (counter before increment).
        struct Patch { size_t at; uint64_t target; };
        std::vector<Patch> patches;

        for (size_t i = 0; i + 1 < variantAddrs.size(); ++i) {
            // cmp rcx, imm32
            emit8(0x48); emit8(0x81); emit8(0xF9);
            emit32(static_cast<uint32_t>(i));
            // je rel32
            emit8(0x0F); emit8(0x84);
            patches.push_back(Patch{bytes.size(), variantAddrs[i]});
            emit32(0);
        }

        // jmp rel32 (default to last variant)
        emit8(0xE9);
        patches.push_back(Patch{bytes.size(), variantAddrs.back()});
        emit32(0);

        auto writeRel32 = [&](size_t at, uint64_t target) {
            const int64_t rel = static_cast<int64_t>(target) -
                                static_cast<int64_t>(stubAddr + at + 4);
            if (rel < INT32_MIN || rel > INT32_MAX) {
                throw std::runtime_error("rel32 out of range for switcher stub");
            }
            const uint32_t rel32 = static_cast<uint32_t>(rel);
            bytes[at + 0] = static_cast<uint8_t>(rel32 & 0xFF);
            bytes[at + 1] = static_cast<uint8_t>((rel32 >> 8) & 0xFF);
            bytes[at + 2] = static_cast<uint8_t>((rel32 >> 16) & 0xFF);
            bytes[at + 3] = static_cast<uint8_t>((rel32 >> 24) & 0xFF);
        };

        for (const auto& patch : patches) {
            writeRel32(patch.at, patch.target);
        }

        return bytes;
    }
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
    const bool isX64 = targetTriple.rfind("x86_64", 0) == 0;

    llvm::Value* idx = builder.CreateLoad(i64, counterPtr, "idx");
    llvm::Value* next = builder.CreateAdd(idx, builder.getInt64(1), "next");
    builder.CreateStore(next, counterPtr);

    std::vector<llvm::BasicBlock*> caseBlocks;
    caseBlocks.reserve(variantAddrs.size());
    for (size_t i = 0; i < variantAddrs.size(); ++i) {
        caseBlocks.push_back(llvm::BasicBlock::Create(context, "case", fn));
    }

    llvm::BasicBlock* defaultBlock = caseBlocks.back();
    llvm::BasicBlock* cur = entry;
    for (size_t i = 0; i + 1 < variantAddrs.size(); ++i) {
        llvm::Value* cmp = builder.CreateICmpEQ(idx, builder.getInt64(i));
        llvm::BasicBlock* next = llvm::BasicBlock::Create(context, "chk", fn);
        builder.CreateCondBr(cmp, caseBlocks[i], next);
        builder.SetInsertPoint(next);
        cur = next;
    }
    builder.CreateBr(defaultBlock);

    auto* calleeTy = llvm::FunctionType::get(voidTy, {}, false);
    for (size_t i = 0; i < variantAddrs.size(); ++i) {
        builder.SetInsertPoint(caseBlocks[i]);
        if (isX64) {
            auto* asmTy = llvm::FunctionType::get(voidTy, {i64}, false);
            auto* jmpAsm = llvm::InlineAsm::get(asmTy, "jmp *$0", "r", true);
            builder.CreateCall(jmpAsm, {builder.getInt64(variantAddrs[i])});
            builder.CreateUnreachable();
        } else {
            llvm::Value* calleePtr = builder.CreateIntToPtr(
                builder.getInt64(variantAddrs[i]),
                llvm::PointerType::getUnqual(calleeTy), "callee");
            auto* call = builder.CreateCall(calleeTy, calleePtr, {});
            call->setTailCallKind(llvm::CallInst::TCK_Tail);
            builder.CreateRetVoid();
        }
    }

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
