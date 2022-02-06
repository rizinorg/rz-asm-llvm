// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <llvm/MC/MCAsmInfo.h>
#include <llvm/MC/MCCodeEmitter.h>
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCParser/MCTargetAsmParser.h>
#include <llvm/MC/MCStreamer.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>

#include <rz_lib.h>
#include <rz_asm.h>

using namespace llvm;

class BufferMCStreamer : public MCStreamer {
	private:
		std::unique_ptr<MCCodeEmitter> emitter;
		RzStrBuf *buf_out;

		bool emitSymbolAttribute(MCSymbol *Symbol, MCSymbolAttr Attribute) override { return true; }
		void emitCommonSymbol(MCSymbol *Symbol, uint64_t Size, unsigned ByteAlignment) override {}
		void emitZerofill(MCSection *Section, MCSymbol *Symbol = nullptr,
			uint64_t Size = 0, unsigned ByteAlignment = 0,
			SMLoc Loc = SMLoc()) override {}

	public:
		BufferMCStreamer(MCContext &context, std::unique_ptr<MCCodeEmitter> emitter, RzStrBuf *buf_out)
		    : MCStreamer(context), emitter(std::move(emitter)), buf_out(buf_out) {}

		void emitInstruction(const MCInst &inst, const MCSubtargetInfo &sti) override {
			SmallVector<MCFixup, 4> fixups;
			SmallString<256> code;
			raw_svector_ostream os(code);
			emitter->encodeInstruction(inst, os, fixups, sti);
			rz_strbuf_append_n(buf_out, code.data(), code.size());
		}
};

static bool init(void **user) {
	llvm::InitializeAllTargetInfos();
	llvm::InitializeAllTargetMCs();
	llvm::InitializeAllAsmParsers();
	return true;
}

static int assemble(RzAsm *a, RzAsmOp *op, const char *buf) {
	SourceMgr src;
	src.AddNewSourceBuffer(MemoryBuffer::getMemBufferCopy(buf), SMLoc());

	std::string arch_name = a->bits == 64 ? "aarch64" : (a->bits == 16 ? "thumb" : "arm");
	std::string cpu_name = "";
	std::string features_str = "";

	Triple triple;
	std::string triple_name = triple.getTriple();
	std::string error;
	const Target *target = TargetRegistry::lookupTarget(arch_name, triple, error);
	if (!target) {
		RZ_LOG_ERROR("LLVM target not found: %s\n", error.c_str());
		return 0;
	}

	const MCTargetOptions mc_options;
	std::unique_ptr<MCRegisterInfo> mri(target->createMCRegInfo(triple_name));
	std::unique_ptr<MCSubtargetInfo> sti(target->createMCSubtargetInfo(triple_name, cpu_name, features_str));
	std::unique_ptr<MCAsmInfo> mai(target->createMCAsmInfo(*mri, triple_name, mc_options));
	MCContext Ctx(triple, mai.get(), mri.get(), sti.get(), &src, &mc_options);
	std::unique_ptr<MCObjectFileInfo> mofi(target->createMCObjectFileInfo(Ctx, false));
	Ctx.setObjectFileInfo(mofi.get());

	std::unique_ptr<MCInstrInfo> mcii(target->createMCInstrInfo());
	std::unique_ptr<MCCodeEmitter> ce(target->createMCCodeEmitter(*mcii, *mri, Ctx));
	std::unique_ptr<MCStreamer> streamer(std::make_unique<BufferMCStreamer>(Ctx, std::move(ce), &op->buf));

	std::unique_ptr<MCAsmParser> parser(createMCAsmParser(src, Ctx, *streamer, *mai));
	std::unique_ptr<MCTargetAsmParser> tap(target->createMCAsmParser(*sti.get(), *parser, *mcii.get(), mc_options));
	if (!tap) {
		RZ_LOG_ERROR("LLVM target does not support assembly parsing.\n");
		return 0;
	}
	parser->setTargetParser(*tap);
	if(parser->Run(false)) {
		return 0;
	}
	return rz_strbuf_length(&op->buf);
}

static RzAsmPlugin asm_plugin = {
	/* .name = */ "arm.llvm",
	/* .arch = */ "arm",
	/* .author = */ "thestr4ng3r",
	/* .version = */ nullptr,
	/* .cpus = */ nullptr,
	/* .desc = */ "Assembler using LLVM MC",
	/* .license = */ "LGPL3",
	/* .bits = */ 16 | 32 | 64,
	/* .endian = */ 0,
	/* .init = */ init,
	/* .fini = */ nullptr,
	/* .disassemble = */ nullptr,
	/* .assemble = */ assemble,
	/* .modify */ nullptr,
	/* .mnemonics = */ nullptr,
	/* .features = */ nullptr
};

RZ_API extern "C" RzLibStruct rizin_plugin = {
	/* .type = */ RZ_LIB_TYPE_ASM,
	/* .data = */ &asm_plugin,
	/* .version = */ RZ_VERSION,
	/* .free = */ nullptr,
	/* .pkgname = */ "rz-asm-llvm"
};
