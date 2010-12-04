#include <asm.hh>
#include <util.hh>
#include <mremap.hh>
#include <cassert>
#include <iterator>
#include <iostream>
#include <cstdio>
#include <cstring>
#include <sys/mman.h>

using namespace Asm;

// Register codes.
// (REX, Reg Field).
#define R REX_PREFIX
#define W (REX_PREFIX | REX_W)
#define B (REX_PREFIX | REX_B | REX_W)
static const uint8_t Asm::register_codes[] = {
    0,0,  0,1,  0,2,  0,3,  0,4,  0,5,  0,6,  0,7, // EAX-EDI
    W,0,  W,1,  W,2,  W,3,  W,4,  W,5,  W,6,  W,7, // RAX-RDI
    B,0,  B,1,  B,2,  B,3,  B,4,  B,5,  B,6,  B,7, // R8D-R15D
    0,0,  0,1,  0,2,  0,3,  0,4,  0,5,  0,6,  0,7, // MM0-MM7
    // TODO: Check if REX_W is needed for the following:
    0,0,  0,1,  0,2,  0,3,  0,4,  0,5,  0,6,  0,7, // XMM0-XMM7
};
static char const *Asm::register_names[] = {
    "EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI",
    "RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI",
    "R8D", "R9D", "R10D", "R11D", "R12D", "R13D", "R14D", "R15D",
    "MM0", "MM1", "MM2", "MM4", "MM5", "MM6", "MM7",
    "XMM0", "XMM1", "XMM2", "XMM3", "XMM4", "XMM5", "XMM6", "XMM7",
    "FS", "GS",
    "NOT_A_REGISTER"
};
char const *Asm::register_name(Register reg) { return register_names[reg]; }
uint8_t Asm::register_rex(Register reg) { assert(reg < FS); return register_codes[(unsigned)reg * 2]; }
uint8_t Asm::register_code(Register reg) { assert(reg < FS); return register_codes[((unsigned)reg * 2)+1]; }
#undef W
#undef R
#undef B

// Registers which can be specified using +r* (in 64-bit mode).
bool has_additive_code_64(Register r)
{
    return r >= RAX && r <= R15D;
}
bool has_additive_code_32(Register r)
{
    return r >= EAX && r <= EDI;
}

static unsigned Asm::register_byte_sizes[] = {
    4, 4, 4, 4, 4, 4, 4, 4, // EAX-EDI
    8, 8, 8, 8, 8, 8, 8, 8, // RAX-RDI
    8, 8, 8, 8, 8, 8, 8, 8, // R8D-R15D
    8, 8, 8, 8, 8, 8, 8, 8, // MM0-MM7
    8, 8, 8, 8, 8, 8, 8, 8, // XMM0-XMM7
};
unsigned Asm::register_byte_size(Register reg) { assert(reg <= XMM7); return register_byte_sizes[reg]; }

static uint8_t raw_modrm(uint8_t mod, uint8_t rm, uint8_t reg)
{
    assert(mod < 5 && rm < 9 && reg < 9);
    return (mod << 6) | (reg << 3) | rm;
}

// Note that this excludes the 16-bit registers.
static bool is_gp3264_register(Register reg)
{
    return (reg >= EAX && reg <= EDI) || (reg >= RAX && reg <= RDI) || (reg >= R8D && reg <= R15D);
}

struct RawModrmSib {
    uint8_t modrm;
    uint8_t sib; // Set to 0 if none, since 0 is not a valid SIB.
};
static RawModrmSib raw_modrmsib(ModrmSib const &modrmsib)
{
    RawModrmSib r;
    uint8_t mod, rm, reg;

    // TODO: Check for consistency in size of rm and reg.

    // Set mod.
    if (modrmsib.disp_size == DISP_SIZE_NONE)
        mod = 3;
    else if ((modrmsib.disp == 0 && modrmsib.rm_reg != EBP) || modrmsib.rm_reg == NOT_A_REGISTER)
        mod = 0;
    else if(modrmsib.disp_size == DISP_SIZE_8)
        mod = 1;
    else if (modrmsib.disp_size == DISP_SIZE_32)
        mod = 2;
    // Set rm.
    if (modrmsib.scale != SCALE_1)
        rm = 4;
    else if (modrmsib.rm_reg == NOT_A_REGISTER)
        rm = 5;
    else {
        assert(is_gp3264_register(modrmsib.rm_reg) && modrmsib.rm_reg != ESP);
        rm = register_code(modrmsib.rm_reg);
    }
    // Set reg.
    reg = (modrmsib.reg != NOT_A_REGISTER ? register_code(modrmsib.reg) : 0);

    r.modrm = raw_modrm(mod, rm, reg);

    // Add SIB if required.
    if (modrmsib.scale == SCALE_1) {
        r.sib = 0;
    }
    else {
        // SIB has the same structure as a modrm byte, so we can use raw_modrm again.

        // Set mod.
        uint8_t sib_mod, sib_rm, sib_reg;
        if (modrmsib.scale == SCALE_2)
            sib_mod = 1;
        else if (modrmsib.scale == SCALE_4)
            sib_mod = 2;
        else if (modrmsib.scale == SCALE_8)
            sib_mod = 3;
        // Set rm (index).
        if (modrmsib.rm_reg == NOT_A_REGISTER)
            sib_rm = 4;
        else {
            assert(is_gp3264_register(modrmsib.rm_reg) && modrmsib.rm_reg != ESP);
            sib_rm = register_code(modrmsib.rm_reg);
        }
        // Set reg (base).
        assert(is_gp3264_register(modrmsib.base_reg));
        sib_reg = register_code(modrmsib.base_reg);

        // Note that reg/rm are in the opposite order as compared to the real modrm byte.
        r.sib = raw_modrm(sib_mod, sib_reg, sib_rm);
    }

    return r;
}

Register Asm::ModrmSib::simple_register() const
{
    if (scale == SCALE_1 && reg == NOT_A_REGISTER && disp_size == DISP_SIZE_NONE)
        return rm_reg;
    else
        return NOT_A_REGISTER;
}

bool Asm::ModrmSib::gp3264_registers_only() const
{
    return (rm_reg == NOT_A_REGISTER || (rm_reg >= EAX && rm_reg <= R15D)) &&
           (reg == NOT_A_REGISTER || (reg >= EAX && reg <= R15D));
}

// Creates a ModrmSib where rm is memory.
namespace Asm {
ModrmSib mem_ModrmSib2op(Register reg, Register base, Register index, Scale scale, int32_t displacement, bool short_displacement)
{
    return ModrmSib(/*rm_reg*/    index == NOT_A_REGISTER ? base : index,
                    /*disp_size*/ short_displacement ? DISP_SIZE_8 : DISP_SIZE_32,
                    /*disp*/      displacement,
                    /*reg*/       reg,
                    /*base_reg*/  index == NOT_A_REGISTER ? NOT_A_REGISTER : base,
                    /*scale*/     scale);
}
ModrmSib mem_ModrmSib1op(Register base, Register index, Scale scale, int32_t displacement, bool short_displacement)
{
    return mem_ModrmSib2op(NOT_A_REGISTER, base, index, scale, displacement, short_displacement);
}
ModrmSib reg_ModrmSib(Register reg, Register rm)
{
    return ModrmSib(rm, DISP_SIZE_NONE, /*displacement*/ 0, reg);
}
ModrmSib reg_ModrmSib(Register rm)
{
    return ModrmSib(rm);
}
}

// Using these is quicker than going via a ModrmSib in simple cases where there's no SIB.
static uint8_t reg_reg_modrm(Register reg, Register rm)
{
    return raw_modrm(3, register_code(rm), register_code(reg));
}
static uint8_t reg_modrm(Register reg) // Single register.
{
    return 0xC0 + register_code(reg);
}

static void rex_reg_code(Register reg, uint8_t &rex, uint8_t &rcode)
{
    rex = register_rex(reg);
    rcode = register_code(reg);
}
#define RRC(reg, v1, v2) uint8_t v1, v2; rex_reg_code(reg, v1, v2)

static uint8_t rex_for_ModrmSib(ModrmSib modrmsib)
{
    if (modrmsib.rm_reg != NOT_A_REGISTER)
        return register_rex(modrmsib.rm_reg);
    else if (modrmsib.reg != NOT_A_REGISTER)
        return register_rex(modrmsib.reg);
    else if (modrmsib.base_reg != NOT_A_REGISTER)
        return register_rex(modrmsib.base_reg);
}

// Append byte:
#define AB(byte) (w.a(static_cast<uint8_t>(byte)))
// Append byte if byte is non-zero:
#define ABIFNZ(byte) ((byte) ? (w.a(static_cast<uint8_t>(byte)),0) : 0)
// Append zero-terminated constant:
#define AZ(bytes) (w.a(reinterpret_cast<const uint8_t*>(bytes), sizeof(bytes)-1))
// Append non-zero-terminated constant:
#define A(bytes) (w.a(reinterpret_cast<const uint8_t*>(bytes), sizeof(bytes)))
// Append with length specified:
#define AL(bytes, l) (w.a(reinterpret_cast<const uint8_t*>(bytes)), l)
// Append 32-bit value:
#define A32(addr) do { uint32_t x__ = addr; w.a(reinterpret_cast<const uint8_t*>(&x__), 4); } while (0)
// Append 64-bit value:
#define A64(addr) do { uint64_t x__ = addr; w.a(reinterpret_cast<const uint8_t*>(&x__), 8); } while (0)

#define REX_W_S "\x48" // REX_W_S[0] == (REX_PREFIX | REX_W)

template <class WriterT>
static void write_modrmsib(WriterT &w, RawModrmSib const &rawmodrmsib)
{
    AB(rawmodrmsib.modrm);
    ABIFNZ(rawmodrmsib.sib);
}

template <class WriterT>
static void write_disp(WriterT &w, ModrmSib const &modrmsib)
{
    if (modrmsib.disp != 0) {
        if (modrmsib.disp_size == DISP_SIZE_8)
            AB(static_cast<uint8_t>(modrmsib.disp));
        else if (modrmsib.disp_size == DISP_SIZE_32)
            A32(modrmsib.disp);
        else assert(0);
    }
}

template <class IntT>
Disp<IntT> Asm::mkdisp(IntT i, DispOp op) { return Disp<IntT>(i, op); }
template Disp<int8_t> Asm::mkdisp<int8_t>(int8_t i, DispOp op);
template Disp<int32_t> Asm::mkdisp<int32_t>(int32_t i, DispOp op);

//
// <<<<<<<<<< START OF INSTRUCTIONS <<<<<<<<<<
//

//
// ADC, ADD, IMUL, MUL, SUB
//

template <class WriterT, uint8_t OPCODE>
static void add_rm_reg_(WriterT &w, ModrmSib const &modrmsib)
{
    assert(modrmsib.gp3264_registers_only());
    ABIFNZ(rex_for_ModrmSib(modrmsib));
    AB(OPCODE);
    write_modrmsib(w, raw_modrmsib(modrmsib));
    write_disp(w, modrmsib);
}

#define INST(name, opcode) \
    template <class WriterT> void Asm::Assembler<WriterT>:: \
    name (ModrmSib const &modrmsib) \
    { add_rm_reg_<WriterT, opcode>(w, modrmsib); }
INST(adc_rm_reg, 0x11)
INST(adc_reg_rm, 0x13)
INST(add_rm_reg, 0x01)
INST(add_reg_rm, 0x03)
INST(sub_rm_reg, 0x29)
INST(sub_reg_rm, 0x2B)
#undef INST

template <class WriterT, Size size, uint8_t SIMPLE_OPCODE, uint8_t COMPLEX_OPCODE, Register EXTENSION>
static void add_rmXX_imm32_(WriterT &w, ModrmSib modrmsib, uint32_t src)
{
    assert(modrmsib.reg == NOT_A_REGISTER && modrmsib.gp3264_registers_only());

    if (modrmsib.simple_register() == EAX) {
        assert(size == SIZE_32);
        AB(SIMPLE_OPCODE);
    }
    else if (modrmsib.simple_register() == RAX) {
        assert(size == SIZE_64);
        AB(REX_PREFIX | REX_W);
        AB(SIMPLE_OPCODE);
    }
    else {
        modrmsib.reg = EXTENSION;

        if (size == SIZE_64)
            AB(REX_PREFIX | REX_W);
        AB(COMPLEX_OPCODE);
        write_modrmsib(w, raw_modrmsib(modrmsib));
        write_disp(w, modrmsib);
    }

    A32(src);
}

#define INST(name, size, simple_opcode, complex_opcode, extension) \
    template <class WriterT> void Asm::Assembler<WriterT>:: \
    name (ModrmSib const &modrmsib, uint32_t src) \
    { add_rmXX_imm32_<WriterT, size, simple_opcode, complex_opcode, extension>(w, modrmsib, src); }
INST(adc_rm32_imm32, SIZE_32, 0x15, 0x81, EDX/*2*/)
INST(adc_rm64_imm32, SIZE_64, 0x15, 0x81, EDX/*2*/)
INST(add_rm32_imm32, SIZE_32, 0x05, 0x81, EAX/*0*/)
INST(add_rm64_imm32, SIZE_64, 0x05, 0x81, EAX/*0*/)
INST(sub_rm32_imm32, SIZE_32, 0x2D, 0x81, EBP/*5*/)
INST(sub_rm64_imm32, SIZE_64, 0x2D, 0x81, EBP/*5*/)
#undef INST

template <class WriterT>
void Asm::Assembler<WriterT>::imul_reg_rm(ModrmSib const &modrmsib)
{
    assert(modrmsib.gp3264_registers_only());
    ABIFNZ(rex_for_ModrmSib(modrmsib));
    AZ("\x0F\xAF");
    write_modrmsib(w, raw_modrmsib(modrmsib));
}

template <class WriterT, bool rexw, Register EXTENSION>
static void mul_dxax_rm_(WriterT &w, ModrmSib modrmsib)
{
    assert(modrmsib.reg == NOT_A_REGISTER && modrmsib.gp3264_registers_only());
    if (rexw)
        AB(REX_PREFIX | REX_W);
    AB(0xF7);
    modrmsib.reg = EXTENSION;
    write_modrmsib(w, raw_modrmsib(modrmsib));
}
#define INST(name, rexw, extension) \
    template <class WriterT> void Asm::Assembler<WriterT>:: \
    name (ModrmSib const &modrmsib) \
    { mul_dxax_rm_<WriterT, rexw, extension>(w, modrmsib); }
INST(imul_rdx_rax_rm, true, ESP/*4*/)
INST(imul_edx_eax_rm, false, ESP/*4*/)
INST(mul_rdx_rax_rm, true, EBP/*5*/)
INST(mul_edx_eax_rm, false, EBP/*5*/)
#undef INST

//
// CMP.
//
template <class WriterT, unsigned BYTE_SIZE, uint8_t REXBYTE, uint8_t OPCODE, Register EXTENSION, class ImmT, Size ImmTSize>
static void cmp_rmXX_imm_(WriterT &w, Assembler<WriterT> &a, ModrmSib modrmsib, ImmT imm)
{
    assert(modrmsib.gp3264_registers_only() &&
          modrmsib.reg == NOT_A_REGISTER &&
          (modrmsib.simple_register() != NOT_A_REGISTER ||
           register_byte_size(modrmsib.simple_register()) == BYTE_SIZE));

    if (BYTE_SIZE == 8 && ImmTSize == 4 && modrmsib.simple_register() == RAX) {
        a.cmp_rax_imm32(imm);
    }
    else {
        ABIFNZ(REXBYTE);
        AB(OPCODE);
        modrmsib.reg = EXTENSION;
        write_modrmsib(w, raw_modrmsib(modrmsib));
        w.a(reinterpret_cast<uint8_t*>(&imm), ImmTSize);
    }
}

// Note that sizeof(int32_t) == 8 (on some platforms anyway),
// so we have to have a separate template argument for the "real" size of the immediate argument.
#define INST(name, size, rexbyte, opcode, extension, immtype, immtypesize)  \
    template <class WriterT> void Asm::Assembler<WriterT>:: \
    name (ModrmSib const &modrmsib, immtype imm) \
    { cmp_rmXX_imm_<WriterT, size, rexbyte, opcode, extension, immtype, immtypesize>(w, *this, modrmsib, imm);  }
INST(cmp_rm8_imm8, 1, 0, 0x80, EDI/*7*/, uint8_t, SIZE_8)
INST(cmp_rm32_imm8, 4, 0, 0x83, EDI/*7*/, uint8_t, SIZE_8)
INST(cmp_rm64_imm8, 8, REX_PREFIX | REX_W, 0x83, EDI/*7*/, uint8_t, SIZE_8)
INST(cmp_rm32_imm32, 4, 0, 0x81, EDI/*7*/, uint32_t, SIZE_32)
INST(cmp_rm64_imm32, 8, 0, 0x81, EDI/*7*/, uint32_t, SIZE_32)
#undef INST

template <class WriterT, uint8_t REXBYTE, uint8_t OPCODE, class ImmT, Size ImmTSize>
static void cmp_XX_imm32_(WriterT &w, ImmT imm)
{
    ABIFNZ(REXBYTE);
    AB(OPCODE);
    w.a(reinterpret_cast<uint8_t*>(&imm), ImmTSize);
}

#define INST(name, rexbyte, opcode, immtype, immtypesize) \
    template <class WriterT> void Asm::Assembler<WriterT>:: \
    name (immtype imm) \
    { cmp_XX_imm32_<WriterT, rexbyte, opcode, immtype, immtypesize>(w, imm); }
INST(cmp_al_imm8, 0, 0x3C, uint8_t, SIZE_8)
INST(cmp_eax_imm32, 0, 0x3D, uint32_t, SIZE_32)
INST(cmp_rax_imm32, REX_PREFIX | REX_W, 0x3D, uint32_t, SIZE_32)
#undef INST

//
// INC, DEC.
//

template <class WriterT, Register EXTENSION>
static void incdec_(WriterT &w, ModrmSib modrmsib)
{
    assert(modrmsib.reg == NOT_A_REGISTER && modrmsib.gp3264_registers_only());
    modrmsib.reg = EXTENSION;
    AB(0xFF);
    write_modrmsib(w, raw_modrmsib(modrmsib));
}

#define INST(name, extension) \
    template <class WriterT> void Asm::Assembler<WriterT>:: \
    name(ModrmSib const &modrmsib) \
    { incdec_<WriterT, extension>(w, modrmsib); }
INST(inc_rm, EAX/*0*/)
INST(dec_rm, ECX/*1*/)
#undef INST

//
// Jcc
//

// Short and near jumps.
template <class WriterT, uint8_t OPCODE_PREFIX, uint8_t OPCODE, class DispT, DispSize disp_size>
static void XX_st_rel_(WriterT &w, DispT disp, BranchHint hint)
{
    std::size_t instruction_size = 1 + disp_size;

    if (hint == BRANCH_HINT_TAKEN) {
        ++instruction_size;
        AB(0x3E);
    }
    else if (hint == BRANCH_HINT_NOT_TAKEN) {
        ++instruction_size;
        AB(0x2E);
    }
    if (OPCODE_PREFIX != 0) {
        ++instruction_size;
        AB(OPCODE_PREFIX);
    }
    AB(OPCODE);
    typename DispT::IntType d = disp.get(instruction_size);
    w.a(reinterpret_cast<uint8_t *>(&d), disp_size);
}
#define INST(prefix, opcode) \
    template <class WriterT> void Asm::Assembler<WriterT>:: \
    prefix ## _st_rel8 (Disp<int8_t> disp, BranchHint hint) \
    { XX_st_rel_<WriterT, 0, opcode, Disp<int8_t>, DISP_SIZE_8>(w, disp, hint); }
#define INST2(prefix, opcode) \
    INST(prefix, opcode) \
    template <class WriterT> void Asm::Assembler<WriterT>:: \
    prefix ## _nr_rel32 (Disp<int32_t> disp, BranchHint hint) \
    { XX_st_rel_<WriterT, 0x0F, opcode + 0x10, Disp<int32_t>, DISP_SIZE_32 >(w, disp, hint); }
INST2(ja, 0x77) INST2(jbe, 0x76) INST2(jc, 0x72)
INST2(jg, 0x7F) INST2(jge, 0x7D) INST2(jl, 0x7C)
INST2(jle, 0x7E) INST2(jnc, 0x73) INST2(jno, 0x71)
INST2(jns, 0x79) INST2(jnz, 0x75) INST2(jo, 0x70)
INST2(jpe, 0x7A) INST2(jpo, 0x7B) INST(jrcxz, 0xE3) // non-use of INST2 for jrcxz is deliberate.
INST2(js, 0x78) INST2(jz, 0x74)
#undef INST2
#undef INST


//
// JMP
//

template <class WriterT, class IntT, Size IntTSize>
static void jmp_nr_relXX_(WriterT &w, IntT disp)
{
    COMPILE_ASSERT(IntTSize == 4 || IntTSize == 1);
    AB(IntTSize == 1 ? 0xEB : 0xE9);
    w.a(reinterpret_cast<uint8_t *>(&disp), IntTSize);
}

#define INST(name, int_t, int_t_size) \
    template <class WriterT> void Asm::Assembler<WriterT>:: \
    name(int_t disp) \
    { jmp_nr_relXX_<WriterT, int_t, int_t_size>(w, disp); }
INST(jmp_nr_rel8, int8_t, SIZE_8)
INST(jmp_nr_rel32, int32_t, SIZE_32)
#undef INST

//
// MOV
//

template <class WriterT>
void Asm::Assembler<WriterT>::mov_reg_reg(Register reg_dest, Register reg_src)
{
    assert(register_byte_size(reg_dest) == register_byte_size(reg_src) &&
           is_gp3264_register(reg_dest) && is_gp3264_register(reg_src));
    RRC(reg_dest, rex, rcode_dest);
    uint8_t rcode_src = register_code(reg_src);

    ABIFNZ(rex);
    AB(0x89);
    AB(reg_reg_modrm(reg_src, reg_dest));
}

template <class WriterT, bool REVERSED>
static void mov_rm_reg_(WriterT &w, ModrmSib const &modrmsib)
{
    assert(modrmsib.gp3264_registers_only());
    ABIFNZ(rex_for_ModrmSib(modrmsib));
    AB(REVERSED ? 0x8A : 0x89);
    write_modrmsib(w, raw_modrmsib(modrmsib));
    write_disp(w, modrmsib);
}
template <class WriterT>
void Asm::Assembler<WriterT>::mov_rm_reg(ModrmSib const &modrmsib)
{ mov_rm_reg_<WriterT, false>(w, modrmsib); }
template <class WriterT>
void Asm::Assembler<WriterT>::mov_reg_rm(ModrmSib const &modrmsib)
{ mov_rm_reg_<WriterT, true>(w, modrmsib); }

template <class WriterT>
void Asm::Assembler<WriterT>::mov_moffs64_rax(uint64_t addr)
{
    AZ(REX_W_S "\xa3");
    A64(addr);
}

template <class WriterT>
void Asm::Assembler<WriterT>::mov_reg_imm64(Register reg, uint64_t imm)
{
    assert(has_additive_code_64(reg));
    RRC(reg, rex, rcode);
    ABIFNZ(rex);
    AB(0xB8 + rcode);
    A64(imm);
}

//
// RET
//

template <class WriterT>
void Asm::Assembler<WriterT>::ret()
{
    AB(0xc3);
}

#undef RRC
#undef AB
#undef AZ
#undef A
#undef AL
#undef A64
#undef REX_W_S

//
// >>>>>>>>>> END OF INSTRUCTIONS >>>>>>>>>>
//

template class Assembler<VectorWriter>;

Asm::VectorWriter::VectorWriter(std::size_t initial_size_)
    : initial_size(initial_size_),
      freebytes(initial_size_),
      length(initial_size_)
{
    mem = static_cast<uint8_t *>(mmap(0,
                                      initial_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                                      MAP_PRIVATE | MAP_ANONYMOUS,
                                      -1, 0));

}

Asm::VectorWriter::~VectorWriter() {
    munmap(mem, length);
}

void Asm::VectorWriter::a(const uint8_t *buf, std::size_t buflength)
{
    if (buflength <= freebytes) {
        memcpy(mem + length - freebytes, buf, buflength);
        freebytes -= buflength;
    }
    else {
        std::size_t newlength = length - freebytes + buflength + ROOM_AHEAD;
        mem = static_cast<uint8_t *>(mremap(mem,
                                          length,
                                          newlength,
                                          PROT_READ | PROT_WRITE | PROT_EXEC));
        if (! mem) {
            uint8_t *newmem =
                static_cast<uint8_t *>(mmap(0,
                                            newlength,
                                            PROT_READ | PROT_WRITE | PROT_EXEC,
                                            MAP_PRIVATE | MAP_ANONYMOUS,
                                            -1, 0));
            memcpy(newmem, mem, length - freebytes);
            memcpy(newmem + length - freebytes, buf, buflength);
            munmap(mem, length);
        }
        else {
            memcpy(mem + length - freebytes, buf, buflength);
        }
        length = newlength;
        freebytes = ROOM_AHEAD;
    }
}
void Asm::VectorWriter::a(uint8_t byte)
{
    uint8_t buf[1];
    if (freebytes > 0)
        mem[length - freebytes--] = byte;
    else {
        buf[0] = byte;
        a(&buf[0], 1);
    }
}
void Asm::VectorWriter::a(VectorWriter const &vw)
{
    a(vw.mem, vw.length - vw.freebytes);
}

std::size_t Asm::VectorWriter::size()
{
    return length - freebytes;
}

// Designed to be used in tests.
void Asm::VectorWriter::canonical_hex(std::string &o)
{
    o.reserve((length - freebytes) * 2 + // One pair of digits per byte.
              length - freebytes - 1);   // Spaces separating bytes.

    char tmps[3];
    for (std::size_t i = 0; i < length - freebytes; ++i) {
        std::sprintf(tmps, "%02x", static_cast<unsigned>(mem[i]));
        o.append(tmps);
        if (i + 1 < length - freebytes)
            o.push_back(' ');
    }
}

void Asm::VectorWriter::debug_print()
{
    for (std::size_t i = 0; i < length - freebytes; ++i) {
        if (i != 0 && i % 10 == 0)
            std::printf("\n");
        std::printf("%02x ", static_cast<unsigned>(mem[i]));
    }
    std::printf("\n\n");
}

uint8_t *Asm::VectorWriter::get_mem()
{
    return mem;
}

Asm::VectorWriter::voidf Asm::VectorWriter::get_exec_func()
{
    return reinterpret_cast<VectorWriter::voidf>(mem);
}
