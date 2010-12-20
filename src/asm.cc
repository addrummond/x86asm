#include <asm.hh>
#include <util.hh>
#include <mremap.hh>
#include <myassert.hh>
#include <iterator>
#include <cstdio>
#include <cstring>
#include <sys/mman.h>

using namespace Asm;

// Register codes.
// {REX, Reg Field}.
#define R REX_PREFIX
#define W (REX_PREFIX | REX_W)
#define B (REX_PREFIX | REX_B | REX_W)
namespace Asm {
static const uint8_t register_codes[][2] = {
    {0,0}, {0,1}, {0,2}, {0,3}, {0,4}, {0,5}, {0,6}, {0,7}, // EAX-EDI
    {W,0}, {W,1}, {W,2}, {W,3}, {W,4}, {W,5}, {W,6}, {W,7}, // RAX-RDI
    {B,0}, {B,1}, {B,2}, {B,3}, {B,4}, {B,5}, {B,6}, {B,7}, // R8D-R15D
    {0,0}, {0,1}, {0,2}, {0,3}, {0,4}, {0,5}, {0,6}, {0,7}, // MM0-MM7
    // TODO: Check if REX_W is needed for the following:
    {0,0}, {0,1}, {0,2}, {0,3}, {0,4}, {0,5}, {0,6}, {0,7}, // XMM0-XMM7
    {0,0}, {0,1}, {0,2}, {0,3}, {0,4}, {0,5}, {0,6}, {0,7}  // AL-BH
};
static char const *register_names[] = {
    "EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI",
    "RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI",
    "R8D", "R9D", "R10D", "R11D", "R12D", "R13D", "R14D", "R15D",
    "MM0", "MM1", "MM2", "MM4", "MM5", "MM6", "MM7",
    "XMM0", "XMM1", "XMM2", "XMM3", "XMM4", "XMM5", "XMM6", "XMM7",
    "AL", "CL", "DL", "BL", "AH", "CH", "DH", "BH"
    "FS", "GS",
    "NOT_A_REGISTER"
};
}
char const *Asm::register_name(Register reg) { return register_names[reg]; }
uint8_t Asm::register_rex(Register reg) { assert(reg < FS); return register_codes[reg][0]; }
uint8_t Asm::register_code(Register reg) { assert(reg < FS); return register_codes[reg][1]; }
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

namespace Asm {
static unsigned register_byte_sizes[] = {
    4, 4, 4, 4, 4, 4, 4, 4, // EAX-EDI
    8, 8, 8, 8, 8, 8, 8, 8, // RAX-RDI
    8, 8, 8, 8, 8, 8, 8, 8, // R8D-R15D
    8, 8, 8, 8, 8, 8, 8, 8, // MM0-MM7
    8, 8, 8, 8, 8, 8, 8, 8, // XMM0-XMM7
    1, 1, 1, 1, 1, 1, 1, 1  // AL-BH
};
}
unsigned Asm::register_byte_size(Register reg) { assert(reg <= BH); return register_byte_sizes[reg]; }

static uint8_t raw_modrm(uint8_t mod, uint8_t rm, uint8_t reg)
{
    assert(mod < 5 && rm < 9 && reg < 9);
    return (mod << 6) | (reg << 3) | rm;
}

// Note that this excludes the 16-bit registers and 8-bit registers.
static bool is_gp3264_register(Register reg)
{
    return (reg >= EAX && reg <= EDI) || (reg >= RAX && reg <= RDI) || (reg >= R8D && reg <= R15D);
}
static bool is_gp8_register(Register reg)
{
    return (reg >= AL && reg <= BH);
}

static bool requires_sib(ModrmSib const &modrmsib)
{
    return !(modrmsib.disp_size == DISP_SIZE_NONE || modrmsib.scale == SCALE_1);
}

struct RawModrmSib {
    uint8_t modrm;
    uint8_t sib; // Set to 0 if none, since 0 is not a valid SIB.
    bool has_disp;
};
static RawModrmSib raw_modrmsib(ModrmSib const &modrmsib)
{
    RawModrmSib r;
    r.has_disp = true;
    uint8_t mod, rm, reg;

    // The special case of RIP.
    if (modrmsib.rip) {
        assert((modrmsib.disp_size == DISP_SIZE_32 || modrmsib.disp_size == DISP_SIZE_NONE) &&
               modrmsib.rm_reg != ESP && modrmsib.rm_reg != EBP &&
               modrmsib.scale == SCALE_1 &&
               modrmsib.base_reg == NOT_A_REGISTER);
        r.modrm = raw_modrm(0,
                            modrmsib.rm_reg != NOT_A_REGISTER ? register_code(modrmsib.rm_reg) : 5,
                            modrmsib.reg != NOT_A_REGISTER ? register_code(modrmsib.reg) : 0);
        r.sib = 0;
        r.has_disp = modrmsib.disp_size != DISP_SIZE_NONE;
//        std::printf("\n\n%x\n\n", (int)(r.modrm));
        return r;
    }

    // Set mod.
    if (modrmsib.disp_size == DISP_SIZE_NONE) {
         mod = 3;
         r.has_disp = false;
    }
    else if ((modrmsib.disp == 0 && modrmsib.rm_reg != RBP && modrmsib.rm_reg != RSP) || modrmsib.rm_reg == NOT_A_REGISTER) {
        mod = 0;
        r.has_disp = false;
    }
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
        assert(is_gp3264_register(modrmsib.rm_reg) && (modrmsib.rm_reg != RSP || mod == 3));
        rm = register_code(modrmsib.rm_reg);
    }
    // Set reg.
    reg = (modrmsib.reg != NOT_A_REGISTER ? register_code(modrmsib.reg) : 0);

    r.modrm = raw_modrm(mod, rm, reg);

    // Add SIB if required.
    if (! requires_sib(modrmsib)) {//(mod == 3 || rm != 4) {
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
        if (modrmsib.base_reg == NOT_A_REGISTER)
            sib_rm = 4;
        else {
            assert(is_gp3264_register(modrmsib.rm_reg) && modrmsib.rm_reg != RSP);
            sib_rm = register_code(modrmsib.rm_reg);
        }
        // Set reg (base).
        Register base_reg = (modrmsib.base_reg == NOT_A_REGISTER ? modrmsib.rm_reg : modrmsib.base_reg);
        assert(is_gp3264_register(base_reg) && register_byte_size(base_reg) == 8);
        sib_reg = register_code(base_reg);

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

bool Asm::ModrmSib::has_reg_operand() const
{
    return reg != NOT_A_REGISTER;
}

bool Asm::ModrmSib::simple_memory() const
{
    return disp_size != DISP_SIZE_NONE && reg == NOT_A_REGISTER;
}

bool Asm::ModrmSib::gp3264_registers_only() const
{
    return (rm_reg == NOT_A_REGISTER || (rm_reg >= EAX && rm_reg <= R15D)) &&
           (reg == NOT_A_REGISTER || (reg >= EAX && reg <= R15D));
}

bool Asm::ModrmSib::gp8_registers_only() const
{
    return (rm_reg == NOT_A_REGISTER || (rm_reg >= AL && rm_reg <= BH)) &&
           (reg == NOT_A_REGISTER || (reg >= AL && reg <= BH));
}

bool Asm::ModrmSib::gp_registers_only() const
{
    return (rm_reg == NOT_A_REGISTER || (rm_reg >= EAX && rm_reg <= R15D) || (rm_reg >= AL && rm_reg <= BH)) &&
           (reg == NOT_A_REGISTER || (reg >= EAX && reg <= R15D) || (reg >= AL && reg <= BH));
}

bool Asm::ModrmSib::all_register_operands_have_size(Size size) const
{
    return (reg == NOT_A_REGISTER || register_byte_size(reg) == size) &&
           (disp_size != DISP_SIZE_NONE || register_byte_size(rm_reg) == size);
}

// Creates a ModrmSib where rm is memory.
namespace Asm {
ModrmSib mem_2op(Register reg, Register base, Register index, Scale scale, int32_t displacement, bool short_displacement)
{
    return ModrmSib(/*rip*/       false,
                    /*rm_reg*/    index == NOT_A_REGISTER ? base : index,
                    /*disp_size*/ short_displacement ? DISP_SIZE_8 : DISP_SIZE_32,
                    /*disp*/      displacement,
                    /*reg*/       reg,
                    /*base_reg*/  index == NOT_A_REGISTER ? NOT_A_REGISTER : base,
                    /*scale*/     scale);
}
ModrmSib mem_2op_short(Register reg, Register base, Register index, Scale scale, int32_t displacement)
{
    return mem_2op(reg, base, index, scale, displacement, true);
}
ModrmSib mem_1op(Register base, Register index, Scale scale, int32_t displacement, bool short_displacement)
{
    return mem_2op(NOT_A_REGISTER, base, index, scale, displacement, short_displacement);
}
ModrmSib mem_1op_short(Register base, Register index, Scale scale, int32_t displacement)
{
    return mem_2op(NOT_A_REGISTER, base, index, scale, displacement, true);
}
ModrmSib reg_2op(Register reg, Register rm)
{
    return ModrmSib(false, rm, DISP_SIZE_NONE, /*displacement*/ 0, reg);
}
ModrmSib reg_1op(Register rm)
{
    return ModrmSib(false, rm);
}
ModrmSib rip_1op(Register reg1, int32_t disp)
{
    return ModrmSib(true, reg1, disp == 0 ? DISP_SIZE_NONE : DISP_SIZE_32, disp);
}
ModrmSib rip_2op(Register reg2, Register reg1, int32_t disp)
{
    return ModrmSib(true, reg1, disp == 0 ? DISP_SIZE_NONE : DISP_SIZE_32, disp, reg2);
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

static uint8_t compute_rex(ModrmSib const &modrmsib, Size size) // Returns 0 if no REX.
{
    uint8_t rex = 0;
    if (size == SIZE_64)
        rex |= REX_W;

    if (! requires_sib(modrmsib)) {//modrmsib.disp_size == DISP_SIZE_NONE || modrmsib.scale == SCALE_1) {
        // No SIB.
        if (modrmsib.rm_reg >= R8D && modrmsib.rm_reg <= R15D)
            rex |= REX_B;
        if (modrmsib.reg >= R8D && modrmsib.reg <= R15D)
            rex |= REX_R;
    }
    else {
        // Yes SIB.
        if (modrmsib.rm_reg >= R8D && modrmsib.rm_reg <= R15D)
            rex |= REX_X;
        if (modrmsib.reg >= R8D && modrmsib.reg <= R15D)
            rex |= REX_R;
    }

    if (rex != 0)
        rex |= REX_PREFIX;
    return rex;
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
//    if (modrmsib.disp != 0) {
//    if (modrmsib.disp_size != DISP_SIZE_NONE) {
        if (modrmsib.disp_size == DISP_SIZE_8)
            AB(static_cast<uint8_t>(modrmsib.disp));
        else if (modrmsib.disp_size == DISP_SIZE_32)
            A32(modrmsib.disp);
        else assert(0);
//    }
}

template <class WriterT>
static void write_modrmsib_disp(WriterT &w, ModrmSib const &modrmsib)
{
    RawModrmSib raw = raw_modrmsib(modrmsib);
    write_modrmsib(w, raw);
    if (raw.has_disp)
        write_disp(w, modrmsib);
}

template <class IntT>
Disp<IntT> Asm::mkdisp(IntT i, DispOp op) { return Disp<IntT>(i, op); }
template Disp<int8_t> Asm::mkdisp<int8_t>(int8_t i, DispOp op);
template Disp<int32_t> Asm::mkdisp<int32_t>(int32_t i, DispOp op);

//
// <<<<<<<<<< START OF INSTRUCTIONS <<<<<<<<<<
//

//
// ADC, ADD, AND, OR, SUB, XOR
//

template <class WriterT, uint8_t OPCODE, Size RM_SIZE>
static void X_rm_reg_(WriterT &w, ModrmSib const &modrmsib)
{
    assert(modrmsib.gp3264_registers_only() &&
           modrmsib.all_register_operands_have_size(RM_SIZE));

    ABIFNZ(compute_rex(modrmsib, RM_SIZE));
    AB(OPCODE);
    write_modrmsib_disp(w, modrmsib);
}

#define INST(name, opcode, rm_size) \
    template <class WriterT> void Asm::Assembler<WriterT>:: \
    name (ModrmSib const &modrmsib) \
    { X_rm_reg_<WriterT, opcode, rm_size>(w, modrmsib); }
INST(adc_rm32_reg, 0x11, SIZE_32)
INST(adc_rm64_reg, 0x11, SIZE_64)
INST(adc_reg_rm32, 0x13, SIZE_32)
INST(adc_reg_rm64, 0x13, SIZE_64)

INST(add_rm32_reg, 0x01, SIZE_32)
INST(add_rm64_reg, 0x01, SIZE_64)
INST(add_reg_rm32, 0x03, SIZE_32)
INST(add_reg_rm64, 0x03, SIZE_64)

INST(and_rm32_reg, 0x21, SIZE_32)
INST(and_rm64_reg, 0x21, SIZE_64)
INST(and_reg_rm32, 0x23, SIZE_32)
INST(and_reg_rm64, 0x23, SIZE_64)

INST(or_rm32_reg, 0x09, SIZE_32)
INST(or_rm64_reg, 0x09, SIZE_64)
INST(or_reg_rm32, 0x0B, SIZE_32)
INST(or_reg_rm64, 0x0B, SIZE_64)

INST(sub_rm32_reg, 0x29, SIZE_32)
INST(sub_rm64_reg, 0x29, SIZE_64)
INST(sub_reg_rm32, 0x2B, SIZE_32)
INST(sub_reg_rm64, 0x2B, SIZE_64)

INST(xor_rm32_reg, 0x31, SIZE_32)
INST(xor_rm64_reg, 0x31, SIZE_64)
INST(xor_reg_rm32, 0x33, SIZE_32)
INST(xor_reg_rm64, 0x33, SIZE_64)
#undef INST

template <class WriterT, Size RM_SIZE, class ImmT, Size IMM_SIZE, uint8_t SIMPLE_OPCODE, uint8_t COMPLEX_OPCODE, Register EXTENSION>
static void add_rmXX_imm32_(WriterT &w, ModrmSib modrmsib, ImmT src)
{
    assert((! modrmsib.has_reg_operand()) &&
           modrmsib.gp3264_registers_only() &&
           modrmsib.all_register_operands_have_size(RM_SIZE));

    if (SIMPLE_OPCODE && modrmsib.simple_register() == EAX) {
        assert(RM_SIZE == SIZE_32);
        AB(SIMPLE_OPCODE);
    }
    else if (SIMPLE_OPCODE && modrmsib.simple_register() == RAX) {
        assert(RM_SIZE == SIZE_64);
        AB(REX_PREFIX | REX_W);
        AB(SIMPLE_OPCODE);
    }
    else {
        ABIFNZ(compute_rex(modrmsib, RM_SIZE));
        AB(COMPLEX_OPCODE);
        modrmsib.reg = EXTENSION;
        write_modrmsib_disp(w, modrmsib);
    }

    w.a(reinterpret_cast<uint8_t *>(&src), IMM_SIZE);
}

#define INST(name, size, immt, imm_size, simple_opcode, complex_opcode, extension) \
    template <class WriterT> void Asm::Assembler<WriterT>:: \
    name (ModrmSib const &modrmsib, immt src) \
    { add_rmXX_imm32_<WriterT, size, immt, imm_size, simple_opcode, complex_opcode, extension>(w, modrmsib, src); }
INST(adc_rm32_imm8, SIZE_32, uint8_t, SIZE_8, 0, 0x80, EDX/*2*/)
INST(adc_rm64_imm8, SIZE_64, uint8_t, SIZE_8, 0, 0x80, EDX/*2*/)
INST(adc_rm32_imm32, SIZE_32, uint32_t, SIZE_32, 0x15, 0x81, EDX/*2*/)
INST(adc_rm64_imm32, SIZE_64, uint32_t, SIZE_32, 0x15, 0x81, EDX/*2*/)

INST(add_rm32_imm8, SIZE_32, uint8_t, SIZE_8, 0, 0x80, EAX/*0*/)
INST(add_rm64_imm8, SIZE_64, uint8_t, SIZE_8, 0, 0x80, EAX/*0*/)
INST(add_rm32_imm32, SIZE_32, uint32_t, SIZE_32, 0x05, 0x81, EAX/*0*/)
INST(add_rm64_imm32, SIZE_64, uint32_t, SIZE_32, 0x05, 0x81, EAX/*0*/)

INST(and_rm32_imm8, SIZE_32, uint8_t, SIZE_8, 0, 0x80, ESP/*4*/)
INST(and_rm64_imm8, SIZE_64, uint8_t, SIZE_8, 0, 0x80, ESP/*4*/)
INST(and_rm32_imm32, SIZE_32, uint32_t, SIZE_32, 0x25, 0x81, ESP/*4*/)
INST(and_rm64_imm32, SIZE_64, uint32_t, SIZE_32, 0x25, 0x81, ESP/*4*/)

INST(or_rm32_imm8, SIZE_32, uint8_t, SIZE_8, 0, 0x80, ECX/*1*/)
INST(or_rm64_imm8, SIZE_64, uint8_t, SIZE_8, 0, 0x80, ECX/*1*/)
INST(or_rm32_imm32, SIZE_32, uint32_t, SIZE_32, 0x0D, 0x81, ECX/*1*/)
INST(or_rm64_imm32, SIZE_64, uint32_t, SIZE_32, 0x0D, 0x81, ECX/*1*/)

INST(sub_rm32_imm8, SIZE_32, uint8_t, SIZE_8, 0, 0x80, EBX/*5*/)
INST(sub_rm64_imm8, SIZE_64, uint8_t, SIZE_8, 0, 0x80, EBX/*5*/)
INST(sub_rm32_imm32, SIZE_32, uint32_t, SIZE_32, 0x2D, 0x81, EBP/*5*/)
INST(sub_rm64_imm32, SIZE_64, uint32_t, SIZE_32, 0x2D, 0x81, EBP/*5*/)

INST(xor_rm32_imm8, SIZE_32, uint8_t, SIZE_8, 0, 0x80, ESI/*6*/)
INST(xor_rm64_imm8, SIZE_64, uint8_t, SIZE_8, 0, 0x80, ESI/*6*/)
INST(xor_rm32_imm32, SIZE_32, uint32_t, SIZE_32, 0x35, 0x81, ESI/*6*/)
INST(xor_rm64_imm32, SIZE_64, uint32_t, SIZE_32, 0x35, 0x81, ESI/*6*/)
#undef INST

//
// CALL
//

template <class WriterT>
void Asm::Assembler<WriterT>::call_rel32(int32_t disp)
{
    AB(0xE8);
    A32(disp + 5); // HACK HACK HACK.
}

template <class WriterT>
void Asm::Assembler<WriterT>::call_rm64(ModrmSib modrmsib)
{
    assert(! modrmsib.has_reg_operand());
    AB(0xFF);
    modrmsib.reg = EDX/*2*/;
    write_modrmsib_disp(w, modrmsib);
}

//
// CMP
//

template <class WriterT, unsigned BYTE_SIZE, Size RM_SIZE, uint8_t OPCODE, Register EXTENSION, class ImmT, Size ImmTSize>
static void cmp_rmXX_imm_(WriterT &w, Assembler<WriterT> &a, ModrmSib modrmsib, ImmT imm)
{
    assert(modrmsib.gp3264_registers_only() &&
           (! modrmsib.has_reg_operand()) &&
           (modrmsib.simple_register() == NOT_A_REGISTER ||
            register_byte_size(modrmsib.simple_register()) == BYTE_SIZE));

    if (BYTE_SIZE == 8 && ImmTSize == 4 && modrmsib.simple_register() == RAX) {
        a.cmp_rax_imm32(imm);
    }
    else {
        ABIFNZ(compute_rex(modrmsib, RM_SIZE));
        AB(OPCODE);
        modrmsib.reg = EXTENSION;
        write_modrmsib_disp(w, modrmsib);
        w.a(reinterpret_cast<uint8_t*>(&imm), ImmTSize);
    }
}

// Note that sizeof(int32_t) == 8 (on some platforms anyway),
// so we have to have a separate template argument for the "real" size of the immediate argument.
#define INST(name, size, rexbyte, opcode, extension, immtype, immtypesize)  \
    template <class WriterT> void Asm::Assembler<WriterT>:: \
    name (ModrmSib const &modrmsib, immtype imm) \
    { cmp_rmXX_imm_<WriterT, size, rexbyte, opcode, extension, immtype, immtypesize>(w, *this, modrmsib, imm);  }
INST(cmp_rm32_imm8, 4, SIZE_32, 0x83, EDI/*7*/, uint8_t, SIZE_8)
INST(cmp_rm64_imm8, 8, SIZE_64, 0x83, EDI/*7*/, uint8_t, SIZE_8)
INST(cmp_rm32_imm32, 4, SIZE_32, 0x81, EDI/*7*/, uint32_t, SIZE_32)
INST(cmp_rm64_imm32, 8, SIZE_64, 0x81, EDI/*7*/, uint32_t, SIZE_32)
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

template <class WriterT, Size SIZE>
static void cmp_rmXX_reg_(WriterT &w, ModrmSib const &modrmsib)
{
    ABIFNZ(compute_rex(modrmsib, SIZE));
    AB(0x39);
}
#define INST(name, size) \
    template <class WriterT> void Asm::Assembler<WriterT>:: \
    name (ModrmSib const &modrmsib) \
    { cmp_rmXX_reg_<WriterT, size>(w, modrmsib); }
INST(cmp_rm32_reg, SIZE_32)
INST(cmp_rm64_reg, SIZE_64)
#undef INST

//
// FABS
//
template <class WriterT>
void Asm::Assembler<WriterT>::fabs_st0() { AZ("\xD9\xE1"); }

//
// FADD, FADDP, FDIV, FDIVP, FIADD, FIDIV, FIMUL, FISUB, FMUL, FMULP, FSUB, FSUBP
//
template <class WriterT, uint8_t OPCODE, Register EXTENSION>
static void fadd_st0_mXXfp_(WriterT &w, ModrmSib modrmsib)
{
    assert(modrmsib.simple_memory());
    AB(OPCODE);
    modrmsib.reg = EXTENSION;
    write_modrmsib_disp(w, modrmsib);
}

#define INST(name, opcode, extension) \
    template <class WriterT> void Asm::Assembler<WriterT>:: \
    name (ModrmSib const &modrmsib) \
    { fadd_st0_mXXfp_<WriterT, opcode, extension>(w, modrmsib); }
INST(fadd_st0_m32fp, 0xD8, EAX/*0*/)
INST(fadd_st0_m64fp, 0xDC, EAX/*0*/)
INST(fsub_st0_m32fp, 0xD8, ESP/*4*/)
INST(fsub_st0_m64fp, 0xDC, ESP/*4*/)
INST(fmul_st0_m32fp, 0xD8, ECX/*1*/)
INST(fmul_st0_m64fp, 0xDC, ECX/*1*/)
INST(fdiv_st0_m32fp, 0xD8, ESI/*6*/)
INST(fdiv_st0_m64fp, 0xDC, ESI/*6*/)

INST(fiadd_st0_m32int, 0xDA, RAX/*0*/)
INST(fiadd_st0_m16int, 0xDE, RAX/*0*/)
INST(fisub_st0_m32int, 0xDA, ESP/*4*/)
INST(fisub_st0_m16int, 0xDE, ESP/*4*/)
INST(fimul_st0_m32int, 0xDA, ECX/*1*/)
INST(fimul_st0_m16int, 0xDE, ECX/*1*/)
#undef INST

template <class WriterT, uint8_t OPCODE1, uint8_t OPCODE2>
static void fadd_st_st_(WriterT &w, unsigned streg)
{
    assert(streg < 8);
    AB(OPCODE1);
    AB(OPCODE2 + streg);
}

#define INST(name, opcode1, opcode2) \
    template <class WriterT> void Asm::Assembler<WriterT>:: \
    name (unsigned streg) \
    { fadd_st_st_<WriterT, opcode1, opcode2>(w, streg); }
INST(fadd_st_st0, 0xDC, 0xC0)
INST(fadd_st0_st, 0xD8, 0xC0)
INST(fsub_st_st0, 0xDC, 0xE8)
INST(fsub_st0_st, 0xD8, 0xE0)
INST(fmul_st_st0, 0xDC, 0xC8)
INST(fmul_st0_st, 0xD8, 0xC8)
INST(fdiv_st_st0, 0xDC, 0xF8)
INST(fdiv_st0_st, 0xD8, 0xF0)
#undef INST

#define INST(name, opcode) \
    template <class WriterT> void Asm::Assembler<WriterT>::name() { AZ(opcode); }
INST(faddp, "\xDE\xC1")
INST(fsubp, "\xDE\xE9")
INST(fmulp, "\xDE\xC9")
INST(fdivp, "\xDE\xF9")
#undef INST

//
// FCOM, FCOMP, FUCOM, FUCOMP
//
template <class WriterT, uint8_t OPCODE1, uint8_t OPCODE2>
static void Xcom_st_sti(WriterT &w, unsigned streg)
{
    assert(streg < 8);
    AB(OPCODE1);
    AB(OPCODE2 + streg);
}

#define INST(name, opcode1, opcode2) \
    template <class WriterT> void Asm::Assembler<WriterT>:: \
    name (unsigned streg) { Xcom_st_sti<WriterT, opcode1, opcode2>(w, streg); }
INST(fcom_st0_st, 0xDB, 0xF0)
INST(fcomp_st0_st, 0xDF, 0xF0)
INST(fucom_st0_st, 0xDB, 0xE8)
INST(fucomp_st0_st, 0xDF, 0xE8)
#undef INST

//
// FDECSTP, FINCSTP
//
#define INST(name, opcode) \
    template <class WriterT> void Asm::Assembler<WriterT>:: name () { AZ(opcode); }
INST(fdecstp, "\xD9\xF6")
INST(fincstp, "\xD9\xF7")
#undef INST

//
// FLD
//
template <class WriterT, uint8_t OPCODE, Register EXTENSION>
static void fld_mX_(WriterT &w, ModrmSib modrmsib)
{
    assert(modrmsib.simple_memory());
    AB(OPCODE);
    modrmsib.reg = EXTENSION;
    write_modrmsib_disp(w, modrmsib);
}

#define INST(name, opcode, extension) \
    template <class WriterT> void Asm::Assembler<WriterT>:: \
    name (ModrmSib const &modrmsib) \
    { fld_mX_<WriterT, opcode, extension>(w, modrmsib); }
INST(fld_m32fp, 0xD9, EAX/*0*/)
INST(fld_m64fp, 0xDD, EAX/*0*/)
INST(fld_m80fp, 0xDB, EBP/*5*/)
INST(fild_m16int, 0xDF, EAX/*0*/)
INST(fild_m32int, 0xDB, EAX/*0*/)
INST(fild_m64int, 0xDF, EBP/*5*/)
#undef INST

template <class WriterT> void Asm::Assembler<WriterT>::fld_st(unsigned streg)
{
    assert(streg < 8);
    AB(0xD9);
    AB(0xC0 + streg);
}

//
// FNOP
//
template <class WriterT> void Asm::Assembler<WriterT>::fnop() { AZ("\xD9\xD0"); }

//
// FST
//
template <class WriterT, uint8_t OPCODE, Register EXTENSION>
static void fst_mXX_st0_(WriterT &w, ModrmSib modrmsib)
{
    assert(modrmsib.simple_memory());
    AB(OPCODE);
    modrmsib.reg = EXTENSION;
    write_modrmsib_disp(w, modrmsib);
}

#define INST(name, opcode, extension) \
    template <class WriterT> void Asm::Assembler<WriterT>::     \
    name (ModrmSib const &modrmsib) \
    { fst_mXX_st0_<WriterT, opcode, extension>(w, modrmsib); }
INST(fst_m32fp_st0, 0xD9, EDX/*2*/)
INST(fst_m64fp_st0, 0xDD, EDX/*2*/)
INST(fstp_m32fp_st0, 0xD9, EBX/*3*/)
INST(fstp_m64fp_st0, 0xDD, EBX/*3*/)
INST(fstp_m80fp_st0, 0xDB, EDI/*7*/)
#undef INST

template <class WriterT>
void Asm::Assembler<WriterT>::fst_st_st0(unsigned streg_dest)
{
    assert(streg_dest < 8);
    AB(0xDD);
    AB(0xD0 + streg_dest);
}
template <class WriterT>
void Asm::Assembler<WriterT>::fstp_st_st0(unsigned streg_dest)
{
    assert(streg_dest < 8);
    AB(0xDD);
    AB(0xD8 + streg_dest);
}

//
// IDIV, IMUL, MUL
//
template <class WriterT, Size RM_SIZE>
static void Xmul_reg_rm_(WriterT &w, ModrmSib const &modrmsib)
{
    assert(modrmsib.gp3264_registers_only() &&
           modrmsib.all_register_operands_have_size(RM_SIZE));
    ABIFNZ(compute_rex(modrmsib, RM_SIZE));
    AZ("\x0F\xAF");
    write_modrmsib_disp(w, modrmsib);
}

#define INST(name, rm_size) \
    template <class WriterT> void Asm::Assembler<WriterT>:: \
    name (ModrmSib const &modrmsib) \
    { Xmul_reg_rm_<WriterT, rm_size>(w, modrmsib); }
INST(imul_reg_rm32, SIZE_32)
INST(imul_reg_rm64, SIZE_64)
#undef INST

template <class WriterT, uint8_t OPCODE, Size RM_SIZE, Register EXTENSION>
static void mul_dxax_rm_(WriterT &w, ModrmSib modrmsib)
{
    assert((! modrmsib.has_reg_operand()) &&
           modrmsib.gp3264_registers_only() &&
           modrmsib.all_register_operands_have_size(RM_SIZE));

    ABIFNZ(compute_rex(modrmsib, RM_SIZE));
    AB(OPCODE);
    modrmsib.reg = EXTENSION;
    write_modrmsib_disp(w, modrmsib);
}

#define INST(name, opcode, rm_size, extension)                  \
    template <class WriterT> void Asm::Assembler<WriterT>:: \
    name (ModrmSib const &modrmsib) \
    { mul_dxax_rm_<WriterT, opcode, rm_size, extension>(w, modrmsib); }
INST(idiv_rdx_rax_rm64, 0xF7, SIZE_64, EDI/*7*/)
INST(idiv_edx_eax_rm32, 0xF7, SIZE_32, EDI/*7*/)
INST(imul_rdx_rax_rm64, 0xF7, SIZE_64, EBP/*5*/)
INST(imul_edx_eax_rm32, 0xF7, SIZE_32, EBP/*5*/)
INST(mul_rdx_rax_rm64, 0xF7, SIZE_64, ESP/*4*/)
INST(mul_edx_eax_rm32, 0xF7, SIZE_32, ESP/*4*/)
#undef INST

//
// INC, DEC.
//

template <class WriterT, Register EXTENSION, uint8_t OPCODE, Size RM_SIZE>
static void incdec_(WriterT &w, ModrmSib modrmsib)
{
    assert((! modrmsib.has_reg_operand()) &&
           modrmsib.gp3264_registers_only() &&
           modrmsib.all_register_operands_have_size(RM_SIZE));

    ABIFNZ(compute_rex(modrmsib, RM_SIZE));
    modrmsib.reg = EXTENSION;
    AB(OPCODE);
    write_modrmsib_disp(w, modrmsib);
}

#define INST(name, extension, opcode, rm_size)                      \
    template <class WriterT> void Asm::Assembler<WriterT>:: \
    name(ModrmSib const &modrmsib) \
    { incdec_<WriterT, extension, opcode, rm_size>(w, modrmsib); }
INST(inc_rm32, EAX/*0*/, 0xFF, SIZE_32)
INST(inc_rm64, EAX/*0*/, 0xFF, SIZE_64)
INST(dec_rm32, ECX/*1*/, 0xFF, SIZE_32)
INST(dec_rm64, ECX/*1*/, 0xFF, SIZE_64)
#undef INST

template <class WriterT>
void Asm::Assembler<WriterT>::dec_reg32(Register reg) { dec_rm32(reg_1op(reg)); }
template <class WriterT>
void Asm::Assembler<WriterT>::dec_reg64(Register reg) { dec_rm64(reg_1op(reg)); }
template <class WriterT>
void Asm::Assembler<WriterT>::inc_reg32(Register reg) { inc_rm32(reg_1op(reg)); }
template <class WriterT>
void Asm::Assembler<WriterT>::inc_reg64(Register reg) { inc_rm64(reg_1op(reg)); }

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
static void jmp_nr_relXX_(WriterT &w, Disp<IntT> disp)
{
    COMPILE_ASSERT(IntTSize == 4 || IntTSize == 1);
    AB(IntTSize == SIZE_8 ? 0xEB : 0xE9);
    IntT d = disp.get(1 + IntTSize);
    w.a(reinterpret_cast<uint8_t *>(&d), IntTSize);
}

#define INST(name, int_t, int_t_size) \
    template <class WriterT> void Asm::Assembler<WriterT>:: \
    name(Disp<int_t> disp)                                  \
    { jmp_nr_relXX_<WriterT, int_t, int_t_size>(w, disp); }
INST(jmp_nr_rel8, int8_t, SIZE_8)
INST(jmp_nr_rel32, int32_t, SIZE_32)
#undef INST

template <class WriterT>
void Asm::Assembler<WriterT>::jmp_nr_rm64(ModrmSib const &modrmsib_)
{
    assert(! modrmsib_.has_reg_operand());
    ModrmSib modrmsib = modrmsib_;
    modrmsib.reg = ESP/*4*/;
    AB(0xFF);
    write_modrmsib_disp(w, modrmsib);
}

//
// LEA
//
template <class WriterT>
void Asm::Assembler<WriterT>::lea_reg_m(ModrmSib const &modrmsib)
{
    assert(modrmsib.has_reg_operand());
    ABIFNZ(compute_rex(modrmsib, (Size)register_byte_size(modrmsib.reg)));
    AB(0x8D);
    write_modrmsib_disp(w, modrmsib);
}


//
// LEAVE
//

template <class WriterT>
void Asm::Assembler<WriterT>::leave() {
    AB(0xC9);
}

//
// MOV
//

template <class WriterT, uint8_t OPCODE, Size RM_SIZE>
static void mov_rm_reg_(WriterT &w, ModrmSib const &modrmsib)
{
    assert(modrmsib.gp_registers_only() /*&&
                                          modrmsib.all_register_operands_have_size(RM_SIZE)*/);

    ABIFNZ(compute_rex(modrmsib, RM_SIZE));
    AB(OPCODE);
    write_modrmsib_disp(w, modrmsib);
}

#define INST(name, reversed, rm_size) \
    template <class WriterT> \
    void Asm::Assembler<WriterT>:: name (ModrmSib const &modrmsib) \
    { mov_rm_reg_<WriterT, reversed, rm_size>(w, modrmsib); }
INST(mov_rm8_reg, 0x88, SIZE_8)
INST(mov_reg_rm8, 0x8A, SIZE_8)
INST(mov_rm32_reg, 0x89, SIZE_32)
INST(mov_rm64_reg, 0x89, SIZE_64)
INST(mov_reg_rm32, 0x8B, SIZE_32)
INST(mov_reg_rm64, 0x8B, SIZE_64)
#undef INST

template <class WriterT>
void Asm::Assembler<WriterT>::mov_moffs64_rax(uint64_t addr)
{
    AZ(REX_W_S "\xa3");
    A64(addr);
}

template <class WriterT, class ImmT, Size SIZE>
static void mov_reg_immX_(Assembler<WriterT> &a, WriterT &w, Register reg, ImmT imm)
{
    assert(((SIZE == SIZE_32 && has_additive_code_32(reg)) ||
            (SIZE == SIZE_64 && has_additive_code_64(reg))));
    RRC(reg, rex, rcode);
    ABIFNZ(rex);
    AB(0xB8 + rcode);
    w.a(reinterpret_cast<uint8_t *>(&imm), SIZE);
}

#define INST(name, immt, size) \
    template <class WriterT> void Asm::Assembler<WriterT>:: \
    name (Register reg, immt imm)                              \
    { mov_reg_immX_<WriterT, immt, size>(*this, w, reg, imm); }
INST(mov_reg_imm32, uint32_t, SIZE_32)
INST(mov_reg_imm64, uint64_t, SIZE_64)
#undef INST

//
// NOP
//

template <class WriterT>
void Asm::Assembler<WriterT>::nop()
{
    AB(0x90);
}

//
// POP, PUSH
//

template <class WriterT>
void Asm::Assembler<WriterT>::pop_reg64(Register reg)
{
    assert(has_additive_code_64(reg));
    AB(0x58 + register_code(reg));
}

template <class WriterT>
void Asm::Assembler<WriterT>::push_reg64(Register reg)
{
    assert(has_additive_code_64(reg));
    AB(0x50 + register_code(reg));
}

template <class WriterT, Size RM_SIZE, uint8_t OPCODE>
static void push_rmX_(Assembler<WriterT> &a, WriterT &w, ModrmSib modrmsib)
{
    assert(! modrmsib.has_reg_operand());

    if (has_additive_code_64(modrmsib.simple_register())) {
        if (OPCODE == 0xFF)
            a.push_reg64(modrmsib.simple_register());
        else if (OPCODE == 0x8F)
            a.pop_reg64(modrmsib.simple_register());
    }
    else {
        AB(OPCODE);
        modrmsib.reg = ESI/*6*/;
        write_modrmsib_disp(w, modrmsib);
    }
}

#define INST(name, rm_size, opcode) \
    template <class WriterT> \
    void Asm::Assembler<WriterT>:: name (ModrmSib const &modrmsib) \
    { push_rmX_<WriterT, rm_size, opcode>(*this, w, modrmsib); }
INST(push_rm64, SIZE_64, 0xFF)
INST(pop_rm64, SIZE_64, 0x8F)
#undef INST

template <class WriterT, class ImmT, Size ImmTSize, uint8_t OPCODE>
static void push_imm_(WriterT &w, ImmT imm)
{
    AB(OPCODE);
    w.a(reinterpret_cast<uint8_t *>(&imm), ImmTSize);
}
#define INST(name, immt, immtsize, opcode) \
    template <class WriterT> \
    void Asm::Assembler<WriterT>:: name (immt imm) \
    { push_imm_<WriterT, immt, immtsize, opcode>(w, imm); }
INST(push_imm8, uint8_t, SIZE_8, 0x6A)
INST(push_imm32, uint32_t, SIZE_32, 0x68)
#undef INST

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
template class Asm::Assembler<Asm::CountingVectorWriter>;

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

Asm::VectorWriter::VectorWriter(Asm::VectorWriter &vw)
    : initial_size(vw.length),
      freebytes(vw.length),
      length(vw.length)
{
    vw.mem = NULL;
}

Asm::VectorWriter::~VectorWriter() {
    munmap(mem, length);
}

void Asm::VectorWriter::clear()
{
    freebytes = length;
}

void Asm::VectorWriter::a(const uint8_t *buf, std::size_t buflength)
{
    if (buflength <= freebytes) {
        memcpy(mem + length - freebytes, buf, buflength);
        freebytes -= buflength;
    }
    else {
        std::size_t newlength = length - freebytes + buflength + ROOM_AHEAD;
        uint8_t *r = static_cast<uint8_t *>(mremap(mem,
                                                   length,
                                                   newlength,
                                                   PROT_READ | PROT_WRITE | PROT_EXEC));
        if (! r) {
            uint8_t *newmem =
                static_cast<uint8_t *>(mmap(0,
                                            newlength,
                                            PROT_READ | PROT_WRITE | PROT_EXEC,
                                            MAP_PRIVATE | MAP_ANONYMOUS,
                                            -1, 0));
            memcpy(newmem, mem, length - freebytes);
            memcpy(newmem + length - freebytes, buf, buflength);
            munmap(mem, length);
            mem = newmem;
        }
        else {
            mem = r;
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

std::size_t Asm::VectorWriter::size() const
{
    return length - freebytes;
}

// Designed to be used in tests.
void Asm::VectorWriter::canonical_hex(std::string &o)
{
    Util::hex_dump(mem, length - freebytes, o);
}

void Asm::VectorWriter::debug_print(std::size_t offset)
{
    Util::debug_hex_print(mem + offset, length - freebytes - offset);
}

uint8_t *Asm::VectorWriter::get_mem(int64_t offset)
{
    return mem + offset;
}

Asm::VectorWriter::voidf Asm::VectorWriter::get_exec_func(int64_t offset)
{
    return reinterpret_cast<VectorWriter::voidf>(mem + offset);
}
uint64_t Asm::VectorWriter::get_start_addr(int64_t offset)
{
    return reinterpret_cast<uint64_t>(mem + offset);
}
void *Asm::VectorWriter::get_start_ptr(int64_t offset)
{
    return reinterpret_cast<void *>(mem + offset);
}

Asm::CountingVectorWriter::CountingVectorWriter(std::size_t &current_size_, std::size_t initial_size)
    : current_size(current_size_), VectorWriter(initial_size) { }

void Asm::CountingVectorWriter::a(const uint8_t *buf, std::size_t length)
{
    current_size += length;
    VectorWriter::a(buf, length);
}

void Asm::CountingVectorWriter::a(uint8_t byte)
{
    current_size++;
    VectorWriter::a(byte);
}

void Asm::CountingVectorWriter::a(Asm::CountingVectorWriter const &vw)
{
    current_size += vw.size();
    VectorWriter::a(vw);
}
