#include <asm.hh>
#include <util.hh>
#include <mremap.hh>
#include <myassert.hh>
#include <iterator>
#include <cstdio>
#include <cstring>
#include <sys/mman.h>
#if defined(DEBUG) && defined(CONFIG_UDIS86)
extern "C" {
namespace udis86 {
#include <udis86.h>
}
}
#endif

using namespace Asm;

// Register codes.
namespace Asm {
static const uint8_t register_codes[] = {
    0,1,2,3,4,5,6,7, // EAX-EDI
    0,1,2,3,4,5,6,7, // RAX-RDI
    0,1,2,3,4,5,6,7, // R8-R15
    0,1,2,3,4,5,6,7, // MM0-MM7
    0,1,2,3,4,5,6,7, // XMM0-XMM7
    0,1,2,3,4,5,6,7  // XMM8-XMM15
};
static char const *register_names[] = {
    "EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI",
    "RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI",
    "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
    "MM0", "MM1", "MM2", "MM3", "MM4", "MM5", "MM6", "MM7",
    "XMM0", "XMM1", "XMM2", "XMM3", "XMM4", "XMM5", "XMM6", "XMM7",
    "XMM8", "XMM9", "XMM10", "XMM11", "XMM12", "XMM13", "XMM14", "XMM15",
    "AL", "CL", "DL", "BL", "AH", "CH", "DH", "BH"
    "FS", "GS",
    "NOT_A_REGISTER"
};
}
char const *Asm::register_name(Register reg) {
    assert(reg < sizeof(register_names)/sizeof(char const *));
    return register_names[reg];
}
uint8_t Asm::register_code(Register reg)
{
    assert(reg < (sizeof(register_codes)/sizeof(uint8_t)));
    uint8_t r = register_codes[reg];
    assert(r <= 7);
    return r;
}

// Registers which can be specified using +r* (in 64-bit mode).
bool has_additive_code_64(Register r)
{
    return r >= RAX && r <= R15;
}
bool has_additive_code_32(Register r)
{
    return r >= EAX && r <= EDI;
}

namespace Asm {
static unsigned register_byte_sizes[] = {
    4, 4, 4, 4, 4, 4, 4, 4,         // EAX-EDI
    8, 8, 8, 8, 8, 8, 8, 8,         // RAX-RDI
    8, 8, 8, 8, 8, 8, 8, 8,         // R8-R15
    10, 10, 10, 10, 10, 10, 10, 10, // MM0-MM7
    16, 16, 16, 16, 16, 16, 16, 16, // XMM0-XMM7
    16, 16, 16, 16, 16, 16, 16, 16, // XMM8-XMM15
    1, 1, 1, 1, 1, 1, 1, 1          // AL-BH
};
}
unsigned Asm::register_byte_size(Register reg) { assert(reg <= BH); return register_byte_sizes[reg]; }

static uint8_t raw_modrm(uint8_t mod, uint8_t rm, uint8_t reg)
{
//    std::printf("raw MOD %i RM %i REG %i\n", mod, rm, reg);
    assert(mod < 5 && rm < 9 && reg < 9);
    return (mod << 6) | (reg << 3) | rm;
}

// Note that this excludes the 16-bit registers and 8-bit registers.
static bool is_gp3264_register(Register reg)
{
    return (reg >= EAX && reg <= EDI) || (reg >= RAX && reg <= RDI) || (reg >= R8 && reg <= R15);
}
static bool is_gp8_register(Register reg)
{
    return (reg >= AL && reg <= BH);
}

static bool requires_sib(ModrmSib const &modrmsib)
{
//    return !(modrmsib.disp_size == DISP_SIZE_NONE || /*modrmsib.scale == SCALE_1 ||*/ modrmsib.rm_reg == NOT_A_REGISTER);
    return (modrmsib.base_reg != NOT_A_REGISTER ||
            (modrmsib.disp_size != DISP_SIZE_NONE && modrmsib.disp != 0));
}

bool Asm::reg_is_forbidden_in_rm(Register reg)
{
    return reg == ESP || reg == RSP || reg == R12 || reg == MM5 || reg == XMM5;
}

RawModrmSib Asm::raw_modrmsib(ModrmSib const &modrmsib)
{
    RawModrmSib r;
    r.has_disp = true;
    uint8_t mod, rm, reg;

    bool reqs_sib = requires_sib(modrmsib);

    // The special case of RIP.
    if (modrmsib.rip) {
        assert(modrmsib.disp_size == DISP_SIZE_32 &&
               modrmsib.rm_reg == NOT_A_REGISTER &&
               modrmsib.scale == SCALE_1 &&
               modrmsib.base_reg == NOT_A_REGISTER);
        r.modrm = raw_modrm(0, 5, modrmsib.reg != NOT_A_REGISTER ? register_code(modrmsib.reg) : 0);
        r.sib = 0;
        r.has_disp = modrmsib.disp_size != DISP_SIZE_NONE;
        return r;
    }

    // Set mod.
    if (modrmsib.disp_size == DISP_SIZE_NONE) {
         mod = 3;
         r.has_disp = false;
    }
    else if (modrmsib.disp == 0 && modrmsib.rm_reg != EBP && modrmsib.rm_reg != RBP && modrmsib.rm_reg != R13) {
        mod = 0;
        r.has_disp = false;
    }
    else if(modrmsib.disp_size == DISP_SIZE_8)
        mod = 1;
    else if (modrmsib.disp_size == DISP_SIZE_32)
        mod = 2;
    // Set rm.
    if (reqs_sib)//(modrmsib.scale != SCALE_1 || modrmsib.rm_reg == NOT_A_REGISTER)
        rm = 4;
    else {
        // Commented out in assert because (X)MM registers are also possible here.
        assert(/*is_gp3264_register(modrmsib.rm_reg) &&*/ ((! reg_is_forbidden_in_rm(modrmsib.rm_reg) || mod == 3)));
        rm = register_code(modrmsib.rm_reg);
    }
    // Set reg.
    reg = (modrmsib.reg != NOT_A_REGISTER ? register_code(modrmsib.reg) : 0);

//    std::printf("MOD %x RM %x REG %x\n", mod, rm, reg);
    // According to the x86 manuals, there's a weird gap in the licitly encodable instructions here:
    // [UPDATE] Hmm, or maybe it's just a typographical error? The font in the modrm table is smaller in the relevant
    // cell but it still contains 8 values, on closer inspection.
//    assert(! (mod == 1 && (rm == 6 || rm == 7) && reg == 2));

    r.modrm = raw_modrm(mod, rm, reg);

    // Add SIB if required.
    if (! reqs_sib) {//(mod == 3 || rm != 4) {
        r.sib = 0;
    }
    else {
//        std::printf("SIB !!!!\n");
        // SIB has the same structure as a modrm byte, so we can use raw_modrm again.

        // Set mod.
        uint8_t sib_mod, sib_rm, sib_reg;
        if (modrmsib.scale == SCALE_1)
            sib_mod = 0;
        else if (modrmsib.scale == SCALE_2)
            sib_mod = 1;
        else if (modrmsib.scale == SCALE_4)
            sib_mod = 2;
        else if (modrmsib.scale == SCALE_8)
            sib_mod = 3;
        // Set rm (index).
        if (modrmsib.base_reg == NOT_A_REGISTER)
            sib_rm = 4;
        else {
            assert(is_gp3264_register(modrmsib.rm_reg) && (! reg_is_forbidden_in_rm(modrmsib.rm_reg)));
            sib_rm = register_code(modrmsib.rm_reg);
        }
        // Set reg (base).
        Register base_reg = (modrmsib.base_reg == NOT_A_REGISTER ? modrmsib.rm_reg : modrmsib.base_reg);
        assert(is_gp3264_register(base_reg) && register_byte_size(base_reg) == 8);
        sib_reg = register_code(base_reg);

        // Note that reg/rm are in the opposite order as compared to the real modrm byte.
//        std::printf("SIB %i\n", sib_mod);
        r.sib = raw_modrm(sib_mod, sib_reg, sib_rm);
    }

    return r;
}

Register Asm::ModrmSib::simple_register() const
{
    if (/*scale == SCALE_1 &&*/ reg == NOT_A_REGISTER && disp_size == DISP_SIZE_NONE)
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
    return (rm_reg == NOT_A_REGISTER || (rm_reg >= EAX && rm_reg <= R15)) &&
           (reg == NOT_A_REGISTER || (reg >= EAX && reg <= R15));
}

bool Asm::ModrmSib::gp8_registers_only() const
{
    return (rm_reg == NOT_A_REGISTER || (rm_reg >= AL && rm_reg <= BH)) &&
           (reg == NOT_A_REGISTER || (reg >= AL && reg <= BH));
}

bool Asm::ModrmSib::gp_registers_only() const
{
    return (rm_reg == NOT_A_REGISTER || (rm_reg >= EAX && rm_reg <= R15) || (rm_reg >= AL && rm_reg <= BH)) &&
           (reg == NOT_A_REGISTER || (reg >= EAX && reg <= R15) || (reg >= AL && reg <= BH));
}

static bool mm_registers_only_(ModrmSib const &modrm, Register mm_start, Register mm_end)
{
    // A bit complicated, because the RM field might (obligatorily) contain a GP register
    // rather than an (X)MM register if it's a memory access.

    if (modrm.disp_size == DISP_SIZE_NONE) {
        if (modrm.rm_reg != NOT_A_REGISTER && (modrm.rm_reg < mm_start || modrm.rm_reg > mm_end))
            return false;
    }
    else {
        if (modrm.rm_reg != NOT_A_REGISTER && (modrm.rm_reg < EAX || modrm.rm_reg > R15))
            return false;
    }
    if (modrm.reg != NOT_A_REGISTER && (modrm.reg < mm_start || modrm.reg > mm_end))
        return false;
    return true;
}

bool Asm::ModrmSib::mm_registers_only() const
{
    return mm_registers_only_(*this, MM0, MM7);
}

bool Asm::ModrmSib::xmm_registers_only() const
{
    return mm_registers_only_(*this, XMM0, XMM15);
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
                    /*disp_size*/ (short_displacement || displacement == 0) ? DISP_SIZE_8 : DISP_SIZE_32,
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
ModrmSib rip(int32_t disp)
{
    return rip_1op(NOT_A_REGISTER, disp);
}
ModrmSib rip_1op(Register reg, int32_t disp)
{
    return ModrmSib(true, NOT_A_REGISTER, DISP_SIZE_32, disp, reg);
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

static bool is_extended_reg(Register reg) // These need REX_B/REX_R
{
    return (reg >= R8 && reg <= R15) || (reg >= XMM8 && reg <= R15);
}
static uint8_t compute_rex(ModrmSib const &modrmsib, Size size, bool allow_rex_w=true) // Returns 0 if no REX.
{
    uint8_t rex = (size == SIZE_64 && allow_rex_w ? REX_W : 0);
    if (size == SIZE_64)
        rex |= REX_W;

    if (! requires_sib(modrmsib)) {
        // No SIB.
        if (is_extended_reg(modrmsib.rm_reg))
            rex |= REX_B;
        if (is_extended_reg(modrmsib.reg))
            rex |= REX_R;
    }
    else {
        // Yes SIB.
        if (is_extended_reg(modrmsib.rm_reg))
            rex |= REX_X;
        if (is_extended_reg(modrmsib.reg))
            rex |= REX_R;
    }

    if (rex != 0)
        rex |= REX_PREFIX;
    return rex;
}
static uint8_t compute_rex_for_reg(Register reg, Size size, bool allow_rex_w=true)
{
    uint8_t rex = (size == SIZE_64 && allow_rex_w ? REX_W : 0);
    rex |= REX_PREFIX;
    if (reg >= R8 && reg <= R15)
        rex |= REX_B;
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

// Disp.
template <class IntT>
Asm::Disp<IntT>::Disp(IntT i_) : i(i_), op(DISP_NO_OP) { }
template <class IntT>
Asm::Disp<IntT>::Disp(IntT i_, DispOp op_) : i(i_), op(op_) { }
template <class IntT>
IntT Asm::Disp<IntT>::get(std::size_t isize) const
{
    return (op == DISP_NO_OP ? i : (op == DISP_ADD_ISIZE ? i + isize : i - isize));
}
template class Disp<int8_t>;
template class Disp<int32_t>;

// DispSetter.
template <class WriterT, class IntT>
Asm::DispSetter<WriterT, IntT>::DispSetter(WriterT &w_, std::size_t isize_, std::size_t disp_position_)
    : w(w_), isize(isize_), disp_position(disp_position_) { }
template <class WriterT, class IntT>
void Asm::DispSetter<WriterT, IntT>::set(Disp<IntT> const &d)
{
    std::printf("DISP POS %li\n", disp_position);
    w.set_at(disp_position, d.get(isize));
}
template class DispSetter<VectorWriter, int8_t>;
template class DispSetter<VectorWriter, int32_t>;


//
// <<<<<<<<<< START OF INSTRUCTIONS <<<<<<<<<<
//

//
// ADC, ADD, AND, OR, SUB, XOR
//

template <class WriterT, uint8_t OPCODE, Size RM_SIZE>
static void X_rm_reg_(Assembler<WriterT> &a, WriterT &w, ModrmSib const &modrmsib)
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
    { X_rm_reg_<WriterT, opcode, rm_size>(*this, w, modrmsib); }
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
static void add_rmXX_imm32_(Assembler<WriterT> &a, WriterT &w, ModrmSib modrmsib, ImmT src)
{
    assert((! modrmsib.has_reg_operand()) &&
           modrmsib.gp3264_registers_only() /*&&
           modrmsib.all_register_operands_have_size(RM_SIZE)*/);

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
    { add_rmXX_imm32_<WriterT, size, immt, imm_size, simple_opcode, complex_opcode, extension>(*this, w, modrmsib, src); }
INST(adc_rm32_imm8, SIZE_32, uint8_t, SIZE_8, 0, 0x83, EDX/*2*/)
INST(adc_rm64_imm8, SIZE_64, uint8_t, SIZE_8, 0, 0x83, EDX/*2*/)
INST(adc_rm32_imm32, SIZE_32, uint32_t, SIZE_32, 0x81, 0x81, EDX/*2*/)
INST(adc_rm64_imm32, SIZE_64, uint32_t, SIZE_32, 0x81, 0x81, EDX/*2*/)

INST(add_rm32_imm8, SIZE_32, uint8_t, SIZE_8, 0, 0x83, EAX/*0*/)
INST(add_rm64_imm8, SIZE_64, uint8_t, SIZE_8, 0, 0x83, EAX/*0*/)
INST(add_rm32_imm32, SIZE_32, uint32_t, SIZE_32, 0x81, 0x81, EAX/*0*/)
INST(add_rm64_imm32, SIZE_64, uint32_t, SIZE_32, 0x81, 0x81, EAX/*0*/)

INST(and_rm32_imm8, SIZE_32, uint8_t, SIZE_8, 0, 0x83, ESP/*4*/)
INST(and_rm64_imm8, SIZE_64, uint8_t, SIZE_8, 0, 0x83, ESP/*4*/)
INST(and_rm32_imm32, SIZE_32, uint32_t, SIZE_32, 0x81, 0x81, ESP/*4*/)
INST(and_rm64_imm32, SIZE_64, uint32_t, SIZE_32, 0x81, 0x81, ESP/*4*/)

INST(or_rm32_imm8, SIZE_32, uint8_t, SIZE_8, 0, 0x83, ECX/*1*/)
INST(or_rm64_imm8, SIZE_64, uint8_t, SIZE_8, 0, 0x83, ECX/*1*/)
INST(or_rm32_imm32, SIZE_32, uint32_t, SIZE_32, 0x81, 0x81, ECX/*1*/)
INST(or_rm64_imm32, SIZE_64, uint32_t, SIZE_32, 0x81, 0x81, ECX/*1*/)

INST(sub_rm32_imm8, SIZE_32, uint8_t, SIZE_8, 0, 0x83, EBX/*5*/)
INST(sub_rm64_imm8, SIZE_64, uint8_t, SIZE_8, 0, 0x83, EBX/*5*/)
INST(sub_rm32_imm32, SIZE_32, uint32_t, SIZE_32, 0x81, 0x81, EBP/*5*/)
INST(sub_rm64_imm32, SIZE_64, uint32_t, SIZE_32, 0x81, 0x81, EBP/*5*/)

INST(xor_rm32_imm8, SIZE_32, uint8_t, SIZE_8, 0, 0x83, ESI/*6*/)
INST(xor_rm64_imm8, SIZE_64, uint8_t, SIZE_8, 0, 0x83, ESI/*6*/)
INST(xor_rm32_imm32, SIZE_32, uint32_t, SIZE_32, 0x81, 0x81, ESI/*6*/)
INST(xor_rm64_imm32, SIZE_64, uint32_t, SIZE_32, 0x81, 0x81, ESI/*6*/)
#undef INST

//
// CALL
//

template <class WriterT>
typename Asm::Assembler<WriterT>::NrDispSetter Asm::Assembler<WriterT>::call_rel32(Disp<int32_t> const &disp)
{
    AB(0xE8);
    std::size_t disp_position = w.size();
    A32(disp.get(5));
    return typename Asm::Assembler<WriterT>::NrDispSetter(w, 5, disp_position);
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
static void cmp_rmXX_imm_(Assembler<WriterT> &a, WriterT &w, ModrmSib modrmsib, ImmT imm)
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
    { cmp_rmXX_imm_<WriterT, size, rexbyte, opcode, extension, immtype, immtypesize>(*this, w, modrmsib, imm);  }
INST(cmp_rm32_imm8, 4, SIZE_32, 0x83, EDI/*7*/, uint8_t, SIZE_8)
INST(cmp_rm64_imm8, 8, SIZE_64, 0x83, EDI/*7*/, uint8_t, SIZE_8)
INST(cmp_rm32_imm32, 4, SIZE_32, 0x81, EDI/*7*/, uint32_t, SIZE_32)
INST(cmp_rm64_imm32, 8, SIZE_64, 0x81, EDI/*7*/, uint32_t, SIZE_32)
#undef INST

template <class WriterT, uint8_t REXBYTE, uint8_t OPCODE, class ImmT, Size ImmTSize>
static void cmp_XX_imm32_(Assembler<WriterT> &a, WriterT &w, ImmT imm)
{
    ABIFNZ(REXBYTE);
    AB(OPCODE);
    w.a(reinterpret_cast<uint8_t*>(&imm), ImmTSize);
}

#define INST(name, rexbyte, opcode, immtype, immtypesize) \
    template <class WriterT> void Asm::Assembler<WriterT>:: \
    name (immtype imm) \
    { cmp_XX_imm32_<WriterT, rexbyte, opcode, immtype, immtypesize>(*this, w, imm); }
INST(cmp_al_imm8, 0, 0x3C, uint8_t, SIZE_8)
INST(cmp_eax_imm32, 0, 0x3D, uint32_t, SIZE_32)
INST(cmp_rax_imm32, REX_PREFIX | REX_W, 0x3D, uint32_t, SIZE_32)
#undef INST

template <class WriterT, Size SIZE>
static void cmp_rmXX_reg_(Assembler<WriterT> &a, WriterT &w, ModrmSib const &modrmsib)
{
    ABIFNZ(compute_rex(modrmsib, SIZE));
    AB(0x39);
    write_modrmsib_disp(w, modrmsib);
}
#define INST(name, size) \
    template <class WriterT> void Asm::Assembler<WriterT>:: \
    name (ModrmSib const &modrmsib) \
    { cmp_rmXX_reg_<WriterT, size>(*this, w, modrmsib); }
INST(cmp_rm32_reg, SIZE_32)
INST(cmp_rm64_reg, SIZE_64)
#undef INST

//
// FABS
//
template <class WriterT>
void Asm::Assembler<WriterT>::fabs_st0()
{
    AZ("\xD9\xE1");
}

//
// FADD, FADDP, FDIV, FDIVP, FIADD, FIDIV, FIMUL, FISUB, FMUL, FMULP, FSUB, FSUBP
//
template <class WriterT, uint8_t OPCODE, Register EXTENSION>
static void fadd_st0_mXXfp_(Assembler<WriterT> &a, WriterT &w, ModrmSib modrmsib)
{
    assert(modrmsib.simple_memory());
    AB(OPCODE);
    modrmsib.reg = EXTENSION;
    write_modrmsib_disp(w, modrmsib);
}

#define INST(name, opcode, extension) \
    template <class WriterT> void Asm::Assembler<WriterT>:: \
    name (ModrmSib const &modrmsib) \
    { fadd_st0_mXXfp_<WriterT, opcode, extension>(*this, w, modrmsib); }
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
static void fadd_st_st_(Assembler<WriterT> &a, WriterT &w, unsigned streg)
{
    assert(streg < 8);
    AB(OPCODE1);
    AB(OPCODE2 + streg);
}

#define INST(name, opcode1, opcode2) \
    template <class WriterT> void Asm::Assembler<WriterT>:: \
    name (unsigned streg) \
    { fadd_st_st_<WriterT, opcode1, opcode2>(*this, w, streg); }
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
static void Xcom_st_sti(Assembler<WriterT> &a, WriterT &w, unsigned streg)
{
    assert(streg < 8);
    AB(OPCODE1);
    AB(OPCODE2 + streg);
}

#define INST(name, opcode1, opcode2) \
    template <class WriterT> void Asm::Assembler<WriterT>:: \
    name (unsigned streg) { Xcom_st_sti<WriterT, opcode1, opcode2>(*this, w, streg); }
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
static void fld_mX_(Assembler<WriterT> &a, WriterT &w, ModrmSib modrmsib)
{
    assert(modrmsib.simple_memory());
    AB(OPCODE);
    modrmsib.reg = EXTENSION;
    write_modrmsib_disp(w, modrmsib);
}

#define INST(name, opcode, extension) \
    template <class WriterT> void Asm::Assembler<WriterT>:: \
    name (ModrmSib const &modrmsib) \
    { fld_mX_<WriterT, opcode, extension>(*this, w, modrmsib); }
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
template <class WriterT> void Asm::Assembler<WriterT>::fnop()
{
    AZ("\xD9\xD0");
}

//
// FST
//
template <class WriterT, uint8_t OPCODE, Register EXTENSION>
static void fst_mXX_st0_(Assembler<WriterT> &a, WriterT &w, ModrmSib modrmsib)
{
    assert(modrmsib.simple_memory());
    AB(OPCODE);
    modrmsib.reg = EXTENSION;
    write_modrmsib_disp(w, modrmsib);
}

#define INST(name, opcode, extension) \
    template <class WriterT> void Asm::Assembler<WriterT>::     \
    name (ModrmSib const &modrmsib) \
    { fst_mXX_st0_<WriterT, opcode, extension>(*this, w, modrmsib); }
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
static void Xmul_reg_rm_(Assembler<WriterT> &a, WriterT &w, ModrmSib const &modrmsib)
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
    { Xmul_reg_rm_<WriterT, rm_size>(*this, w, modrmsib); }
INST(imul_reg_rm32, SIZE_32)
INST(imul_reg_rm64, SIZE_64)
#undef INST

template <class WriterT, uint8_t OPCODE, Size RM_SIZE, Register EXTENSION>
static void mul_dxax_rm_(Assembler<WriterT> &a, WriterT &w, ModrmSib modrmsib)
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
    { mul_dxax_rm_<WriterT, opcode, rm_size, extension>(*this, w, modrmsib); }
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
static void incdec_(Assembler<WriterT> &a, WriterT &w, ModrmSib modrmsib)
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
    { incdec_<WriterT, extension, opcode, rm_size>(*this, w, modrmsib); }
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
template <class WriterT, uint8_t OPCODE_PREFIX, uint8_t OPCODE, class DispT, DispSize DISP_SIZE>
static DispSetter<WriterT, typename DispT::IntType> XX_XX_rel_(Assembler<WriterT> &a, WriterT &w, DispT const &disp, BranchHint hint)
{
    std::size_t instruction_size = 1 + DISP_SIZE;

    if (hint == BRANCH_HINT_TAKEN) {
        ++instruction_size;
        AB(0x3E);
    }
    else if (hint == BRANCH_HINT_NOT_TAKEN) {
        ++instruction_size;
        AB(0x2E);
    }

    if (OPCODE_PREFIX != 0) {
        AB(OPCODE_PREFIX);
        ++instruction_size;
    }

    AB(OPCODE);
    std::size_t disp_position = w.size();
    typename DispT::IntType d = disp.get(instruction_size);
    w.a(reinterpret_cast<uint8_t *>(&d), DISP_SIZE);

    return DispSetter<WriterT, typename DispT::IntType>(w, instruction_size, disp_position);
}
#define INST(prefix, opcode) \
    template <class WriterT> DispSetter<WriterT, int8_t> Asm::Assembler<WriterT>:: \
    prefix ## _st_rel8 (Disp<int8_t> const &disp, BranchHint hint) \
    { return XX_XX_rel_<WriterT, 0, opcode, Disp<int8_t>, DISP_SIZE_8>(*this, w, disp, hint); }
#define INST2(prefix, opcode) \
    INST(prefix, opcode) \
    template <class WriterT> DispSetter<WriterT, int32_t> Asm::Assembler<WriterT>:: \
    prefix ## _nr_rel32 (Disp<int32_t> const &disp, BranchHint hint) \
    { return XX_XX_rel_<WriterT, 0x0F, opcode + 0x10, Disp<int32_t>, DISP_SIZE_32 >(*this, w, disp, hint); }
INST2(ja, 0x77) INST2(jbe, 0x76) INST2(jc, 0x72)
INST2(jg, 0x7F) INST2(jge, 0x7D) INST2(jl, 0x7C)
INST2(jle, 0x7E) INST2(jnc, 0x73) INST2(jno, 0x71)
INST2(jns, 0x79) INST2(jnz, 0x75) INST2(jo, 0x70)
INST2(jpe, 0x7A) INST2(jpo, 0x7B) INST(jrcxz, 0xE3) // non-use of INST2 for jrcxz is deliberate.
INST2(js, 0x78) INST2(jz, 0x74)
#undef INST2
#undef INST


//
// INT
//
template <class WriterT>
void Asm::Assembler<WriterT>::int3()
{
    AB(0xCC);
}
template <class WriterT>
void Asm::Assembler<WriterT>::int_imm8(uint8_t imm)
{
    AB(0xCD);
    AB(imm);
}


//
// JMP
//

template <class WriterT, class IntT, Size IntTSize>
static DispSetter<WriterT, IntT> jmp_nr_relXX_(Assembler<WriterT> &a, WriterT &w, Disp<IntT> const &disp, BranchHint hint)
{
    COMPILE_ASSERT(IntTSize == 4 || IntTSize == 1);
    AB(IntTSize == SIZE_8 ? 0xEB : 0xE9);
    std::size_t disp_position = w.size();
    IntT d = disp.get(1 + IntTSize);
    w.a(reinterpret_cast<uint8_t *>(&d), IntTSize);
    return DispSetter<WriterT, IntT>(w, 1 + IntTSize, disp_position);
}

#define INST(name, int_t, int_t_size) \
    template <class WriterT> DispSetter<WriterT, int_t> Asm::Assembler<WriterT>:: \
    name(Disp<int_t> const &disp, BranchHint hint) \
    { return jmp_nr_relXX_<WriterT, int_t, int_t_size>(*this, w, disp, hint); }
INST(jmp_nr_rel8, int8_t, SIZE_8)
INST(jmp_nr_rel32, int32_t, SIZE_32)
#undef INST

template <class WriterT>
void Asm::Assembler<WriterT>::jmp_nr_rm64(ModrmSib const &modrmsib_, BranchHint hint)
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
static void mov_rm_reg_(Assembler<WriterT> &a, WriterT &w, ModrmSib const &modrmsib)
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
    { mov_rm_reg_<WriterT, reversed, rm_size>(*this, w, modrmsib); }
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
    ABIFNZ(compute_rex_for_reg(reg, SIZE));
    AB(0xB8 + register_code(reg));
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
// SSE(2) MOV* instructions.
//
template <class WriterT, uint8_t FIRST_OPCODE_BYTE, uint8_t FINAL_OPCODE_BYTE>
static void movdqa_(Assembler<WriterT> &a, WriterT &w, ModrmSib const &modrmsib)
{
    assert(modrmsib.xmm_registers_only());
    ABIFNZ(compute_rex(modrmsib, SIZE_128));
    AB(FIRST_OPCODE_BYTE);
    AB(0x0F);
    AB(FINAL_OPCODE_BYTE);
    write_modrmsib_disp(w, modrmsib);
}

#define INST(name, first_opcode_byte, final_opcode_byte)     \
    template <class WriterT> void Asm::Assembler<WriterT>:: \
    name (ModrmSib const &modrmsib) \
    { movdqa_<WriterT, first_opcode_byte, final_opcode_byte>(*this, w, modrmsib); }
INST(movdqa_mm_mmm128, 0x66, 0x6F)
INST(movdqa_mmm128_mm, 0x66, 0x7F)
INST(movdqu_mm_mmm128, 0xF3, 0x6F)
INST(movdqu_mmm128_mm, 0xF3, 0x7F)
#undef INST

template <class WriterT, uint8_t FINAL_OPCODE_BYTE>
static void movq_(Assembler<WriterT> &a, WriterT &w, ModrmSib const &modrmsib)
{
    assert(modrmsib.mm_registers_only());
    ABIFNZ(compute_rex(modrmsib, SIZE_128));
    AB(0x0F);
    AB(FINAL_OPCODE_BYTE);
    write_modrmsib_disp(w, modrmsib);
}

#define INST(name, final_opcode_byte) \
    template <class WriterT> void Asm::Assembler<WriterT>:: \
    name (ModrmSib const &modrmsib) \
    { movq_<WriterT, final_opcode_byte>(*this, w, modrmsib); }
INST(movq_mm_mmm64, 0x6F)
INST(movq_mmm64_mm, 0x7F)
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
// NOT
//
template <class WriterT, Size RM_SIZE>
static void not_X_(Assembler<WriterT> &a, WriterT &w, ModrmSib modrmsib)
{
    assert((! modrmsib.has_reg_operand()) &&
           modrmsib.gp3264_registers_only() &&
           modrmsib.all_register_operands_have_size(RM_SIZE));
    ABIFNZ(compute_rex(modrmsib, RM_SIZE));
    AB(0xF7);
    modrmsib.reg = RDX/*2*/;
    write_modrmsib_disp(w, modrmsib);
}

#define INST(name, rm_size) \
    template <class WriterT> void Asm::Assembler<WriterT>:: \
    name (ModrmSib const &modrmsib) \
    { not_X_<WriterT, rm_size>(*this, w, modrmsib); }
INST(not_rm32, SIZE_32)
INST(not_rm64, SIZE_64)
#undef INST

//
// POP, PUSH
//

template <class WriterT>
void Asm::Assembler<WriterT>::pop_reg64(Register reg)
{
    assert(has_additive_code_64(reg));
    ABIFNZ(compute_rex_for_reg(reg, SIZE_64, false));
    AB(0x58 + register_code(reg));
}

template <class WriterT>
void Asm::Assembler<WriterT>::push_reg64(Register reg)
{
    assert(has_additive_code_64(reg));
//    std::printf("\nHEX: %x %x\n\n", (int)compute_rex_for_reg(reg, SIZE_64, false), 0x50 + register_code(reg));
    ABIFNZ(compute_rex_for_reg(reg, SIZE_64, false));
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
        ABIFNZ(compute_rex(modrmsib, RM_SIZE, false));
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
static void push_imm_(Assembler<WriterT> &a, WriterT &w, ImmT imm)
{
    AB(OPCODE);
    w.a(reinterpret_cast<uint8_t *>(&imm), ImmTSize);
}
#define INST(name, immt, immtsize, opcode) \
    template <class WriterT> \
    void Asm::Assembler<WriterT>:: name (immt imm) \
    { push_imm_<WriterT, immt, immtsize, opcode>(*this, w, imm); }
INST(push_imm8, uint8_t, SIZE_8, 0x6A)
INST(push_imm32, uint32_t, SIZE_32, 0x68)
#undef INST

//
// POPF, PUSHF
//
template <class WriterT>
void Asm::Assembler<WriterT>::popf()
{
    AB(0x9D);
}
template <class WriterT>
void Asm::Assembler<WriterT>::pushf()
{
    AB(0x9C);
}

//
// PXOR
//
template <class WriterT, Size SIZE>
static void pxor_(Assembler<WriterT> &a, WriterT &w, ModrmSib const &modrmsib)
{
    assert(modrmsib.xmm_registers_only());
    ABIFNZ(compute_rex(modrmsib, SIZE, false));
    if (SIZE == SIZE_64)
        AZ("\x0F\xEF");
    else
        AZ("\x66\x0F\xEF");
    write_modrmsib_disp(w, modrmsib);
}

#define INST(name, size) \
    template <class WriterT> \
    void Asm::Assembler<WriterT>:: name (ModrmSib const &modrmsib) \
    { pxor_<WriterT, size>(*this, w, modrmsib); }
INST(pxor_mm_mmm64, SIZE_64)
INST(pxor_mm_mmm128, SIZE_128)
#undef INST

//
// RET
//

template <class WriterT>
void Asm::Assembler<WriterT>::ret()
{
    AB(0xc3);
}

#undef AB
#undef AZ
#undef A
#undef AL
#undef A64
#undef REX_W_S

#ifdef DEBUG
template <class WriterT>
void Asm::Assembler<WriterT>::emit_save_all_regs()
{
    // Save flags register.
    pushf();
    // Push all GP registers.
    for (int i = RAX; i <= R15; ++i) {
        push_rm64(reg_1op(static_cast<Register>(i)));
    }
    // Push all XMM registers.
    mov_reg_rm64(reg_2op(RCX, RSP)); // Can't use RSP as base reg owing to weird x86 instruction encoding.
    sub_rm64_imm32(reg_1op(RSP), 16*16); // Space for 16 16-byte registers.
    for (int i = XMM0; i <= XMM15; ++i) {
        movdqu_mmm128_mm(mem_2op(static_cast<Register>(i)/*reg*/, RCX/*base*/, NOT_A_REGISTER/*index*/, SCALE_1, (i-XMM0+1)*-16));
    }
}

template <class WriterT>
void Asm::Assembler<WriterT>::emit_restore_all_regs()
{
    // Restore saved registers.
    mov_reg_rm64(reg_2op(RCX, RSP)); // Can't use RSP as base reg owing to weird x86 instruction encoding.    
    for (int i = XMM15; i >= XMM0; --i) {
        movdqu_mm_mmm128(mem_2op(static_cast<Register>(i)/*reg*/, RCX/*base*/, NOT_A_REGISTER/*index*/, SCALE_1, (XMM15-i)*16));
    }
    add_rm64_imm32(reg_1op(RSP), 16*16);
    for (int i = R15; i >= RAX; --i) {
        pop_rm64(reg_1op(static_cast<Register>(i)));
    }
    popf();
}

template <class WriterT>
void Asm::Assembler<WriterT>::emit_debug_print(char const *str)
{
    emit_save_all_regs();
    // Call puts.
    mov_reg_imm64(RDI, PTR(str));
    mov_reg_imm64(RCX, PTR(std::puts));
    mov_reg_imm32(EAX, 0);
    call_rm64(reg_1op(RCX));
    emit_restore_all_regs();
}

template <class WriterT>
void Asm::Assembler<WriterT>::emit_set_single_step_onoff(bool on)
{
    push_rm64(reg_1op(RAX));
    pushf();
    pop_rm64(reg_1op(RAX));
    if (on) {
        or_rm64_imm8(reg_1op(RAX), 0x80);
    }
    else {
        // Slightly roundabout method (we can't just AND RAX with a 64-bit
        // immediate value because x86 instruction encoding generally doesn't
        // permit 64-bit immediate values).
        not_rm64(reg_1op(RAX));
        or_rm64_imm8(reg_1op(RAX), 0x80);
        not_rm64(reg_1op(RAX));
    }
    push_rm64(reg_1op(RAX));
    popf();
    pop_rm64(reg_1op(RAX));
}
#endif DEBUG

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

template <class IntT>
void Asm::VectorWriter::set_at(std::size_t index, IntT value)
{
//    std::printf("SIZE: [i]%li %li\n", index, length-freebytes);
    assert(index + sizeof(IntT) <= (length - freebytes));
    *reinterpret_cast<IntT *>(mem + index) = value;
}
#define INST(t) \
    template void Asm::VectorWriter::set_at<t>(std::size_t index, t value);
INST(int8_t) INST(uint8_t) INST(int32_t) INST(uint32_t) INST(int64_t) INST(uint64_t)
#undef INST


std::size_t Asm::VectorWriter::size() const
{
    return length - freebytes;
}

// Designed to be used in tests.
void Asm::VectorWriter::canonical_hex(std::string &o)
{
    Util::hex_dump(mem, length - freebytes, o);
}

void Asm::VectorWriter::debug_print(std::size_t offset, std::size_t highlight_start, std::size_t highlight_end)
{
    Util::debug_hex_print(mem + offset, length - freebytes - offset, 16, 4, highlight_start, highlight_end);
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
