#ifndef ASM_HH
#define ASM_HH

#include <stdint.h>
#include <cstddef>
#include <vector>
#include <map>
#include <string>

namespace Asm {

enum Register {
    EAX=0, ECX, EDX, EBX, ESP, EBP, ESI, EDI,
    RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI,
    R8D, R9D, R10D, R11D, R12D, R13D, R14D, R15D,
    MM0, MM1, MM2, MM3, MM4, MM5, MM6, MM7,
    XMM0, XMM1, XMM2, XMM3, XMM4, XMM5, XMM6, XMM7,

    // For the most part, the assembler doesn't support fiddling around
    // with 8-bit registers, but there are one or two exceptions
    // (e.g. MOV). There's no support at all for doing stuff with the
    // 16-bit registers.
    AL, CL, DL, BL, AH, CH, DH, BH,

    FS,GS, // Other segment registers are ignored in 64-bit mode.

    NOT_A_REGISTER
};

char const *register_name(Register reg);

enum Size {
    SIZE_8=1,
    SIZE_16=2,
    SIZE_32=4,
    SIZE_64=8,
    SIZE_80=10,
};

enum DispSize {
    DISP_SIZE_NONE=0,
    DISP_SIZE_8=1,
    DISP_SIZE_32=4
};

// For SIB.
enum Scale {
    SCALE_1=1,
    SCALE_2=2,
    SCALE_4=4,
    SCALE_8=8
};

struct ModrmSib {
    ModrmSib(bool rip_ = false, Register rm_reg_=NOT_A_REGISTER, DispSize disp_size_=DISP_SIZE_NONE,
             int32_t disp_=0, Register reg_=NOT_A_REGISTER, Register base_reg_=NOT_A_REGISTER, Scale scale_=SCALE_1)
        : rip(rip_), rm_reg(rm_reg_), disp_size(disp_size_), disp(disp_), reg(reg_), base_reg(base_reg_), scale(scale_) { }

    // This is horrible, but I suspect there's no significantly-less-horrible alternative scheme.
    //
    // TODO: These comments are out of date.
    //
    // WITH NO SIB:
    //     rm_reg    <- R/M (rows on p. 2-7 of IA32 SDM 2A).
    //     reg       <- Additional reg operand (cols on p. 2-7) or NOT_A_REGISTER if no additional reg operand.
    //     base_reg  <- NOT_A_REGISTER.
    //     disp_size <- DISP_SIZE_NONE if Mod=11; otherwise DISP_SIZE_8 or DISP_SIZE_32.
    //                  (not that for Mod=00, disp_size should be set to 8 or 32, and disp should be set to 0).
    //     disp      <- Displacement.
    //     scale     <- SCALE_1.
    //
    // WITH A SIB:
    //     rm_reg    <- Index.
    //     reg       <- Additional reg operand (as when no SIB is present; see above).
    //     base_reg  <- Base.
    //     disp_size <- (As when no SIB is present; see above).
    //     disp      <- Displacement.
    //     scale     <- SCALE_2 or SCALE_3 or SCALE_4.
    //
    // To create one of these structures without going mad, use 'mem_*' or 'reg_*',
    // functions defined immediately below this struct.

    // Returns a register if there is no SIB, no second operand, and r/m is a register.
    // Otherwise returns NOT_A_REGISTER.
    Register simple_register() const;
    // Return true if all register operands are GP 32 or 64-bit registers.
    bool gp3264_registers_only() const;
    // Return true if all register operands are 8-bit GP registers.
    bool gp8_registers_only() const;
    bool gp_registers_only() const;
    // Returns true if there is no additional reg operand.
    bool has_reg_operand() const;
    // Checks that all register operands in a ModRM byte have a given (byte) size.
    bool all_register_operands_have_size(Size size) const;
    // True if it specifies a memory location only with no additional register operand.
    bool simple_memory() const;

    bool rip;
    Register rm_reg;
    Register reg;
    Register base_reg;
    DispSize disp_size;
    int32_t disp;
    Scale scale;
};
// For two-operands.
ModrmSib mem_2op(Register reg, Register base=NOT_A_REGISTER, Register index=NOT_A_REGISTER, Scale scale=SCALE_1, int32_t displacement=0, bool short_displacement=false);
// For one operand.
ModrmSib mem_1op(Register base=NOT_A_REGISTER, Register index=NOT_A_REGISTER, Scale scale=SCALE_1, int32_t displacement=0, bool short_displacement=false);
ModrmSib mem_2op_short(Register reg, Register base=NOT_A_REGISTER, Register index=NOT_A_REGISTER, Scale scale=SCALE_1, int32_t displacement=0);
ModrmSib mem_1op_short(Register index=NOT_A_REGISTER, Scale scale=SCALE_1, int32_t displacement=0);
ModrmSib reg_2op(Register reg, Register rm);
ModrmSib reg_1op(Register rm);
ModrmSib rip_1op(Register reg, int32_t offset=0);
ModrmSib rip_2op(Register reg2, Register reg1, int32_t offset=0);

enum Rex {
    REX_PREFIX = 0x40,
    REX_W      = 0x08,
    REX_R      = 0x04,
    REX_X      = 0x02,
    REX_B      = 0x01
};

enum BranchHint {
    BRANCH_HINT_NONE,
    BRANCH_HINT_TAKEN,
    BRANCH_HINT_NOT_TAKEN
};

unsigned const NUMBER_OF_REGISTERS = 48;
uint8_t register_code(Register reg);
uint8_t register_rex(Register reg);
unsigned register_byte_size(Register reg);

// This class is used to allow displacements to be expressed as a simple
// function of the size of certain instructions. E.g., when writing a jump
// instruction with a negative displacement, one needs to know the size of
// the jump instruction itself.
enum DispOp {
    DISP_NO_OP,
    DISP_ADD_ISIZE,
    DISP_SUB_ISIZE
};
template <class IntT>
class Disp {
public:
    typedef IntT IntType;

    Disp(IntT i_) : i(i_), op(DISP_NO_OP) { }
    Disp(IntT i_, DispOp op_) : i(i_), op(op_) { }

    IntT get(std::size_t isize) { return (op == DISP_NO_OP ? i : (op == DISP_ADD_ISIZE ? i + isize : i - isize)); }

private:
    IntT i;
    DispOp op;
};
template <class IntT>
Disp<IntT> mkdisp(IntT i, DispOp op = DISP_NO_OP);

template <class WriterT>
class Assembler {
public:
    Assembler(WriterT &writer) : w(writer) { }

    // ADC
    void adc_rm32_reg(ModrmSib const &modrmsib);
    void adc_rm64_reg(ModrmSib const &modrmsib);
    void adc_reg_rm32(ModrmSib const &modrmsib);
    void adc_reg_rm64(ModrmSib const &modrmsib);
    void adc_rm32_imm8(ModrmSib const &modrmsib, uint8_t src);
    void adc_rm64_imm8(ModrmSib const &modrmsib, uint8_t src);
    void adc_rm32_imm32(ModrmSib const &modrmsib, uint32_t src);
    void adc_rm64_imm32(ModrmSib const &modrmsib, uint32_t src);

    // ADD
    void add_rm32_reg(ModrmSib const &modrmsib);
    void add_rm64_reg(ModrmSib const &modrmsib);
    void add_reg_rm32(ModrmSib const &modrmsib);
    void add_reg_rm64(ModrmSib const &modrmsib);
    void add_rm32_imm8(ModrmSib const &modrmsib, uint8_t src);
    void add_rm64_imm8(ModrmSib const &modrmsib, uint8_t src);
    void add_rm32_imm32(ModrmSib const &modrmsib, uint32_t src);
    void add_rm64_imm32(ModrmSib const &modrmsib, uint32_t src);

    // AND
    void and_rm32_reg(ModrmSib const &modrmsib);
    void and_rm64_reg(ModrmSib const &modrmsib);
    void and_reg_rm32(ModrmSib const &modrmsib);
    void and_reg_rm64(ModrmSib const &modrmsib);
    void and_rm32_imm8(ModrmSib const &modrmsib, uint8_t src);
    void and_rm64_imm8(ModrmSib const &modrmsib, uint8_t src);
    void and_rm32_imm32(ModrmSib const &modrmsib, uint32_t src);
    void and_rm64_imm32(ModrmSib const &modrmsib, uint32_t src);

    // CALL
    void call_rel32(int32_t disp);
    void call_rm64(ModrmSib modrmsib);

    // CMP
    void cmp_rm32_imm8(ModrmSib const &modrmsib, uint8_t imm);
    void cmp_rm64_imm8(ModrmSib const &modrmsib, uint8_t imm);
    void cmp_rm32_imm32(ModrmSib const &modrmsib, uint32_t imm);
    void cmp_rm64_imm32(ModrmSib const &modrmsib, uint32_t imm);
    void cmp_al_imm8(uint8_t imm);
    void cmp_eax_imm32(uint32_t imm);
    void cmp_rax_imm32(uint32_t imm); // This is also a special case of cmp_rm64_imm32.

    // DEC
    void dec_rm32(ModrmSib const &modrmsib);
    void dec_rm64(ModrmSib const &modrmsib);
    // Utils:
    void dec_reg32(Register reg) { dec_rm32(reg_1op(reg)); }
    void dec_reg64(Register reg) { dec_rm64(reg_1op(reg)); }

    // FABS
    void fabs_st0();

    // FADD
    void fadd_st0_m32fp(ModrmSib const &modrmsib);
    void fadd_st0_m64fp(ModrmSib const &modrbsib);
    void fadd_st_st0(unsigned streg_src);
    void fadd_st0_st(unsigned streg_dest);
    
    // FADDP
    void faddp();

    // FCOM
    void fcom_st0_st(unsigned streg);
    void fcomp_st0_st(unsigned streg);

    // FDECSTP
    void fdecstp();

    // FDIV
    void fdiv_st0_m32fp(ModrmSib const &modrmsib);
    void fdiv_st0_m64fp(ModrmSib const &modrbsib);
    void fdiv_st_st0(unsigned streg_src);
    void fdiv_st0_st(unsigned streg_dest);

    // FDIVP
    void fdivp();

    // FINCSTP
    void fincstp();

    // FIADD, FIDIV, FILD, FIMUL, FISUB
    void fiadd_st0_m32int(ModrmSib const &modrmsib);
    void fiadd_st0_m16int(ModrmSib const &modrmsib);
    void fidiv_st0_m32int(ModrmSib const &modrmsib);
    void fidiv_st0_m16int(ModrmSib const &modrmsib);
    void fild_m16int(ModrmSib const &modrmsib);
    void fild_m32int(ModrmSib const &modrmsib);
    void fild_m64int(ModrmSib const &modrmsib);
    void fimul_st0_m32int(ModrmSib const &modrmsib);
    void fimul_st0_m16int(ModrmSib const &modrmsib);
    void fisub_st0_m32int(ModrmSib const &modrmsib);
    void fisub_st0_m16int(ModrmSib const &modrmsib);

    // FLD
    void fld_m32fp(ModrmSib const &modrmsib);
    void fld_m64fp(ModrmSib const &mosrmsib);
    void fld_m80fp(ModrmSib const &modrbsib);
    void fld_st(unsigned streg);

    // FMUL
    void fmul_st0_m32fp(ModrmSib const &modrmsib);
    void fmul_st0_m64fp(ModrmSib const &modrbsib);
    void fmul_st_st0(unsigned streg_src);
    void fmul_st0_st(unsigned streg_dest);

    // FMULP
    void fmulp();

    // FNOP
    void fnop();

    // FST
    void fst_m32fp_st0(ModrmSib const &modrmsib);
    void fst_m64fp_st0(ModrmSib const &modrmsib);
    void fst_st_st0(unsigned streg_dest);

    // FSTP
    void fstp_m32fp_st0(ModrmSib const &modrmsib);
    void fstp_m64fp_st0(ModrmSib const &modrmsib);
    void fstp_m80fp_st0(ModrmSib const &modrmsib);
    void fstp_st_st0(unsigned streg_dest);

    // FSUB
    void fsub_st0_m32fp(ModrmSib const &modrmsib);
    void fsub_st0_m64fp(ModrmSib const &modrbsib);
    void fsub_st_st0(unsigned streg_src);
    void fsub_st0_st(unsigned streg_dest);

    // FSUBP
    void fsubp();

    // FUCOM
    void fucom_st0_st(unsigned streg);
    void fucomp_st0_st(unsigned streg);

    // IDIV
    void idiv_edx_eax_rm32(ModrmSib const &modrmsib);
    void idiv_rdx_rax_rm64(ModrmSib const &modrmsib);

    // IMUL
    void imul_reg_rm32(ModrmSib const &modrmsib);
    void imul_reg_rm64(ModrmSib const &modrmsib);
    void imul_edx_eax_rm32(ModrmSib const &modrmsib);
    void imul_rdx_rax_rm64(ModrmSib const &modrmsib);

    // INC
    void inc_rm32(ModrmSib const &modrmsib);
    void inc_rm64(ModrmSib const &modrmsib);
    // Utils:
    void inc_reg32(Register reg) { inc_rm32(reg_1op(reg)); }
    void inc_reg64(Register reg) { inc_rm64(reg_1op(reg)); }

    // Jcc
    // See http://unixwiz.net/techtips/x86-jumps.html (synonyms excluded).
    //
    // JE,JZ             JZ
    // JNE,JNZ           JNZ
    // JB,JNAE,JC        JC
    // JNB,JAE,JNC       JNC
    // JBE,JNA           JBE
    // JA,JNBE           JA
    // JL,JNGE           JL
    // JGE,JNL           JGE
    // JLE,JNG           JLE
    // JG,JNLE           JG
    // JP,JPE            JPE
    // JNP,JPO           JPO
    // JCXZ,JECXZ,JRCXZ  JRCXZ
    void ja_st_rel8(Disp<int8_t> disp, BranchHint hint=BRANCH_HINT_NONE);
    void jc_st_rel8(Disp<int8_t> disp, BranchHint hint=BRANCH_HINT_NONE);
    void jg_st_rel8(Disp<int8_t> disp, BranchHint hint=BRANCH_HINT_NONE);
    void jge_st_rel8(Disp<int8_t> disp, BranchHint hint=BRANCH_HINT_NONE);
    void jl_st_rel8(Disp<int8_t> disp, BranchHint hint=BRANCH_HINT_NONE);
    void jle_st_rel8(Disp<int8_t> disp, BranchHint hint=BRANCH_HINT_NONE);
    void jbe_st_rel8(Disp<int8_t> disp, BranchHint hint=BRANCH_HINT_NONE);
    void jnc_st_rel8(Disp<int8_t> disp, BranchHint hint=BRANCH_HINT_NONE);
    void jno_st_rel8(Disp<int8_t> disp, BranchHint hint=BRANCH_HINT_NONE);
    void jns_st_rel8(Disp<int8_t> disp, BranchHint hint=BRANCH_HINT_NONE);
    void jnz_st_rel8(Disp<int8_t> disp, BranchHint hint=BRANCH_HINT_NONE);
    void jo_st_rel8(Disp<int8_t> disp, BranchHint hint=BRANCH_HINT_NONE);
    void jpe_st_rel8(Disp<int8_t> disp, BranchHint hint=BRANCH_HINT_NONE);
    void jpo_st_rel8(Disp<int8_t> disp, BranchHint hint=BRANCH_HINT_NONE);
    void jrcxz_st_rel8(Disp<int8_t> disp, BranchHint hint=BRANCH_HINT_NONE);
    void js_st_rel8(Disp<int8_t> disp, BranchHint hint=BRANCH_HINT_NONE);
    void jz_st_rel8(Disp<int8_t> disp, BranchHint hint=BRANCH_HINT_NONE);
    void ja_nr_rel32(Disp<int32_t> disp, BranchHint hint=BRANCH_HINT_NONE);
    void jc_nr_rel32(Disp<int32_t> disp, BranchHint hint=BRANCH_HINT_NONE);
    void jg_nr_rel32(Disp<int32_t> disp, BranchHint hint=BRANCH_HINT_NONE);
    void jge_nr_rel32(Disp<int32_t> disp, BranchHint hint=BRANCH_HINT_NONE);
    void jl_nr_rel32(Disp<int32_t> disp, BranchHint hint=BRANCH_HINT_NONE);
    void jle_nr_rel32(Disp<int32_t> disp, BranchHint hint=BRANCH_HINT_NONE);
    void jbe_nr_rel32(Disp<int32_t> disp, BranchHint hint=BRANCH_HINT_NONE);
    void jnc_nr_rel32(Disp<int32_t> disp, BranchHint hint=BRANCH_HINT_NONE);
    void jno_nr_rel32(Disp<int32_t> disp, BranchHint hint=BRANCH_HINT_NONE);
    void jns_nr_rel32(Disp<int32_t> disp, BranchHint hint=BRANCH_HINT_NONE);
    void jnz_nr_rel32(Disp<int32_t> disp, BranchHint hint=BRANCH_HINT_NONE);
    void jo_nr_rel32(Disp<int32_t> disp, BranchHint hint=BRANCH_HINT_NONE);
    void jpe_nr_rel32(Disp<int32_t> disp, BranchHint hint=BRANCH_HINT_NONE);
    void jpo_nr_rel32(Disp<int32_t> disp, BranchHint hint=BRANCH_HINT_NONE);
    void jrcxz_nr_rel32(Disp<int32_t> disp, BranchHint hint=BRANCH_HINT_NONE);
    void js_nr_rel32(Disp<int32_t> disp, BranchHint hint=BRANCH_HINT_NONE);
    void jz_nr_rel32(Disp<int32_t> disp, BranchHint hint=BRANCH_HINT_NONE);

    // JMP
    void jmp_nr_rel8(int8_t disp);
    void jmp_nr_rel32(int32_t disp);
    void jmp_nr_rm64(ModrmSib const &modrmsib);

    // LEA
    void lea_reg_m(ModrmSib const &modrmsib);

    // LEAVE
    void leave();

    // MOV
    void mov_reg_reg(Register dest, Register src); // Provided because ordering of args
                                                   // can be confusing if mov_rm_reg is
                                                   // used to move one reg to another,
                                                   // and because the modrm byte can be
                                                   // computed using simpler code in this
                                                   // case.
    void mov_rm8_reg(ModrmSib const &modrmsib);
    void mov_rm32_reg(ModrmSib const &modrmsib);
    void mov_rm64_reg(ModrmSib const &modrmsib);
    void mov_reg_rm8(ModrmSib const &modrmsib);
    void mov_reg_rm32(ModrmSib const &modrmsib);
    void mov_reg_rm64(ModrmSib const &modrmsib);
    void mov_reg_imm32(Register reg, uint32_t imm);
    void mov_reg_imm64(Register reg, uint64_t imm);
    void mov_moffs64_rax(uint64_t addr);

    // MUL
    void mul_edx_eax_rm32(ModrmSib const &modrmsib);
    void mul_rdx_rax_rm64(ModrmSib const &modrmsib);

    // NOP
    void nop();

    // OR
    void or_rm32_reg(ModrmSib const &modrmsib);
    void or_rm64_reg(ModrmSib const &modrmsib);
    void or_reg_rm32(ModrmSib const &modrmsib);
    void or_reg_rm64(ModrmSib const &modrmsib);
    void or_rm32_imm8(ModrmSib const &modrmsib, uint8_t src);
    void or_rm64_imm8(ModrmSib const &modrmsib, uint8_t src);
    void or_rm32_imm32(ModrmSib const &modrmsib, uint32_t src);
    void or_rm64_imm32(ModrmSib const &modrmsib, uint32_t src);

    // POP
    void pop_rm64(ModrmSib const &modrmsib);
    void pop_reg64(Register reg);

    // PUSH
    void push_rm16(ModrmSib const &modrmsib);
    void push_rm64(ModrmSib const &modrmsib);
    void push_reg64(Register reg);
    void push_imm8(uint8_t imm);
    void push_imm32(uint32_t imm);

    // SUB
    void sub_rm32_reg(ModrmSib const &modrmsib);
    void sub_rm64_reg(ModrmSib const &modrmsib);
    void sub_reg_rm32(ModrmSib const &modrmsib);
    void sub_reg_rm64(ModrmSib const &modrmsib);
    void sub_rm32_imm8(ModrmSib const &modrmsib, uint8_t src);
    void sub_rm64_imm8(ModrmSib const &modrmsib, uint8_t src);
    void sub_rm32_imm32(ModrmSib const &modrmsib, uint32_t src);
    void sub_rm64_imm32(ModrmSib const &modrmsib, uint32_t src);

    // RET
    void ret();

    // OR
    void xor_rm32_reg(ModrmSib const &modrmsib);
    void xor_rm64_reg(ModrmSib const &modrmsib);
    void xor_reg_rm32(ModrmSib const &modrmsib);
    void xor_reg_rm64(ModrmSib const &modrmsib);
    void xor_rm32_imm8(ModrmSib const &modrmsib, uint8_t src);
    void xor_rm64_imm8(ModrmSib const &modrmsib, uint8_t src);
    void xor_rm32_imm32(ModrmSib const &modrmsib, uint32_t src);
    void xor_rm64_imm32(ModrmSib const &modrmsib, uint32_t src);

private:
    WriterT &w;
};

class VectorWriter {
public:
    static const std::size_t ROOM_AHEAD = 20;

    VectorWriter(std::size_t initial_size = 20);
    ~VectorWriter();

    void a(const uint8_t *buf, std::size_t length);
    void a(uint8_t byte);
    void a(VectorWriter const &vw);

    std::size_t size();

    void canonical_hex(std::string &o);
    void debug_print();

    typedef void (*voidf)(void);
    uint8_t *get_mem();
    voidf get_exec_func();
    uint64_t get_start_addr();
    void *get_start_ptr();

private:
    const std::size_t initial_size;

    uint8_t *mem;
    std::size_t length;
    std::size_t freebytes;
};

typedef Assembler<VectorWriter> VectorAssembler;

// Utility for converting pointers to uint64_t.
#define PTR(p) reinterpret_cast<uint64_t>(p)

}

#endif
