#ifndef ASM_HH
#define ASM_HH

#include <stdint.h>
#include <cstddef>
#include <cstdlib>
#include <vector>
#include <map>
#include <string>

namespace Asm {

enum Register {
    EAX=0, ECX, EDX, EBX, ESP, EBP, ESI, EDI,
    RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI,
    R8, R9, R10, R11, R12, R13, R14, R15,
    MM0, MM1, MM2, MM3, MM4, MM5, MM6, MM7,
    XMM0, XMM1, XMM2, XMM3, XMM4, XMM5, XMM6, XMM7,
    XMM8, XMM9, XMM10, XMM11, XMM12, XMM13, XMM14, XMM15,

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
    SIZE_128=16
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
    // Return true if all register operands are GP registers.
    bool gp_registers_only() const;
    // Return true if all register operands are MM registers.
    bool mm_registers_only() const;
    // Return true iff all register operands are XMM registers.
    bool xmm_registers_only() const;
    // Returns true if there is no additional reg operand.
    bool has_reg_operand() const;
    // Checks that all register operands in a ModRM byte have a given (byte) size.
    bool all_register_operands_have_size(Size size) const;
    // True if it specifies a memory location only with no additional register operand.
    bool simple_memory() const;

    bool rip;
    Register rm_reg;
    DispSize disp_size;
    int32_t disp;
    Register reg;
    Register base_reg;
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
ModrmSib rip(int32_t disp);
ModrmSib rip_1op(Register reg, int32_t disp);

bool reg_is_forbidden_in_rm(Register reg);

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

struct RawModrmSib {
    uint8_t modrm;
    uint8_t sib; // Set to 0 if none, since 0 is not a valid SIB.
    bool has_disp;
};
RawModrmSib raw_modrmsib(ModrmSib const &modrmsib);

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

    Disp(IntT i_);
    Disp(IntT i_, DispOp op_);

    IntT get(std::size_t isize) const;

private:
    IntT i;
    DispOp op;
};
template <class IntT>
Disp<IntT> mkdisp(IntT i, DispOp op = DISP_NO_OP);

template <class WriterT, class IntT>
class DispSetter {
public:
    DispSetter(WriterT &w_, std::size_t isize_, std::size_t disp_position_);

    void set(Disp<IntT> const &d);

private:
    WriterT &w;
    std::size_t isize;
    std::size_t disp_position;
};

#ifdef DEBUG
extern bool DEBUG_STEP_BY_DEFAULT;
#endif
template <class WriterT>
class Assembler {
public:
    Assembler(WriterT &writer) : w(writer)
#ifdef DEBUG
    ,debug_stepping(DEBUG_STEP_BY_DEFAULT)
    ,last_instruction_offset(0)                               
#endif
   { }

    typedef DispSetter<WriterT, int8_t> StDispSetter;
    typedef DispSetter<WriterT, int32_t> NrDispSetter;

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
    NrDispSetter call_rel32(Disp<int32_t> const &disp);
    void call_rm64(ModrmSib modrmsib);

    // CMP
    void cmp_rm32_imm8(ModrmSib const &modrmsib, uint8_t imm);
    void cmp_rm64_imm8(ModrmSib const &modrmsib, uint8_t imm);
    void cmp_rm32_imm32(ModrmSib const &modrmsib, uint32_t imm);
    void cmp_rm64_imm32(ModrmSib const &modrmsib, uint32_t imm);
    void cmp_al_imm8(uint8_t imm);
    void cmp_eax_imm32(uint32_t imm);
    void cmp_rax_imm32(uint32_t imm); // This is also a special case of cmp_rm64_imm32.
    void cmp_rm32_reg(ModrmSib const &modrmsib);
    void cmp_rm64_reg(ModrmSib const &modrmsib);

    // DEC
    void dec_rm32(ModrmSib const &modrmsib);
    void dec_rm64(ModrmSib const &modrmsib);
    // Utils:
    void dec_reg32(Register reg);
    void dec_reg64(Register reg);

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
    void inc_reg32(Register reg);
    void inc_reg64(Register reg);

    // Jcc
    // See http://unixwiz.net/techtips/x86-jumps.html
    //
    // JE,JZ             JZ  *
    // JNE,JNZ           JNZ *
    // JB,JNAE,JC        JC  *
    // JNB,JAE,JNC       JNC *
    // JBE,JNA           JBE *
    // JA,JNBE           JA  *
    // JL,JNGE           JL  *
    // JGE,JNL           JGE *
    // JLE,JNG           JLE
    // JG,JNLE           JG
    // JP,JPE            JPE
    // JNP,JPO           JPO
    // JCXZ,JECXZ,JRCXZ  JRCXZ
    StDispSetter ja_st_rel8(Disp<int8_t> const &disp, BranchHint hint=BRANCH_HINT_NONE);
    StDispSetter jc_st_rel8(Disp<int8_t> const &disp, BranchHint hint=BRANCH_HINT_NONE);
    StDispSetter jg_st_rel8(Disp<int8_t> const &disp, BranchHint hint=BRANCH_HINT_NONE);
    StDispSetter jge_st_rel8(Disp<int8_t> const &disp, BranchHint hint=BRANCH_HINT_NONE);
    StDispSetter jl_st_rel8(Disp<int8_t> const &disp, BranchHint hint=BRANCH_HINT_NONE);
    StDispSetter jle_st_rel8(Disp<int8_t> const &disp, BranchHint hint=BRANCH_HINT_NONE);
    StDispSetter jbe_st_rel8(Disp<int8_t> const &disp, BranchHint hint=BRANCH_HINT_NONE);
    StDispSetter jnc_st_rel8(Disp<int8_t> const &disp, BranchHint hint=BRANCH_HINT_NONE);
    StDispSetter jno_st_rel8(Disp<int8_t> const &disp, BranchHint hint=BRANCH_HINT_NONE);
    StDispSetter jns_st_rel8(Disp<int8_t> const &disp, BranchHint hint=BRANCH_HINT_NONE);
    StDispSetter jnz_st_rel8(Disp<int8_t> const &disp, BranchHint hint=BRANCH_HINT_NONE);
    StDispSetter jo_st_rel8(Disp<int8_t> const &disp, BranchHint hint=BRANCH_HINT_NONE);
    StDispSetter jpe_st_rel8(Disp<int8_t> const &disp, BranchHint hint=BRANCH_HINT_NONE);
    StDispSetter jpo_st_rel8(Disp<int8_t> const &disp, BranchHint hint=BRANCH_HINT_NONE);
    StDispSetter jrcxz_st_rel8(Disp<int8_t> const &disp, BranchHint hint=BRANCH_HINT_NONE);
    StDispSetter js_st_rel8(Disp<int8_t> const &disp, BranchHint hint=BRANCH_HINT_NONE);
    StDispSetter jz_st_rel8(Disp<int8_t> const &disp, BranchHint hint=BRANCH_HINT_NONE);
    NrDispSetter ja_nr_rel32(Disp<int32_t> const &disp, BranchHint hint=BRANCH_HINT_NONE);
    NrDispSetter jc_nr_rel32(Disp<int32_t> const &disp, BranchHint hint=BRANCH_HINT_NONE);
    NrDispSetter jg_nr_rel32(Disp<int32_t> const &disp, BranchHint hint=BRANCH_HINT_NONE);
    NrDispSetter jge_nr_rel32(Disp<int32_t> const &disp, BranchHint hint=BRANCH_HINT_NONE);
    NrDispSetter jl_nr_rel32(Disp<int32_t> const &disp, BranchHint hint=BRANCH_HINT_NONE);
    NrDispSetter jle_nr_rel32(Disp<int32_t> const &disp, BranchHint hint=BRANCH_HINT_NONE);
    NrDispSetter jbe_nr_rel32(Disp<int32_t> const &disp, BranchHint hint=BRANCH_HINT_NONE);
    NrDispSetter jnc_nr_rel32(Disp<int32_t> const &disp, BranchHint hint=BRANCH_HINT_NONE);
    NrDispSetter jno_nr_rel32(Disp<int32_t> const &disp, BranchHint hint=BRANCH_HINT_NONE);
    NrDispSetter jns_nr_rel32(Disp<int32_t> const &disp, BranchHint hint=BRANCH_HINT_NONE);
    NrDispSetter jnz_nr_rel32(Disp<int32_t> const &disp, BranchHint hint=BRANCH_HINT_NONE);
    NrDispSetter jo_nr_rel32(Disp<int32_t> const &disp, BranchHint hint=BRANCH_HINT_NONE);
    NrDispSetter jpe_nr_rel32(Disp<int32_t> const &disp, BranchHint hint=BRANCH_HINT_NONE);
    NrDispSetter jpo_nr_rel32(Disp<int32_t> const &disp, BranchHint hint=BRANCH_HINT_NONE);
    NrDispSetter js_nr_rel32(Disp<int32_t> const &disp, BranchHint hint=BRANCH_HINT_NONE);
    NrDispSetter jz_nr_rel32(Disp<int32_t> const &disp, BranchHint hint=BRANCH_HINT_NONE);
    // Inline definitions for synonyms.
    StDispSetter je_st_rel8(Disp<int8_t> const & disp, BranchHint hint=BRANCH_HINT_NONE) { jz_st_rel8(disp, hint); }
    StDispSetter jne_st_rel8(Disp<int8_t> const &disp, BranchHint hint=BRANCH_HINT_NONE) { jnz_st_rel8(disp, hint); }
    StDispSetter jb_st_rel8(Disp<int8_t> const &disp, BranchHint hint=BRANCH_HINT_NONE) { jc_st_rel8(disp, hint); }
    StDispSetter jnae_st_rel8(Disp<int8_t> const &disp, BranchHint hint=BRANCH_HINT_NONE) { jc_st_rel8(disp, hint); }
    StDispSetter jnb_st_rel8(Disp<int8_t> const &disp, BranchHint hint=BRANCH_HINT_NONE) { jnc_st_rel8(disp, hint); }
    StDispSetter jae_st_rel8(Disp<int8_t> const &disp, BranchHint hint=BRANCH_HINT_NONE) { jnc_st_rel8(disp, hint); }
    StDispSetter jna_st_rel8(Disp<int8_t> const &disp, BranchHint hint=BRANCH_HINT_NONE) { jbe_st_rel8(disp, hint); }
    StDispSetter jnbe_st_rel8(Disp<int8_t> const &disp, BranchHint hint=BRANCH_HINT_NONE) { ja_st_rel8(disp, hint); }
    StDispSetter jnge_st_rel8(Disp<int8_t> const &disp, BranchHint hint=BRANCH_HINT_NONE) { jl_st_rel8(disp, hint); }
    StDispSetter jnl_st_rel8(Disp<int8_t> const &disp, BranchHint hint=BRANCH_HINT_NONE) { jge_st_rel8(disp, hint); }
    StDispSetter jng_st_rel8(Disp<int8_t> const &disp, BranchHint hint=BRANCH_HINT_NONE) { jle_st_rel8(disp, hint); }
    StDispSetter jnle_st_rel8(Disp<int8_t> const &disp, BranchHint hint=BRANCH_HINT_NONE) { jg_st_rel8(disp, hint); }
    StDispSetter jp_st_rel8(Disp<int8_t> const &disp, BranchHint hint=BRANCH_HINT_NONE) { jpe_st_rel8(disp, hint); }
    StDispSetter jnp_st_rel8(Disp<int8_t> const &disp, BranchHint hint=BRANCH_HINT_NONE) { jpo_st_rel8(disp, hint); }
    StDispSetter jcxz_st_rel8(Disp<int8_t> const &disp, BranchHint hint=BRANCH_HINT_NONE) { jrcxz_st_rel8(disp, hint); }
    StDispSetter jecxz_st_rel8(Disp<int8_t> const &disp, BranchHint hint=BRANCH_HINT_NONE) { jrcxz_st_rel8(disp, hint); }
    NrDispSetter je_nr_rel32(Disp<int32_t> const &disp, BranchHint hint=BRANCH_HINT_NONE) { jz_nr_rel32(disp, hint); }
    NrDispSetter jne_nr_rel32(Disp<int32_t> const &disp, BranchHint hint=BRANCH_HINT_NONE) { jnz_nr_rel32(disp, hint); }
    NrDispSetter jb_nr_rel32(Disp<int32_t> const &disp, BranchHint hint=BRANCH_HINT_NONE) { jc_nr_rel32(disp, hint); }
    NrDispSetter jnae_nr_rel32(Disp<int32_t> const &disp, BranchHint hint=BRANCH_HINT_NONE) { jc_nr_rel32(disp, hint); }
    NrDispSetter jnb_nr_rel32(Disp<int32_t> const &disp, BranchHint hint=BRANCH_HINT_NONE) { jnc_nr_rel32(disp, hint); }
    NrDispSetter jae_nr_rel32(Disp<int32_t> const &disp, BranchHint hint=BRANCH_HINT_NONE) { jnc_nr_rel32(disp, hint); }
    NrDispSetter jna_nr_rel32(Disp<int32_t> const &disp, BranchHint hint=BRANCH_HINT_NONE) { jbe_nr_rel32(disp, hint); }
    NrDispSetter jnbe_nr_rel32(Disp<int32_t> const &disp, BranchHint hint=BRANCH_HINT_NONE) { ja_nr_rel32(disp, hint); }
    NrDispSetter jnge_nr_rel32(Disp<int32_t> const &disp, BranchHint hint=BRANCH_HINT_NONE) { jl_nr_rel32(disp, hint); }
    NrDispSetter jnl_nr_rel32(Disp<int32_t> const &disp, BranchHint hint=BRANCH_HINT_NONE) { jge_nr_rel32(disp, hint); }
    NrDispSetter jng_nr_rel32(Disp<int32_t> const &disp, BranchHint hint=BRANCH_HINT_NONE) { jle_nr_rel32(disp, hint); }
    NrDispSetter jnle_nr_rel32(Disp<int32_t> const &disp, BranchHint hint=BRANCH_HINT_NONE) { jg_nr_rel32(disp, hint); }
    NrDispSetter jp_nr_rel32(Disp<int32_t> const &disp, BranchHint hint=BRANCH_HINT_NONE) { jpe_nr_rel32(disp, hint); }
    NrDispSetter jnp_nr_rel32(Disp<int32_t> const &disp, BranchHint hint=BRANCH_HINT_NONE) { jpo_nr_rel32(disp, hint); }

    // INT
    void int3();
    void int_imm8(uint8_t imm);

    // JMP (these have branch hints just to give the same method signature as other JMPs).
    StDispSetter jmp_nr_rel8(Disp<int8_t> const &disp, BranchHint hint=BRANCH_HINT_NONE);
    NrDispSetter jmp_nr_rel32(Disp<int32_t> const &disp, BranchHint hint=BRANCH_HINT_NONE);
    void jmp_nr_rm64(ModrmSib const &modrmsib, BranchHint hint=BRANCH_HINT_NONE);

    // LEA
    void lea_reg_m(ModrmSib const &modrmsib);

    // LEAVE
    void leave();

    // MOV
    void mov_rm8_reg(ModrmSib const &modrmsib);
    void mov_rm32_reg(ModrmSib const &modrmsib);
    void mov_rm64_reg(ModrmSib const &modrmsib);
    void mov_reg_rm8(ModrmSib const &modrmsib);
    void mov_reg_rm32(ModrmSib const &modrmsib);
    void mov_reg_rm64(ModrmSib const &modrmsib);
    void mov_reg_imm32(Register reg, uint32_t imm);
    void mov_reg_imm64(Register reg, uint64_t imm);
    void mov_moffs64_rax(uint64_t addr);
    void mov_reg_reg8(Register dest, Register src) { mov_reg_rm8(reg_2op(dest, src)); }
    void mov_reg_reg32(Register dest, Register src) { mov_reg_rm32(reg_2op(dest, src)); }
    void mov_reg_reg64(Register dest, Register src) { mov_reg_rm64(reg_2op(dest, src)); }

    // SSE(2) MOV* intructions.
    void movdqa_mm_mmm128(ModrmSib const &modrmsib);
    void movdqa_mmm128_mm(ModrmSib const &modrmsib);
    void movdqu_mm_mmm128(ModrmSib const &modrmsib);
    void movdqu_mmm128_mm(ModrmSib const &modrmsib);
    void movq_mm_mmm64(ModrmSib const &modrmsib);
    void movq_mmm64_mm(ModrmSib const &modrmsib);

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

    // POPF
    void popf();

    // PUSH
    void push_rm16(ModrmSib const &modrmsib);
    void push_rm64(ModrmSib const &modrmsib);
    void push_reg64(Register reg);
    void push_imm8(uint8_t imm);
    void push_imm32(uint32_t imm);

    // PUSHF
    void pushf();

    // SSE2 PXOR
    void pxor_mm_mmm64(ModrmSib const &modrmsib);
    void pxor_mm_mmm128(ModrmSib const &modrmsib);

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

#ifdef DEBUG
    void start_debug_stepping() { debug_stepping = true; }
    void stop_debug_stepping() { debug_stepping = false; }
    bool debug_stepping_is_on() const { return debug_stepping; }
    void emit_save_all_regs();
    void emit_restore_all_regs();
    void emit_debug_print(char const *str);
    void emit_step_point();

    void store_last_instruction_offset() { last_instruction_offset = w.size(); }
    std::size_t get_last_instruction_offset() { return last_instruction_offset; }
#endif

private:
    WriterT &w;

#ifdef DEBUG
    bool debug_stepping;
    std::vector<std::string> listing;
    std::size_t last_instruction_offset;
#endif
};

class VectorWriter {
public:
    static const std::size_t DEFAULT_INITIAL_SIZE = 20;
    static const std::size_t ROOM_AHEAD = 20;

    VectorWriter(std::size_t initial_size = DEFAULT_INITIAL_SIZE);
    VectorWriter(VectorWriter &vw);
    ~VectorWriter();

    void a(const uint8_t *buf, std::size_t length);
    void a(uint8_t byte);
    void a(VectorWriter const &vw);

    template <class IntT>
    void set_at(std::size_t index, IntT value);

    std::size_t size() const;

    void canonical_hex(std::string &o);
    void debug_print(std::size_t offset=0, std::size_t highlight_start = 0, std::size_t highlight_end = 0);

    typedef void (*voidf)(void);
    uint8_t *get_mem(int64_t offset=0);
    voidf get_exec_func(int64_t offset=0);
    uint64_t get_start_addr(int64_t offset=0);
    void *get_start_ptr(int64_t offset=0);

    void clear();

private:
    const std::size_t initial_size;
    std::size_t freebytes;
    std::size_t length;
    uint8_t *mem;
};

typedef Assembler<VectorWriter> VectorAssembler;

class CountingVectorWriter : public VectorWriter { // (originally had this templated, but caused headaches)
public:
    CountingVectorWriter(std::size_t &current_size_, std::size_t initial_size = DEFAULT_INITIAL_SIZE);

    void a(const uint8_t *buf, std::size_t length);
    void a(uint8_t byte);
    void a(CountingVectorWriter const &vw);

private:
    std::size_t &current_size;
};

typedef Assembler<CountingVectorWriter> CountingVectorAssembler;

// Utility for converting pointers to uint64_t.
#define PTR(p) reinterpret_cast<uint64_t>(p)

}

#endif
