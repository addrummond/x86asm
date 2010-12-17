#include <vm.hh>
#include <myassert.hh>
#include <cctype>
#include <sstream>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <asm.hh>
#include <iostream>
#include <fstream>

using namespace Vm;

const Opcode Vm::FIRST_OP = OP_EXIT;

const unsigned Vm::MAX_REG_ID = 127;

static char const *op_names[] = {
    "EXIT",
    "INCRW",
    "DECRW",
    "LDI16",
    "LDI64",
    "JMP",
    "CALL",
    "RET",
    "CMP",
    "JE",
    "JG",
    "JL",
    "IADD",
    "IMUL",
    "IDIV",
    "MKVEC",
    "REVEC",
    "REFVEC",
    "SETVEC",
    "DEBUG_PRINTREG"
};

#define END OPR_NULL
static Operand const op_operand_specs[][4] = {
    { OPR_REGISTER, END },                          // EXIT

    { OPR_REGISTER, END },                          // INCRW
    { END },                                        // DECRW
    { OPR_REGISTER, OPR_IMM16, END },               // LDI16
    { OPR_IMM64, END },                             // LDI64

    { OPR_REGISTER, OPR_FLAGS, END },               // JMP 
    { OPR_REGISTER, END },                          // CALL
    { OPR_REGISTER, END },                          // RET
    { OPR_REGISTER, OPR_REGISTER, OPR_FLAGS, END }, // CMP
    { OPR_REGISTER, END },                          // JE
    { OPR_REGISTER, END },                          // JG
    { OPR_REGISTER, END },                          // JL

    { OPR_REGISTER, OPR_REGISTER, END },            // IADD
    { OPR_REGISTER, OPR_REGISTER, END },            // IMUL
    { OPR_REGISTER, OPR_REGISTER, END },            // IDIV

    { OPR_REGISTER, END },                          // MKVEC
    { OPR_REGISTER, OPR_REGISTER, END },            // REVEC
    { OPR_REGISTER, OPR_REGISTER, END },            // REFVEC
    { OPR_REGISTER, OPR_REGISTER, END },            // SETVEC

    { OPR_REGISTER, END },                          // DEBUG_PRINTREG
};
#undef END

const unsigned Vm::TAG_INT = 0;
const unsigned Vm::TAG_DOUBLE = 1;
const unsigned Vm::TAG_VECTOR = 2;

Operand const *Vm::op_operands(Opcode o)
{
    return op_operand_specs[o-FIRST_OP];
}

char const *Vm::op_name(Opcode o)
{
    return op_names[o-FIRST_OP];
}

char const *Vm::tag_name(unsigned tag)
{
    switch (tag) {
        case TAG_INT: return "int";
        case TAG_DOUBLE: return "double";
        case TAG_VECTOR: return "vector";
    }
}

Opcode Vm::op_code_by_name(std::string const &name)
{
    for (unsigned i = 0; i < sizeof(op_names)/sizeof(char const *); ++i) {
        if (name == op_names[i])
            return static_cast<Opcode>(i + FIRST_OP);
    }
    return OP_NULL;
}

uint32_t Vm::make_instruction(Opcode opcode)
{
    return opcode;
}

uint32_t Vm::make_rop_instruction(Opcode opcode, RegId reg1, RegId reg2, RegId reg3)
{
    return opcode        |
           (reg1 << 8)   |
           (reg2 << 16)  |
           (reg3 << 24);
}

uint32_t Vm::make_imm24_instruction(Opcode opcode, uint32_t immediate)
{
    assert(immediate < (1 << 16));
    return opcode         |
           immediate << 8;
}

// Used in 'parse_vm_asm'.
static bool finalizeInstruction(Opcode currentOpCode,
                                std::vector<uint64_t> const &operands,
                                std::vector<uint8_t> &instructions,
                                std::string &emsg)
{
    uint32_t base = currentOpCode;
    uint64_t extra;
    bool has_extra = false;

    Operand const *operand_spec;
    std::vector<uint64_t>::const_iterator operand;
    for (operand_spec = op_operands(currentOpCode),
         operand = operands.begin();
         *operand_spec && operand < operands.end();
         ++operand_spec, ++operand) {
                    
        if (*operand_spec == OPR_REGISTER) {
            if (*operand > MAX_REG_ID) {
                emsg = "Invalid register.";
                return false;
            }
            base |= *operand << ((operand - operands.begin() + 1) * 8);
        }
        else if (*operand_spec == OPR_IMM16) {
            if (*operand > (2 << 16) - 1) {
                emsg = "Too big for imm 16.";
                return false;
            }
            base |= *operand << ((operand - operands.begin() + 1) * 8);
        }
        else if (*operand_spec == OPR_IMM64) {
            break;
        }
        else assert(false);
    }
    
    // TODO: Currently only works for one imm operand.
    for (; *operand_spec != OPR_NULL && operand < operands.end(); ++operand_spec, ++operand) {
        if (*operand_spec != OPR_IMM64) {
            emsg = "Bad thing.";
            return false;
        }        
        extra = *operand;
    }
    
    instructions.reserve(instructions.size() + 12);
    instructions.insert(instructions.end(), reinterpret_cast<uint8_t *>(&base), reinterpret_cast<uint8_t *>(&base) + 4);
    if (has_extra)
        instructions.insert(instructions.end(), reinterpret_cast<uint8_t *>(&extra), reinterpret_cast<uint8_t *>(&extra) + 8);

    return true;
}

namespace {
enum ParseState {
    ST_INITIAL,
    ST_RANDS_FOR_OP,
};
}
bool Vm::parse_vm_asm(std::string const &input, std::vector<uint8_t> &instructions, std::string &emsg)
{
    typedef std::string::const_iterator sit;

    sit i = input.begin();
    ParseState s = ST_INITIAL;
    std::string currentOp;
    Opcode currentOpCode;
    Operand const *currentOperand;
    bool currentNumberIsSigned = true;
    bool currentNumberIsHex = false;
    std::string currentNumber;
    std::vector<uint64_t> operands;

    int last = 0;
    for (; i < input.end() || !(last++); ++i) {
        char c = last ? ' ' : *i;

        if (s == ST_INITIAL) {
            if (std::isalpha(c) || c == '_' || (currentOp.size() > 0 && std::isdigit(c))) {
                currentOp.push_back(c);
            }
            else if (std::isspace(c)) {
                if (currentOp.size() == 0)
                    continue;
                currentOpCode = op_code_by_name(currentOp);
                if (currentOpCode == OP_NULL) {
                    emsg = "Unrecognized instruction " + currentOp;
                    return false;
                }
                s = ST_RANDS_FOR_OP;
                currentOperand = op_operands(currentOpCode);
                if (*currentOperand == OPR_NULL) {
                    if (! finalizeInstruction(currentOpCode, operands, instructions, emsg))
                        return false;
                    s = ST_INITIAL;
                    currentOp = "";
                    operands.clear();
                }
            }
        }
        else if (s == ST_RANDS_FOR_OP) {
            assert(*currentOperand != OPR_NULL);
            if (*currentOperand == OPR_IMM16 || *currentOperand == OPR_IMM64 || *currentOperand == OPR_REGISTER || *currentOperand == OPR_FLAGS) {
                if (std::isdigit(c) || c == '-')
                    currentNumber.push_back(c);
                else if (c == 'U')
                    currentNumberIsSigned = false;
                else if (c == 'H')
                    currentNumberIsHex = true;
                else if (std::isspace(c)) {
                    ++currentOperand;
                    uint64_t r;
                    if (currentNumberIsSigned)
                        r = static_cast<uint64_t>(std::strtoll(currentNumber.c_str(), NULL, currentNumberIsHex ? 16 : 10));
                    else
                        r = static_cast<uint64_t>(std::strtoull(currentNumber.c_str(), NULL, currentNumberIsHex ? 16 : 10));
                    if (errno != 0) { // Not sure why using 'std::errno' doesn't work here.
                        emsg = "Bad number: " + currentNumber;
                        return false;
                    }
                    operands.push_back(r);
                    currentNumber = "";
                    currentNumberIsSigned = true;
                    currentNumberIsHex = false;

                    if (*currentOperand == OPR_NULL) {
                        if (! finalizeInstruction(currentOpCode, operands, instructions, emsg))
                            return false;
                        s = ST_INITIAL;
                        currentOp = "";
                        operands.clear();
                    }
                }
                else {
                    emsg = "Unexpected character.";
                    return false;
                }
            }
            else assert(false);
        }
    }

    if (s != ST_INITIAL) {
        emsg = "Bad final state.";
        return false;
    }
    return true;
}

// Addresses of some functions we'll want to call.
static const uint64_t malloc_ptr = reinterpret_cast<uint64_t>(std::malloc);

static int8_t RegId_to_disp(RegId id)
{
    assert(id <= 127 && id > 0);
    return id * -8;
}

template <class WriterT>
static void move_x86reg_to_vmreg_ptr(Asm::Assembler<WriterT> &a, Asm::Register x86reg, RegId vmreg)
{
    using namespace Asm;
    a.mov_rm64_reg(mem_2op_short(x86reg, RBP, NOT_A_REGISTER/*index*/, SCALE_1, RegId_to_disp(vmreg)));
}

template <class WriterT>
static void move_vmreg_ptr_to_x86reg(Asm::Assembler<WriterT> &a, RegId vmreg, Asm::Register x86reg)
{
    using namespace Asm;
    a.mov_reg_rm64(mem_2op_short(x86reg, RBP, NOT_A_REGISTER/*index*/, SCALE_1, RegId_to_disp(vmreg)));
}

// Emit code to allocate tagged memory.
// Leaves address (untagged) in RAX.
template <class WriterT>
void Vm::emit_malloc_constsize(Asm::Assembler<WriterT> &a, std::size_t size, RegId ptr_dest, unsigned tag)
{
    using namespace Asm;

    assert(tag < 4);

    a.mov_reg_imm64(RDI, static_cast<uint64_t>(size));
    a.mov_reg_imm64(RCX, static_cast<uint64_t>(malloc_ptr));
    a.mov_reg_imm64(RAX, 0);
    a.call_rm64(reg_1op(RCX));

    // TODO: Handle out of memory case.

    // Add the tag (pointer to allocated memory is now in RAX).
    a.mov_reg_imm64(RCX, static_cast<uint64_t>(tag));
    a.or_reg_rm64(reg_2op(RCX, RAX));

    move_x86reg_to_vmreg_ptr(a, RCX, ptr_dest);
}

template <class WriterT>
static void emit_incrw(Asm::Assembler<WriterT> &a, RegId num_regs)
{
    using namespace Asm;
    a.call_rel32(0);
    a.push_rm64(reg_1op(RBP));
    a.mov_rm64_reg(reg_2op(RSP, RBP));
    a.sub_rm64_imm8(reg_1op(RBP), num_regs * 8);
}

template <class WriterT>
static void emit_ldi(Asm::Assembler<WriterT> &a, RegId ptr_dest, uint64_t val)
{
    using namespace Asm;
    emit_malloc_constsize(a, 8, ptr_dest, TAG_INT); // Leaves untagged address in RAX.
    a.mov_reg_imm64(RCX, val);
    a.mov_rm64_reg(mem_2op(RCX, RAX));
}

template <class WriterT>
static void emit_add(Asm::Assembler<WriterT> &a, RegId r_dest, RegId r_src)
{
    using namespace Asm;
    a.mov_reg_rm64(mem_2op_short(RDX, RBP, NOT_A_REGISTER/*index*/, SCALE_1, RegId_to_disp(r_dest)));
    a.mov_reg_rm64(mem_2op_short(RCX, RBP, NOT_A_REGISTER/*index*/, SCALE_1, RegId_to_disp(r_src)));
    a.mov_reg_rm64(mem_2op(RAX, RDX));
    a.add_reg_rm64(mem_2op(RAX, RCX));
    a.mov_rm64_reg(mem_2op(RAX, RDX));
}

template <class WriterT>
static void emit_exit(Asm::Assembler<WriterT> &a, uint64_t const &bpfml, uint64_t const &spfml, RegId retreg)
{
    using namespace Asm;

    a.mov_reg_rm64(mem_2op_short(RAX, RBP, NOT_A_REGISTER/*index*/, SCALE_1, RegId_to_disp(retreg)));

    a.mov_reg_imm64(RCX, PTR(&bpfml));
    a.mov_reg_rm64(mem_2op(RBP, RCX));
    a.mov_reg_imm64(RCX, PTR(&spfml));
    a.mov_reg_rm64(mem_2op(RSP, RCX));

    a.leave(); // Now that we've reset ESP/EBP, calling leave/ret
    a.ret();   // will return from main_loop_.
}

static void print_vm_reg(RegId rid, uint64_t tagged_ptr)
{
    uint64_t tag = tagged_ptr & 0x0000000000000003;
    std::printf("- REGISTER %i\n- TAG      %lli (%s)\n", (int)rid, tag, tag_name(tag));
    if (tag == TAG_INT) {
        std::printf("- VALUE:   %lli\n\n", *((long long *)(tagged_ptr)));
    }
    else assert(false);
}

template <class WriterT>
static void emit_debug_printreg(Asm::Assembler<WriterT> &a, RegId r)
{
    using namespace Asm;
    a.mov_reg_imm32(EDI, static_cast<uint32_t>(r));
    a.mov_reg_rm64(mem_2op_short(RSI, RBP, NOT_A_REGISTER/*index*/, SCALE_1, RegId_to_disp(r)));
    a.mov_reg_imm64(RCX, PTR(print_vm_reg));
    a.call_rm64(reg_1op(RCX));
}

template <class WriterT>
static void debug_print_x86reg64(Asm::Assembler<WriterT> &a, Asm::Register r, const char *preamble)
{
    using namespace Asm;
    const char *format = "%s%llx\n";
    a.push_reg64(RCX);
    a.push_reg64(RBX);
    a.push_reg64(r);
    a.mov_reg_imm64(RDI, PTR(format));
    a.mov_reg_imm64(RSI, PTR(preamble));
    a.mov_reg_reg(RBX, RSP);
    a.mov_reg_rm64(mem_2op_short(RDX, RBX));
    a.mov_reg_imm64(RCX, PTR(std::printf));
    a.mov_reg_imm32(EAX, 0);
    a.call_rm64(reg_1op(RCX));
    a.pop_reg64(r);
    a.pop_reg64(RBX);
    a.pop_reg64(RCX);
}

static const Asm::Register gp_regs[] = {
    Asm::RAX, Asm::RCX, Asm::RDX, Asm::RBX, Asm::RSP, Asm::RBP, Asm::RSI, Asm::RDI,
    Asm::R8D, Asm::R9D, Asm::R10D, Asm::R11D, Asm::R12D, Asm::R13D, Asm::R14D, Asm::R15D
};
template <class WriterT>
static void save_all_regs(Asm::Assembler<WriterT> &a, uint64_t *buffer)
{
    using namespace Asm;

    a.push_reg64(RAX);
    a.mov_reg_imm64(RAX, PTR(buffer));
    unsigned i = 1;
    for (; i < sizeof(gp_regs) / sizeof(Register); ++i) {
        a.mov_rm64_reg(mem_2op_short(gp_regs[i], RAX, NOT_A_REGISTER, SCALE_1, i*8));
    }
    a.pop_reg64(RAX);
    a.push_reg64(RCX);
    a.mov_reg_imm64(RCX, PTR(buffer));
    a.mov_rm64_reg(mem_2op_short(RAX, RCX));
    a.pop_reg64(RCX);
}
template <class WriterT>
static void restore_all_regs(Asm::Assembler<WriterT> &a, uint64_t *buffer)
{
    using namespace Asm;

    a.mov_reg_imm64(RAX, PTR(buffer));
    unsigned i = 1;
    for (; i < sizeof(gp_regs) / sizeof(Register); ++i) {
        a.mov_reg_rm64(mem_2op_short(gp_regs[i], RAX, NOT_A_REGISTER, SCALE_1, i*8));
    }
    a.push_reg64(RCX);
    a.mov_reg_imm64(RCX, PTR(buffer));
    a.mov_reg_rm64(mem_2op_short(RAX, RCX));
    a.pop_reg64(RCX);
}

template <bool DEBUG_MODE>
uint64_t main_loop_(std::vector<uint8_t> &instructions, std::size_t start, const std::size_t BLOB_SIZE)
{
    using namespace Asm;

    VectorWriter alaw;
    VectorAssembler alaa(alaw);

    // Store the current base pointer and stack pointer.
    uint64_t base_pointer_for_main_loop;
    uint64_t stack_pointer_for_main_loop;
    
    uint64_t address_of_main_label;

    uint64_t saved_registers[16];
    bool registers_are_saved;

    uint64_t addr;
    int32_t rel;

    typedef std::vector<uint8_t>::iterator It;
    It i;

    // <<<<< END OF VAR DEFINITIONS <<<<<

    // This could just be inline ASM, but since we already have an assembler,
    // we may as well do it without making use of compiler-specific extensions.
    VectorWriter bpw;
    VectorAssembler bpa(bpw);
    bpa.mov_reg_imm64(RCX, PTR(&base_pointer_for_main_loop));
    bpa.mov_rm64_reg(mem_2op(RBP, RCX));
    bpa.mov_reg_imm64(RCX, PTR(&stack_pointer_for_main_loop));
    bpa.mov_rm64_reg(mem_2op(RSP, RCX));
    bpa.ret();
    bpw.get_exec_func()();

    // TODO: Code duplication with test8 in asm_tests.cc
    // Get the address of the next instruction by creating a function,
    // calling it, and storing the return address that gets pushed onto
    // the stack.
    alaa.push_reg64(RBP); // Function preamble.
    alaa.mov_reg_reg(RBP, RSP);

    alaa.mov_reg_imm64(RCX, PTR(&address_of_main_label));
    alaa.mov_reg_rm64(mem_2op(RDX, RBP, NOT_A_REGISTER, SCALE_1, 8));
    alaa.mov_rm64_reg(mem_2op(RDX, RCX));

    alaa.leave();
    alaa.ret();
    alaw.get_exec_func()();

    // This is the main loop. Bytecode is read in in chunks of a size determined by
    // BLOB_SIZE. Each chunk is compiled, and ASM code is appended at the end to:
    //
    //     1) Save all registers. (TODO: Currently FP not saved).
    //     2) Jump back to main_label.
    //
    // The jump is a relative jump, so it should be fairly fast.
    //
    // (Yes yes, this is horrible, just a very early prototype. The point is just
    // that we really are doing JIT compilation here rather than AOT, although this
    // is somewhat moot given that the compiler isn't handling jumps yet!)
main_label:

    if (start >= instructions.size())
        return 0;

    VectorWriter *w = new VectorWriter;
    VectorAssembler *a = new VectorAssembler(*w);

    if (registers_are_saved) {
        restore_all_regs(*a, saved_registers);
    }

    for (i = instructions.begin() + start;
         i != instructions.end() && i - instructions.begin() - start < BLOB_SIZE*4;
         i += 4) {
        assert(i + 3 < instructions.end());

        if (*i == OP_NULL)
            assert(false);
        else if (*i == OP_EXIT) {
            emit_exit(*a, base_pointer_for_main_loop, stack_pointer_for_main_loop, i[1]);
        }
        else if (*i == OP_INCRW) {
            emit_incrw(*a, i[1]);
        }
        else if (*i == OP_LDI16) {
            emit_ldi(*a, i[1], i[2] + (i[3] << 8));
        }
        else if (*i == OP_IADD) {
            emit_add(*a, i[1], i[2]);
        }
        else if (*i == OP_DEBUG_PRINTREG) {
            emit_debug_printreg(*a, i[1]);
        }
        else assert(false);

        // Makes it easier to see which ASM is for which VM instruction when debugging.
        if (DEBUG_MODE) a->nop();
    }

    // Save all registers and set 'registers_are_saved' to true.
    save_all_regs(*a, saved_registers);
    a->mov_reg_imm64(RCX, PTR(&registers_are_saved));
    a->mov_reg_imm64(RAX, 1);
    if (sizeof(bool) == 1)
        a->mov_rm8_reg(mem_2op(AL, RCX));
    else if (sizeof(bool) == 4)
        a->mov_rm32_reg(mem_2op(EAX, RCX));
    else if (sizeof(bool) == 8)
        a->mov_rm64_reg(mem_2op(RAX, RCX));
    else assert(false);

    // Do a rel32 jump to main_label.
    addr = w->get_start_addr() + w->size();
    rel = (int32_t)(address_of_main_label - addr);
    a->jmp_nr_rel32(mkdisp<int32_t>(rel, DISP_SUB_ISIZE));

    start += BLOB_SIZE * 4;

    w->get_exec_func()();

    delete w;
    delete a;
}
uint64_t Vm::main_loop(std::vector<uint8_t> &instructions, std::size_t start, const std::size_t BLOB_SIZE)
{ main_loop_<false>(instructions, start, BLOB_SIZE); }
uint64_t Vm::main_loop_debug(std::vector<uint8_t> &instructions, std::size_t start, const std::size_t BLOB_SIZE)
{ main_loop_<true>(instructions, start, BLOB_SIZE); }
