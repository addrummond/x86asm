#include <vm.hh>
#include <myassert.hh>
#include <mem.hh>
#include <cctype>
#include <sstream>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <iostream>
#include <util.hh>
#ifdef DEBUG
#include <fstream>
#endif
#include <algorithm>

//
// Register scheme.
//
// * GP registers are volatile scratch registers.
// * R10-R15 hold the first 8 registers.
//

using namespace Vm;

// TODO: Figure out why using R11D and R12D causes problems.
// When debugging, we want to check that register saving is working properly. Hence,
// we use registers that need to be saved before using those that don't.
#ifdef DEBUG
const Asm::Register vm_regs_x86_regs[] = { Asm::RDI, Asm::RSI, Asm::R13D, Asm::R14D, Asm::R15D, Asm::RBX  };
const bool vm_regs_x86_regs_to_save[] =  { true,     true,     false,     false,     false,     true };
#else
//const Asm::Register vm_regs_x86_regs[] = { /*Asm::R11D, Asm::R12D,*/ Asm::R13D, Asm::R14D, Asm::R15D, Asm::RBX, Asm::RDI, Asm::RSI };
//const bool vm_regs_x86_regs_to_save[] =  { /*false,     false,*/     false,     false,     false,     true,     true,     true };
#endif
const int NUM_VM_REGS_IN_X86_REGS = sizeof(vm_regs_x86_regs)/sizeof(Asm::Register);

static Asm::Register registers_to_save_before_c_funcall[] = { Asm::RBX };

const Opcode Vm::FIRST_OP = OP_EXIT;

// We can have 127 on the machine stack and some number in registers.
const unsigned Vm::MAX_REG_ID = 127 + 4;
const unsigned MAX_VM_REGS = MAX_REG_ID-1;

static char const *op_names[] = {
    "EXIT",
    "INCRW",
    "DECRW",
    "LDI16",
    "LDI64",
    "JMP",
    "CJMP",
    "CALL",
    "RET",
    "CMP",
    "JE",
    "CJE",
    "JNE",
    "CJNE",
    "JG",
    "CJG",
    "JL",
    "CJL",
    "IADD",
    "IMUL",
    "IDIV",
    "MKVEC",
    "REVEC",
    "REFVEC",
    "SETVEC",
    "DEBUG_PRINTREG",
    "DEBUG_SAYHI"
};

#define END OPR_NULL
static Operand const op_operand_specs[][4] = {
    { OPR_REGISTER, END },                 // EXIT
    { OPR_REGISTER, END },                 // INCRW
    { END },                               // DECRW
    { OPR_REGISTER, OPR_IMM16, END },      // LDI16
    { OPR_REGISTER, OPR_IMM64, END },      // LDI64

    { OPR_REGISTER, OPR_FLAGS, END },      // JMP
    { OPR_IMM16, /*OPR_FLAGS,*/ END },     // CJMP
    { OPR_REGISTER, OPR_IMM16, END },      // CALL
    { OPR_REGISTER, END },                 // RET
    { OPR_REGISTER, OPR_REGISTER, END },   // CMP
    { OPR_REGISTER, END },                 // JE
    { OPR_IMM16, END },                    // CJE
    { OPR_REGISTER, END },                 // JNE
    { OPR_REGISTER, END },                 // CJNE
    { OPR_REGISTER, END },                 // JG
    { OPR_IMM16, END },                    // CJG
    { OPR_REGISTER, END },                 // JL
    { OPR_IMM16, END },                    // CJL

    { OPR_REGISTER, OPR_REGISTER, END },   // IADD
    { OPR_REGISTER, OPR_REGISTER, END },   // IMUL
    { OPR_REGISTER, OPR_REGISTER, END },   // IDIV

    { OPR_REGISTER, END },                 // MKVEC
    { OPR_REGISTER, OPR_REGISTER, END },   // REVEC
    { OPR_REGISTER, OPR_REGISTER, END },   // REFVEC
    { OPR_REGISTER, OPR_REGISTER, END },   // SETVEC

    { OPR_REGISTER, END },                 // DEBUG_PRINTREG
    { END }                                // DEBUG_SAYHI
};
#undef END

const uint32_t Vm::FLAG_DESTINATION = 0x80000000;

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
        default: assert(false);
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
                                uint32_t flags,
                                std::vector<uint8_t> &instructions,
                                std::string &emsg)
{
    uint32_t base = currentOpCode | flags;
    uint64_t extra;
    bool has_extra = false;

    assert(currentOpCode != OP_NULL);

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
        has_extra = true;
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

    uint32_t flags = 0;

    int last = 0;
    for (; i < input.end() || !(last++); ++i) {
        char c = last ? ' ' : *i;

        if (s == ST_INITIAL) {
            if (std::isalpha(c) || c == '_' || (currentOp.size() > 0 && std::isdigit(c))) {
                currentOp.push_back(c);
            }
            else if(c == '>') {
                flags |= FLAG_DESTINATION;
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
                    if (! finalizeInstruction(currentOpCode, operands, flags, instructions, emsg))
                        return false;
                    s = ST_INITIAL;
                    currentOp = "";
                    operands.clear();
                    flags = 0;
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
                        if (! finalizeInstruction(currentOpCode, operands, flags, instructions, emsg))
                            return false;
                        s = ST_INITIAL;
                        currentOp = "";
                        operands.clear();
                        flags = 0;
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

struct MainLoopState {
    MainLoopState(Vm::VectorAssemblerBroker &ab_, std::vector<uint8_t> &instructions_)
        : ab(ab_), instructions(instructions_) { }
    
    Vm::VectorAssemblerBroker &ab;
    std::vector<uint8_t> &instructions;
    std::size_t start;
    std::vector<uint8_t>::const_iterator position_of_last_incrw;
    std::size_t BLOB_SIZE;
    uint64_t saved_registers[16];
    bool registers_are_saved;
    std::size_t current_num_vm_registers;
    uint64_t initial_base_pointer_for_main_loop;
    uint64_t initial_stack_pointer_for_main_loop;

    Mem::MemState mem_state;

#ifdef DEBUG
    struct Asm::CountingVectorWriter *last_writer;
    std::size_t last_asm_offset;
#endif
};

///////////
Vm::VectorAssemblerBroker::Entry::Entry() { }
Vm::VectorAssemblerBroker::Entry::Entry(Vm::VectorAssemblerBroker::Entry const &e)
    : writer(e.writer), assembler(e.assembler), offset(e.offset) { }
Vm::VectorAssemblerBroker::Entry::Entry(Asm::CountingVectorWriter *writer_, Asm::CountingVectorAssembler *assembler_, int64_t offset_)
    : writer(writer_), assembler(assembler_), offset(offset_) { }

Vm::VectorAssemblerBroker::VectorAssemblerBroker(const std::size_t MAX_BYTES_)
    : MAX_BYTES(MAX_BYTES_), current_size(MAX_BYTES_) { }

std::size_t Vm::VectorAssemblerBroker::size()
{ return items.size(); }

struct CheckIfEntryContainsRetAddr {
    VectorAssemblerBroker::Entry const &e;
    bool &contained;
    CheckIfEntryContainsRetAddr(VectorAssemblerBroker::Entry const &e_, bool &contained_)
        : e(e_), contained(contained_) { }

    void operator()(uint64_t return_address)
    {
        uint64_t start = e.writer->get_start_addr();
        uint64_t end = start + e.writer->size();
        if (return_address >= start && return_address >= end) {
            contained = true;
        }
    }
};
struct CheckIfCallStackContainsRetAddr {
    uint64_t base_pointer;
    uint64_t stop_pointer;
    CheckIfCallStackContainsRetAddr(uint64_t base_pointer_, uint64_t stop_pointer_)
        : base_pointer(base_pointer_), stop_pointer(stop_pointer_) { }

    bool operator()(VectorAssemblerBroker::Entry const &e)
    {
        bool contained = false;
        Mem::walk_stack(base_pointer, stop_pointer, CheckIfEntryContainsRetAddr(e, contained));
        return contained;
    }
};

Vm::VectorAssemblerBroker::Entry const &Vm::VectorAssemblerBroker::simple_get_writer_assembler_for(uint8_t const *bytecode)
{
    using namespace Asm;

    CountingVectorWriter *w = new CountingVectorWriter(current_size);
    CountingVectorAssembler *a = new CountingVectorAssembler(*w);
    boost::shared_ptr<VectorAssemblerBroker::Entry> e(new VectorAssemblerBroker::Entry(w, a, 0));
    items[bytecode] = e;
    reverse_items[e] = bytecode;
    return *e;
}

template <class FuncT>
Vm::VectorAssemblerBroker::Entry const &Vm::VectorAssemblerBroker::get_writer_assembler_for(uint8_t const *bytecode, FuncT deletion_criterion)
{
    using namespace Asm;

    ConstMapIt it = items.find(bytecode);
    if (it == items.end()) {
        return simple_get_writer_assembler_for(bytecode);
    }
    else if (current_size >= MAX_BYTES) {
        // Not a very good algorithm...
        std::size_t max;
        MapIt it2;
        int i;
        for (i = 0, it2 = items.begin(); i < 5 && it2 != items.end(); ++i, ++it2) {
            break;
            CountingVectorWriter *w = it2->second->writer;
            if (w->size() < 2000) {
                w->clear();
                return *(it2->second);
            }
        }
        assert(items.size() > 0);
        if (it2 == items.end()) --it2; // Note that there must be at least one element in 'items' if current_size >= MAX_BYTES

        if (! deletion_criterion(const_cast<const Vm::VectorAssemblerBroker::Entry &>(*(it2->second))))
            return simple_get_writer_assembler_for(bytecode);

        delete it2->second->writer;
        delete it2->second->assembler;
        boost::shared_ptr<Entry> e(new VectorAssemblerBroker::Entry(
            new CountingVectorWriter(current_size),
            new CountingVectorAssembler(*(it2->second->assembler)),
            0
        ));
        items[it2->first] = e;
        reverse_items[e] = it2->first;
        return *(it2->second);
    }
    else {
        return *(it->second);
    }
}

uint64_t Vm::VectorAssemblerBroker::get_asm_code_addr_for(uint8_t const *bytecode)
{
    ConstMapIt it = items.find(bytecode);
    if (it == items.end())
        return NULL;
    else {
        return it->second->writer->get_start_addr(it->second->offset);
    }
}

void Vm::VectorAssemblerBroker::mark_bytecode(Vm::VectorAssemblerBroker::Entry const &e, uint8_t const *bytecode_addr)
{
    boost::shared_ptr<VectorAssemblerBroker::Entry> newEntry(new VectorAssemblerBroker::Entry(e.writer, e.assembler, e.writer->size()));
    items[bytecode_addr] = newEntry;
    reverse_items[newEntry] = bytecode_addr;
}

Vm::VectorAssemblerBroker::Entry const *Vm::VectorAssemblerBroker::known_to_be_local(uint8_t const *bytecode_addr1, uint8_t const *bytecode_addr2)
{
    ConstMapIt it1 = items.find(bytecode_addr1);
    ConstMapIt it2 = items.find(bytecode_addr2);
    if (it1 != items.end() && it2 != items.end() && it1->second->writer == it2->second->writer)
        return &*(it2->second);
    else
        return NULL;
}

static int8_t RegId_to_disp(RegId id)
{
    assert(id <= MAX_REG_ID && id > NUM_VM_REGS_IN_X86_REGS);
    return (id-NUM_VM_REGS_IN_X86_REGS-1) * 8;
}

static bool vm_reg_is_in_x86_reg(RegId id)
{
    assert(id <= MAX_REG_ID);
    return id <= NUM_VM_REGS_IN_X86_REGS;
}

template <class WriterT>
static void move_x86reg_to_vmreg_ptr(Asm::Assembler<WriterT> &a, RegId vmreg, Asm::Register x86reg)
{
    using namespace Asm;
    if (vmreg <= NUM_VM_REGS_IN_X86_REGS) {
        if (x86reg != vm_regs_x86_regs[vmreg-1])
            a.mov_reg_reg64(vm_regs_x86_regs[vmreg-1], x86reg);
    }
    else
        a.mov_rm64_reg(mem_2op_short(x86reg, RBP, NOT_A_REGISTER/*index*/, SCALE_1, RegId_to_disp(vmreg)));
}

template <class WriterT>
static Asm::Register move_vmreg_ptr_to_x86reg(Asm::Assembler<WriterT> &a, Asm::Register x86reg, RegId vmreg)
{
    using namespace Asm;
    if (vmreg <= NUM_VM_REGS_IN_X86_REGS)
        return vm_regs_x86_regs[vmreg - 1];
    a.mov_reg_rm64(mem_2op_short(x86reg, RBP, NOT_A_REGISTER/*index*/, SCALE_1, RegId_to_disp(vmreg)));
    return x86reg;
}

template <class WriterT>
static void move_vmreg_ptr_to_guaranteed_x86reg(Asm::Assembler<WriterT> &a, Asm::Register x86reg, RegId vmreg)
{
    using namespace Asm;
    if (vmreg <= NUM_VM_REGS_IN_X86_REGS) {
        if (x86reg != vm_regs_x86_regs[vmreg-1])
            a.mov_reg_reg64(x86reg, vm_regs_x86_regs[vmreg-1]);
    }
    else
        a.mov_reg_rm64(mem_2op_short(x86reg, RBP, NOT_A_REGISTER/*index*/, SCALE_1, RegId_to_disp(vmreg)));
}

static int is_saved_before_c_funcall(Asm::Register reg)
{
    using namespace Asm;

    int saved_count = 0;
    for (int i = 0; i < sizeof(vm_regs_x86_regs) / sizeof(Register); ++i) {
        if (reg == vm_regs_x86_regs[i]) {
            return vm_regs_x86_regs_to_save[i] ? saved_count : -1;
        }
        if (vm_regs_x86_regs_to_save[i])
            ++saved_count;
    }
    assert(false);
}

template <class WriterT>
static void move_vmreg_ptr_to_guaranteed_x86reg_following_save(MainLoopState const &mls, Asm::Assembler<WriterT> &a, Asm::Register x86reg, RegId vmreg)
{
    using namespace Asm;

    unsigned regs_saved = 0;
    for (int i = 0; i < sizeof(vm_regs_x86_regs) / sizeof(Register) && i < mls.current_num_vm_registers; ++i) {
        if (vm_regs_x86_regs_to_save[i])
            ++regs_saved;
    }

    if (! vm_reg_is_in_x86_reg(vmreg)) {
        move_vmreg_ptr_to_guaranteed_x86reg(a, x86reg, vmreg);
    }
    else {
        Register x86_reg_for_vmreg = vm_regs_x86_regs[vmreg];
        int saved_count = is_saved_before_c_funcall(x86_reg_for_vmreg);
        if (saved_count == -1) {
            move_vmreg_ptr_to_guaranteed_x86reg(a, x86reg, vmreg);
        }
        else {
            int offset = (saved_count * 8) - 8;
            assert(offset <= 127);
            a.mov_reg_rm64(mem_2op_short(x86reg, RBP, NOT_A_REGISTER/*index*/, SCALE_1, offset));
        }
    }
}

static void *my_malloc(size_t bytes)
{
    void *r = std::malloc(bytes);
#ifdef DEBUG
//   std::printf("MALLOC CALLED: 0x%llx\n", (unsigned long long)r);
#endif
    return r;
}

static void *call_alloc_tagged_mem(Mem::MemState &ms, std::size_t size, unsigned tag)
{ ms.alloc_tagged_mem(size, tag); }
// Emit code to allocate tagged memory.
// Leaves address (untagged) in RAX and tagged in RDX. (This
// is how the Mem::MemState::Allocation structure is returned according
// to the x86-64 ABI.)
template <class WriterT>
static void emit_malloc_constsize(MainLoopState const &mls, Asm::Assembler<WriterT> &a, std::size_t size, RegId ptr_dest, unsigned tag)
{
    using namespace Asm;

    assert(tag < 4);

    save_regs_before_c_funcall(mls, a);
    a.mov_reg_imm64(RDI, PTR(&(mls.mem_state)));
    a.mov_reg_imm64(RSI, static_cast<uint64_t>(size));
    a.mov_reg_imm64(RDX, static_cast<uint64_t>(tag));
    a.mov_reg_imm64(RAX, 0);
    a.mov_reg_imm64(RCX, PTR(call_alloc_tagged_mem));
    a.call_rm64(reg_1op(RCX));
    restore_regs_after_c_funcall(mls, a);
    move_x86reg_to_vmreg_ptr(a, ptr_dest, RDX);
}

template <class WriterT>
static void emit_incrw(Asm::Assembler<WriterT> &a, RegId num_regs)
{
    using namespace Asm;
    a.call_rel32(mkdisp<int32_t>(0, DISP_ADD_ISIZE));
    a.push_rm64(reg_1op(RBP));
    a.mov_rm64_reg(reg_2op(RSP, RBP));
    if (num_regs > 8)
        a.sub_rm64_imm8(reg_1op(RBP), (num_regs - 8) * 8);
}

template <class WriterT>
static void emit_ldi(MainLoopState const &mls, Asm::Assembler<WriterT> &a, RegId ptr_dest, uint64_t val)
{
    using namespace Asm;
    emit_malloc_constsize(mls, a, 8, ptr_dest, TAG_INT); // Leaves untagged address in RAX.
    a.mov_reg_imm64(RCX, val);
    a.mov_rm64_reg(mem_2op(RCX, RAX));
}

template <class WriterT>
static void emit_cmp(Asm::Assembler<WriterT> &a, RegId op1, RegId op2)
{
    using namespace Asm;
    Register r1 = move_vmreg_ptr_to_x86reg(a, RDX, op1);
    Register r2 = move_vmreg_ptr_to_x86reg(a, RCX, op2);
    a.mov_reg_rm64(mem_2op(RAX, r2));
    a.cmp_rm64_reg(mem_2op(RAX, r1));
}

template <class WriterT>
static void emit_iadd(Asm::Assembler<WriterT> &a, RegId r_dest, RegId r_src)
{
    using namespace Asm;
    Register r1 = move_vmreg_ptr_to_x86reg(a, RDX, r_dest);
    Register r2 = move_vmreg_ptr_to_x86reg(a, RCX, r_src);
    a.mov_reg_rm64(mem_2op(RAX, r1));
    a.add_reg_rm64(mem_2op(RAX, r2));
    a.mov_rm64_reg(mem_2op(RAX, r1));
}

template <class WriterT>
static void emit_exit(MainLoopState const &mls, Asm::Assembler<WriterT> &a, RegId retreg)
{
    using namespace Asm;

    if (retreg != 0)
        move_vmreg_ptr_to_guaranteed_x86reg(a, RAX, retreg);
    else
        a.mov_reg_imm64(RAX, 0);

    // Restore RBP and RSP.
    a.mov_reg_imm64(RCX, PTR(&(mls.initial_base_pointer_for_main_loop)));
    a.mov_reg_rm64(mem_2op(RBP, RCX));
    a.mov_reg_imm64(RCX, PTR(&(mls.initial_stack_pointer_for_main_loop)));
    a.mov_reg_rm64(mem_2op(RSP, RCX));

    a.leave(); // Now that we've reset ESP/EBP, calling leave/ret
    a.ret();   // will return from main_loop_.
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
    a.mov_reg_reg64(RBX, RSP);
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
static void save_all_regs(Asm::CountingVectorAssembler &a, uint64_t *buffer)
{
    using namespace Asm;

    assert(buffer != NULL);

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
static void restore_all_regs(Asm::Assembler<WriterT> &a, uint64_t *buffer, Asm::Register except=Asm::NOT_A_REGISTER)
{
    using namespace Asm;

    assert(buffer != NULL);

    a.mov_reg_imm64(RAX, PTR(buffer));
    unsigned i = 1;
    for (; i < sizeof(gp_regs) / sizeof(Register); ++i) {
        if (gp_regs[i] != except)
            a.mov_reg_rm64(mem_2op_short(gp_regs[i], RAX, NOT_A_REGISTER, SCALE_1, i*8));
    }
    a.push_reg64(RCX);
    a.mov_reg_imm64(RCX, PTR(buffer));
    a.mov_reg_rm64(mem_2op_short(RAX, RCX));
    a.pop_reg64(RCX);
}

// Save those registers which
//     (i)  belong to the caller according to the X86-64 ABI.
//     (ii) are used to hold VM registers.
template <class WriterT>
static void save_regs_before_c_funcall(MainLoopState const &mls, Asm::Assembler<WriterT> &a)
{
    using namespace Asm;
    for (int i = 0; i < sizeof(vm_regs_x86_regs) / sizeof(Register) && i < mls.current_num_vm_registers; ++i) {
//    for (int i = 0; i < sizeof(vm_regs_x86_regs) / sizeof(Register); ++i) {
        if (vm_regs_x86_regs_to_save[i]) {
//        if (true) {
            Register r = vm_regs_x86_regs[i];
            a.push_rm64(reg_1op(r));
        }
    }
}
template <class WriterT>
static void restore_regs_after_c_funcall(MainLoopState const &mls, Asm::Assembler<WriterT> &a)
{
    using namespace Asm;
    for (int i = std::min(static_cast<int>(mls.current_num_vm_registers), static_cast<int>((sizeof(vm_regs_x86_regs) / sizeof(Register)))) - 1; i >= 0; --i) {
//    for (int i = (sizeof(vm_regs_x86_regs) / sizeof(Register)) - 1; i >= 0; --i) {
        if (vm_regs_x86_regs_to_save[i]) {
//        if (true) {
            Register r = vm_regs_x86_regs[i];
            a.pop_rm64(reg_1op(r));
        }
    }
}

template <class WriterT>
static void emit_call(MainLoopState const &mls, Asm::Assembler<WriterT> &a, RegId r, unsigned num_args)
{
    using namespace Asm;

    assert(num_args < MAX_VM_REGS);

    move_vmreg_ptr_to_x86reg(a, RCX, r);
    for (int i = 0; i < NUM_VM_REGS_IN_X86_REGS; ++i) {
        a.push_rm64(reg_1op(vm_regs_x86_regs[i]));
    }
    a.mov_reg_imm64(RDI, num_args);
    a.call_rm64(reg_1op(RCX));
    for (int i = NUM_VM_REGS_IN_X86_REGS; i >=0; --i) {
        a.pop_rm64(reg_1op(vm_regs_x86_regs[i]));
    }
}

template <class WriterT>
static void emit_ret(MainLoopState const &mls, Asm::Assembler<WriterT> &a)
{
    a.ret();
}

static void print_vm_reg(RegId rid, uint64_t tagged_ptr)
{
    uint64_t tag = tagged_ptr & 0x0000000000000003;
    std::printf("- REGISTER %i\n- TAG      %lli (%s)\n", (int)rid, tag, tag_name(tag));
    if (tag == TAG_INT) {
        std::printf("- PTR:     0x%llx\n", (unsigned long long)tagged_ptr);
        std::printf("- VALUE:   %lli\n\n", *((long long *)(tagged_ptr & 0xFFFFFFFFFFFFFFFC)));
    }
    else assert(false);
}
template <class WriterT>
static void emit_debug_printreg(MainLoopState const &mls, Asm::Assembler<WriterT> &a, RegId r)
{
    using namespace Asm;

    save_regs_before_c_funcall(mls, a);
    a.mov_reg_imm32(EDI, static_cast<uint32_t>(r));
    move_vmreg_ptr_to_guaranteed_x86reg_following_save(mls, a, RSI, r);
    a.mov_reg_imm64(RCX, PTR(print_vm_reg));
    a.mov_reg_imm64(RAX, 0);
    a.call_rm64(reg_1op(RCX));
    restore_regs_after_c_funcall(mls, a);
}

static void sayhi() { std::printf("HI\n"); }
template <class WriterT>
static void emit_debug_sayhi(MainLoopState const &mls, Asm::Assembler<WriterT> &a)
{
    using namespace Asm;

    a.mov_reg_imm64(RCX, PTR(sayhi));
    save_regs_before_c_funcall(mls, a);
    a.call_rm64(reg_1op(RCX));
    restore_regs_after_c_funcall(mls, a);
}

namespace {
template <class WriterT, std::size_t S>
struct ASM {
    static void mov_rmX_reg(Asm::Assembler<WriterT> &a, Asm::ModrmSib const &modrmsib);
};
#define INST(size) \
    template <class WriterT> \
    struct ASM<WriterT, size/8> { \
        static void mov_rmX_reg(Asm::Assembler<WriterT> &a, Asm::ModrmSib const &modrmsib) \
        { a.mov_rm ## size ## _reg(modrmsib); } \
    };
INST(8) INST(32) INST(64)
#undef INST
}
template <class WriterT>
static void set_bool(Asm::Assembler<WriterT> &a, bool &var, bool tf)
{
    using namespace Asm;

    a.mov_reg_imm64(RCX, PTR(&var));
    a.mov_reg_imm64(RAX, tf ? 1 : 0);
    ASM<WriterT, sizeof(bool)*8>::mov_rmX_reg(a, mem_2op(AL, RCX));
}

// This could just be inline ASM, but since we already have an assembler,
// we may as well do it without making use of compiler-specific extensions.
#define GET_BASE_POINTER_AND_STACK_POINTER(bp_var, sp_var) \
    do { \
        using namespace Asm; \
        VectorWriter bpw__; \
        VectorAssembler bpa__(bpw__); \
        bpa__.mov_reg_imm64(RCX, PTR(&(bp_var))); \
        bpa__.mov_rm64_reg(mem_2op(RBP, RCX)); \
        bpa__.mov_reg_imm64(RCX, PTR(&(sp_var))); \
        bpa__.mov_rm64_reg(mem_2op(RSP, RCX)); \
        bpa__.ret(); \
        bpw__.get_exec_func()(); \
    } while (0);

static uint64_t inner_main_loop(MainLoopState &mls);
template <class WriterT>
static void call_main_loop_setting_start_to(MainLoopState &mls, Asm::Assembler<WriterT> &a, WriterT &w, std::size_t value)
{
    using namespace Asm;

    // Save all registers and set 'registers_are_saved' to true.
    save_all_regs(a, mls.saved_registers);
    set_bool(a, mls.registers_are_saved, true);

    // Increment 'start' by the relevant amount.
    a.mov_reg_imm64(RAX, value);
    a.mov_moffs64_rax(PTR(&(mls.start)));

    // Call the innner main loop.
    a.mov_reg_imm64(RCX, PTR(inner_main_loop));
    a.mov_reg_imm64(RDI, PTR(&mls));
    a.mov_reg_imm64(RAX, 0);
    a.call_rm64(reg_1op(RCX));
}

static uint64_t inner_main_loop(MainLoopState &mls)
{
    using namespace Asm;

    if (mls.start >= mls.instructions.size()) {
        // This could just be inline ASM, but since we already have an assembler,
        // we may as well do it without making use of compiler-specific extensions.
        VectorWriter evw;
        VectorAssembler eva(evw);
        emit_exit(mls, eva, 0);
        evw.get_exec_func()(); // This will return from the outer main loop.
    }

    uint64_t bp;
    uint64_t sp;
    VectorAssemblerBroker::Entry e;
    if (mls.registers_are_saved) {
        GET_BASE_POINTER_AND_STACK_POINTER(bp, sp);
        e = mls.ab.get_writer_assembler_for(&*(mls.instructions.begin() + mls.start),
                                            CheckIfCallStackContainsRetAddr(bp, mls.initial_base_pointer_for_main_loop));
    }
    else {
        e = mls.ab.get_writer_assembler_for(&*(mls.instructions.begin() + mls.start),
                                            VectorAssemblerBroker::AlwaysDelete());
    }

    CountingVectorAssembler *a = e.assembler;
    CountingVectorWriter *w = e.writer;
//    std::printf("WRITER: %llx\n", w);

    // Makes it easier to see which ASM is for which VM instruction when debugging.
#ifdef DEBUG
    a->nop();
#endif

    // Kill the stack space used by 'inner_main_loop'.
//    a->leave();

    if (mls.registers_are_saved) {
        restore_all_regs(*a, mls.saved_registers);
    }

#ifdef DEBUG
    a->nop();
#endif

    bool last_instruction_exited = false;
    std::vector<uint8_t>::const_iterator i;
    for (i = mls.instructions.begin() + mls.start;
         i != mls.instructions.end() && i - mls.instructions.begin() - mls.start < mls.BLOB_SIZE*4;
         i += 4) {
        assert(i + 3 < mls.instructions.end());

        last_instruction_exited = false;

        // If this bit of the code is jumped to, cache the location of the generated assembly.
        if (i[3] & FLAG_DESTINATION >> 24)
            mls.ab.mark_bytecode(e, &*i);

        switch (*i) {
            case OP_NULL: assert(false);
            case OP_EXIT: {
                last_instruction_exited = true;
                emit_exit(mls, *a, i[1]);
            } break;
            case OP_INCRW: {
                emit_incrw(*a, i[1]);
                mls.position_of_last_incrw = i;
                mls.current_num_vm_registers = (uint8_t)i[1];
                assert(mls.current_num_vm_registers != 0);
            } break;
            case OP_LDI16: {
                emit_ldi(mls, *a, i[1], i[2] + ((uint64_t)i[3] << 8));
            } break;
            case OP_LDI64: {
#define C(x) static_cast<uint64_t>(x)
                emit_ldi(mls, *a, i[1],
                         i[4] + (C(i[5]) << 8) + (C(i[6]) << 16) +
                         (C(i[7]) << 24) + (C(i[8]) << 32) +
                         (C(i[9]) << 40) + (C(i[10]) << 48) +
                         (C(i[11]) << 56));
                i += 8;
#undef C
            } break;
            case OP_CMP: {
                emit_cmp(*a, i[1], i[2]);
            } break;
            case OP_IADD: {
                emit_iadd(*a, i[1], i[2]);
            } break;
            case OP_DEBUG_PRINTREG: {
                emit_debug_printreg(mls, *a, i[1]);
            } break;
            case OP_DEBUG_SAYHI: {
                emit_debug_sayhi(mls, *a);
            } break;
            case OP_CALL: {
                emit_call(mls, *a, i[1], i[2] + (static_cast<unsigned>(i[3]) << 8));
            } break;
            case OP_RET: {
                emit_ret(mls, *a);
            } break;
            case OP_CJMP:
            case OP_CJE:
            case OP_CJNE: {
                if (*i == OP_CJMP) last_instruction_exited = true;

                std::size_t bytecode_offset = i[1] + ((std::size_t)i[2] << 8);

                typedef void (CountingVectorAssembler::*jmp_fptr)(Disp<int32_t> disp, BranchHint hint);
                struct Pr { Opcode opcode; BranchHint hint; jmp_fptr fptr; };
                static Pr const jmp_fptrs[] = {
                    { OP_CJMP, BRANCH_HINT_NONE, &CountingVectorAssembler::jmp_nr_rel32 },
                    { OP_CJE, BRANCH_HINT_NONE, &CountingVectorAssembler::je_nr_rel32 },
                    { OP_CJNE, BRANCH_HINT_NONE, &CountingVectorAssembler::jne_nr_rel32 }
                };

                // If this is a local jump, we can guarantee that the ASM code for the jump will be
                // created/deleted at the same time as the ASM code for the target, so we can make the jump
                // directly rather than going via the main JIT loop (much faster).
                if (VectorAssemblerBroker::Entry const *je = mls.ab.known_to_be_local(&*(mls.instructions.begin() + mls.start), &*(mls.instructions.begin() + bytecode_offset))) {
                    // Check if it's in the same stack frame.
                    if (! (mls.instructions.begin() + bytecode_offset >= mls.position_of_last_incrw)) {
                        // TODO: Implement.
                        assert(false);
                    }

                    // FAST(er)
                    uint64_t current_addr = w->get_start_addr() + w->size();
                    uint64_t target_addr = je->writer->get_start_addr(je->offset);
                    int32_t rel = (int32_t)(target_addr - current_addr);

                    int j;
                    for (j = 0; j < sizeof(jmp_fptrs) / sizeof(Pr); ++j) {
                        if (jmp_fptrs[j].opcode == *i) {
                            (a->*(jmp_fptrs[j].fptr))(mkdisp<int32_t>(rel, DISP_SUB_ISIZE), jmp_fptrs[j].hint);
                            break;
                        }
                    }
                    assert(j < sizeof(jmp_fptrs) / sizeof(Pr));
                }
                else {
#ifdef DEBUG
                    std::printf("** SLOW JUMP (possible bug) **\n");
#endif
                    // SLOW
                    call_main_loop_setting_start_to(mls, *a, *w, bytecode_offset);
                }
            } break;
            default: assert(false);
        }
#ifdef DEBUG
        a->nop();
#endif
    }

    if (! last_instruction_exited)
        call_main_loop_setting_start_to(mls, *a, *w, i - mls.instructions.begin());

#ifdef DEBUG
    if (mls.last_writer != w)
        mls.last_asm_offset = 0;

    std::ofstream f;
    f.open("/tmp/vm_debug_raw", std::ios::app | std::ios::binary);
    f.write(reinterpret_cast<char *>(w->get_mem(mls.last_asm_offset)), w->size() - mls.last_asm_offset);
    f.close();

    mls.last_asm_offset = w->size();
    mls.last_writer = w;
#endif

    w->get_exec_func(e.offset)();

    return 0;
}

uint64_t Vm::main_loop(std::vector<uint8_t> &instructions, std::size_t start, const std::size_t BLOB_SIZE)
{
    using namespace Asm;

    VectorAssemblerBroker ab(2 << 12);

    MainLoopState mls(ab, instructions);
    mls.start = start;
    mls.position_of_last_incrw = instructions.begin() + start;
    mls.BLOB_SIZE = BLOB_SIZE;
    mls.registers_are_saved = false;
    mls.current_num_vm_registers = 0;
#ifdef DEBUG
    mls.last_writer = NULL;
    mls.last_asm_offset = 0;
#endif

    GET_BASE_POINTER_AND_STACK_POINTER(mls.initial_base_pointer_for_main_loop,
                                       mls.initial_stack_pointer_for_main_loop);

    return inner_main_loop(mls);
}
