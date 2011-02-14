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
// * Those GP registers that AREN'T used to pass arguments according to the x86-64 ABI are
//   are used as volatile scratch registers.
// * All other registers, including R8-R15, are used to hold VM registers.
//

using namespace Vm;

// When debugging, we want to check that register saving is working properly. Hence,
// we use registers that need to be saved before using those that don't.
#ifdef DEBUG
const Asm::Register vm_regs_x86_regs[] = { Asm::R8, Asm::R9, Asm::R10, Asm::R11, Asm::RDI, Asm::R12, Asm::R13, Asm::R14, Asm::R15, Asm::RCX  };
const bool vm_regs_x86_regs_to_save[] =  { true,    true,    true,     true,     true,     false,    false,    false,    false,    true };
#else
//const Asm::Register vm_regs_x86_regs[] = { /*Asm::R12,*/ Asm::R13, Asm::R14, Asm::R15, Asm::R8, Asm::R9, Asm::R10, Asm::R11, Asm::RCX, Asm::RDI };
//const bool vm_regs_x86_regs_to_save[] =  { /*false,*/    false,    false,    false,    true,    true,    true,     true,     true,     true     };
#endif
const int NUM_VM_REGS_IN_X86_REGS = sizeof(vm_regs_x86_regs)/sizeof(Asm::Register);

const Opcode Vm::FIRST_OP = OP_EXIT;

// We can have 127 on the machine stack and some number in registers.
const unsigned Vm::MAX_REG_ID = 127 + 4;
const unsigned MAX_VM_REGS = MAX_REG_ID-1;

#ifdef DEBUG
#   define SCRATCH_REG(r) (assert((r) == Asm::RAX || (r) == Asm::RBX || (r) == Asm::RDX || (r) == Asm::RSI), r)
#else
#   define SCRATCH_REG(r) (r)
#endif

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
    "MKIVEC0",
    "MKIVECD",
    "MKIVEC",
    "REFIVEC",
    "SETIVEC",
    "DEBUG_PRINTREG",
    "DEBUG_SAYHI"
};

#define END OPR_NULL
static Operand const op_operand_specs[][4] = {
    { OPR_REGISTER, END },                       // EXIT
    { OPR_REGISTER, END },                       // INCRW
    { END },                                     // DECRW
    { OPR_REGISTER, OPR_IMM16, END },            // LDI16
    { OPR_REGISTER, OPR_IMM64, END },            // LDI64

    { OPR_REGISTER, OPR_FLAGS, END },            // JMP
    { OPR_IMM16, /*OPR_FLAGS,*/ END },           // CJMP
    { OPR_REGISTER, OPR_IMM16, END },            // CALL
    { OPR_REGISTER, END },                       // RET
    { OPR_REGISTER, OPR_REGISTER, END },         // CMP
    { OPR_REGISTER, END },                       // JE
    { OPR_IMM16, END },                          // CJE
    { OPR_REGISTER, END },                       // JNE
    { OPR_REGISTER, END },                       // CJNE
    { OPR_REGISTER, END },                       // JG
    { OPR_IMM16, END },                          // CJG
    { OPR_REGISTER, END },                       // JL
    { OPR_IMM16, END },                          // CJL

    { OPR_REGISTER, OPR_REGISTER, END },         // IADD
    { OPR_REGISTER, OPR_REGISTER, END },         // IMUL
    { OPR_REGISTER, OPR_REGISTER, END },         // IDIV

    { OPR_REGISTER, END },                       // MKIVEC0
    { OPR_REGISTER, OPR_FLAGS, END },            // MKIVECD
    { OPR_REGISTER, OPR_FLAGS, OPR_IMM64, END }, // MKIVEC
    { OPR_REGISTER, OPR_REGISTER, END },         // REFIVEC
    { OPR_REGISTER, OPR_REGISTER, END },         // SETIVEC

    { OPR_REGISTER, END },                       // DEBUG_PRINTREG
    { END }                                      // DEBUG_SAYHI
};
#undef END

const uint32_t Vm::FLAG_DESTINATION = 0x80000000;

const unsigned Vm::TAG_INT = 0;
const unsigned Vm::TAG_BOOL = 1;
const unsigned Vm::TAG_DOUBLE = 2;
const unsigned Vm::TAG_VECTOR = 3;
const unsigned Vm::TAG_NULL = 4;

const unsigned Vm::TAG_MASK = 7; // Lowest three bits.

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
        case TAG_BOOL: return "bool";
        case TAG_DOUBLE: return "double";
        case TAG_VECTOR: return "vector";
        case TAG_NULL: return "tag_null";
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

typedef void(*ErrorHandler)(struct MainLoopState &mls);

struct SavedRegisters {
    uint64_t gp_registers[16];
    uint64_t xmm_registers[32];
    uint64_t flags;
};
struct MainLoopState {
    MainLoopState(Vm::VectorAssemblerBroker &ab_, std::vector<uint8_t> &instructions_)
        : ab(ab_), instructions(instructions_) { }
    
    Vm::VectorAssemblerBroker &ab;
    std::vector<uint8_t> &instructions;
    std::size_t start;
    std::vector<uint8_t>::const_iterator position_of_last_incrw;
    std::size_t BLOB_SIZE;
    SavedRegisters saved_registers;
    bool registers_are_saved;
    std::size_t current_num_vm_registers;
    uint64_t initial_base_pointer_for_main_loop;
    uint64_t initial_stack_pointer_for_main_loop;
    bool last_instruction_exited;

    Mem::MemState mem_state;

    ErrorHandler type_error_handler;
    boost::shared_ptr<Asm::VectorWriter> type_error_handler_asm;

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

static Asm::Register RegId_to_x86reg(RegId id)
{
    assert(id <= NUM_VM_REGS_IN_X86_REGS);
    return vm_regs_x86_regs[id-1];
}
static int8_t RegId_to_disp(RegId id)
{
    assert(id <= MAX_REG_ID && id > NUM_VM_REGS_IN_X86_REGS);
    return (id-NUM_VM_REGS_IN_X86_REGS-1) * 8;
}

static bool vm_reg_is_in_x86reg(RegId id)
{
    assert(id <= MAX_REG_ID);
    return id <= NUM_VM_REGS_IN_X86_REGS;
}

template <class WriterT>
static void move_x86reg_to_vmreg_ptr(Asm::Assembler<WriterT> &a, RegId vmreg, Asm::Register x86reg)
{
    using namespace Asm;
    if (vmreg <= NUM_VM_REGS_IN_X86_REGS) {
        if (x86reg != RegId_to_x86reg(vmreg)) {
            a.mov_reg_reg64(RegId_to_x86reg(vmreg), x86reg);
        }
    }
    else
        a.mov_rm64_reg(mem_2op_short(x86reg, RBP, NOT_A_REGISTER/*index*/, SCALE_1, RegId_to_disp(vmreg)));
}

template <class WriterT>
static Asm::Register move_vmreg_ptr_to_x86reg(Asm::Assembler<WriterT> &a, Asm::Register x86reg, RegId vmreg)
{
    using namespace Asm;
    if (vmreg <= NUM_VM_REGS_IN_X86_REGS)
        return RegId_to_x86reg(vmreg);
    a.mov_reg_rm64(mem_2op_short(x86reg, RBP, NOT_A_REGISTER/*index*/, SCALE_1, RegId_to_disp(vmreg)));
    return x86reg;
}

template <class WriterT>
static void move_vmreg_ptr_to_guaranteed_x86reg(Asm::Assembler<WriterT> &a, Asm::Register x86reg, RegId vmreg, std::size_t stack_offset=0)
{
    using namespace Asm;
    assert(vmreg > 0);
    if (vmreg <= NUM_VM_REGS_IN_X86_REGS) {
        if (x86reg != RegId_to_x86reg(vmreg)) {
            a.mov_reg_reg64(x86reg, RegId_to_x86reg(vmreg));
        }
    }
    else {
        a.mov_reg_rm64(mem_2op_short(x86reg, RBP, NOT_A_REGISTER/*index*/, SCALE_1, RegId_to_disp(vmreg) + stack_offset));
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

static void myprint(char const *preamble, uint64_t value)
{
    std::printf("%s%llx\n", preamble, value);
}
template <class WriterT>
static void debug_print_x86reg64(Asm::Assembler<WriterT> &a, Asm::Register r, const char *preamble)
{
    using namespace Asm;

    a.emit_save_all_regs();
    if (r != RSI)
        a.mov_reg_reg64(RSI, r); // Second argument to printf.
    a.mov_reg_imm64(RDI, PTR(preamble)); // First argument to printf.
    a.mov_reg_imm64(RCX, PTR(myprint));
    a.call_rm64(reg_1op(RCX));
    a.emit_restore_all_regs();
}

static Mem::MemState::Allocation call_alloc_tagged_mem(Mem::MemState &ms, std::size_t size, unsigned tag, unsigned second_tag)
{ SCRATCH_REG(Asm::RAX); SCRATCH_REG(Asm::RDX); return ms.alloc_tagged_mem(size, tag, second_tag); }
// Emit code to allocate tagged memory.
// Leaves address (untagged) in RAX and tagged in RDX. (This
// is how the Mem::MemState::Allocation structure is returned according
// to the x86-64 ABI.)
template <class WriterT>
static void emit_alloc_tagged_mem(MainLoopState const &mls, Asm::Assembler<WriterT> &a, std::size_t size, RegId ptr_dest, unsigned tag, unsigned second_tag)
{
    using namespace Asm;

    assert(tag < 4);

    save_regs_before_c_funcall(mls, a);
    a.mov_reg_imm64(RDI, PTR(&(mls.mem_state)));
    a.mov_reg_imm64(RSI, static_cast<uint64_t>(size));
    a.mov_reg_imm64(RDX, static_cast<uint64_t>(tag));
    a.mov_reg_imm64(RCX, static_cast<uint64_t>(second_tag));
    a.mov_reg_imm32(EAX, 0);
    a.mov_reg_imm64(RBX, PTR(call_alloc_tagged_mem));
    a.call_rm64(reg_1op(RBX));
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
    if (num_regs > NUM_VM_REGS_IN_X86_REGS)
        a.sub_rm64_imm8(reg_1op(RBP), (num_regs - NUM_VM_REGS_IN_X86_REGS) * 8);
}

template <class WriterT>
static void emit_ldi(MainLoopState const &mls, Asm::Assembler<WriterT> &a, RegId ptr_dest, uint64_t val)
{
    using namespace Asm;
    emit_alloc_tagged_mem(mls, a, 8, ptr_dest, TAG_INT, 0); // Leaves untagged address in RAX.
    a.mov_reg_imm64(SCRATCH_REG(RBX), val);
    a.mov_rm64_reg(mem_2op(RBX, RAX));
}

template <class WriterT>
static void emit_cmp(Asm::Assembler<WriterT> &a, RegId op1, RegId op2)
{
    using namespace Asm;
    Register r1 = move_vmreg_ptr_to_x86reg(a, SCRATCH_REG(RDX), op1);
    Register r2 = move_vmreg_ptr_to_x86reg(a, SCRATCH_REG(RBX), op2);
    a.mov_reg_rm64(mem_2op(SCRATCH_REG(RAX), r2));
    a.cmp_rm64_reg(mem_2op(RAX, r1));
}

static void type_error_handler(MainLoopState &mls)
{
    std::printf("\n\n*** TYPE ERROR ***\n\n");
    std::exit(1);
}
// The main purpose of this is to generate a function with a reference to the main loop
// state 'baked' in. This means that the tag-checking code doesn't have to pass this
// parameter in.
template <class WriterT>
static boost::shared_ptr<WriterT> gen_type_error_handler_asm(MainLoopState const &mls)
{
    using namespace Asm;
    boost::shared_ptr<WriterT> w(new WriterT);
    Asm::Assembler<WriterT> a(*w);

    a.push_reg64(RBP);
    a.mov_reg_reg64(RBP, RSP);

    save_regs_before_c_funcall(mls, a);
    a.mov_reg_imm64(RDI, PTR(&mls));
    a.mov_reg_imm64(RBX, PTR(mls.type_error_handler));
    a.mov_reg_imm32(EAX, 0);
    a.call_rm64(reg_1op(RBX));
    // Won't actually get here.
    restore_regs_after_c_funcall(mls, a);

    a.leave();
    a.ret();

    return w;
}

template <class WriterT>
static void check_tag(MainLoopState const &mls, Asm::Assembler<WriterT> &a, WriterT &w, Asm::Register x86reg, unsigned expected_tag_value, Asm::Register scratch_reg)
{
    using namespace Asm;

    assert(x86reg != scratch_reg && scratch_reg != RAX && scratch_reg != EAX && expected_tag_value <= TAG_MASK);

    a.mov_reg_rm64(reg_2op(scratch_reg, x86reg));
    a.and_rm64_imm8(reg_1op(scratch_reg), (uint8_t)TAG_MASK);
    a.cmp_rm64_imm8(reg_1op(scratch_reg), (uint8_t)expected_tag_value);
    typename Asm::Assembler<WriterT>::StDispSetter ds = a.je_st_rel8(0); // Going to fill this in in a minute.
    std::size_t byte = w.size();
    a.mov_reg_imm64(scratch_reg, mls.type_error_handler_asm->get_start_addr());
    a.call_rm64(reg_1op(scratch_reg));
    std::size_t af = w.size();
    ds.set(af - byte);
}

template <class WriterT>
static void emit_iadd(MainLoopState const &mls, Asm::Assembler<WriterT> &a, WriterT &w, RegId r_dest, RegId r_src)
{
    using namespace Asm;
    Register r1 = move_vmreg_ptr_to_x86reg(a, RDX, r_dest);
    Register r2 = move_vmreg_ptr_to_x86reg(a, RBX, r_src);

    // Check that the values are integers.
    check_tag(mls, a, w, r1, TAG_INT, SCRATCH_REG(RSI));
    check_tag(mls, a, w, r2, TAG_INT, SCRATCH_REG(RSI));

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
    a.mov_reg_imm64(RBX, PTR(&(mls.initial_base_pointer_for_main_loop)));
    a.mov_reg_rm64(mem_2op(RBP, RBX));
    a.mov_reg_imm64(RBX, PTR(&(mls.initial_stack_pointer_for_main_loop)));
    a.mov_reg_rm64(mem_2op(RSP, RBX));

    a.leave(); // Now that we've reset ESP/EBP, calling leave/ret
    a.ret();   // will return from main_loop_.
}

static const Asm::Register gp_regs[] = {
    Asm::RAX, Asm::RCX, Asm::RDX, Asm::RBX, Asm::RSP, Asm::RBP, Asm::RSI, Asm::RDI,
    Asm::R8, Asm::R9, Asm::R10, Asm::R11, Asm::R12, Asm::R13, Asm::R14, Asm::R15
};
static void save_all_regs(Asm::CountingVectorAssembler &a, SavedRegisters &saved)
{
    using namespace Asm;

    // Note that this function isn't supposed to save ALL registers. Just those
    // registers which hold state which might carry across VM instructions. So for
    // example, we're not saving the flags register, because any use of this register
    // should be self-contained for each VM instruction. Right now, we're also not
    // saving XMM regs since the VM doesn't do any floating point yet.

    // We're going to use RAX as scratch, so save it first.
    a.push_reg64(RAX);

    // Save general purpose registers.
    a.mov_reg_imm64(RAX, PTR(saved.gp_registers));
    unsigned i = 1; // Skipping RAX (see below).
    for (; i < sizeof(gp_regs) / sizeof(Register); ++i) {
        a.mov_rm64_reg(mem_2op_short(gp_regs[i], RAX, NOT_A_REGISTER, SCALE_1, i*8));
    }
    // Save flags.
//    a.pushf();
//    a.pop_reg64(RAX);
//    a.mov_moffs64_rax(PTR(&(saved.flags)));
    // Save XMM regs.
//    a.mov_reg_imm64(RAX, PTR(saved.xmm_registers));
//    for (int i = XMM0; i <= XMM15; ++i) {
//        a.movdqu_mmm128_mm(mem_2op(static_cast<Register>(i)/*reg*/, RAX/*base*/, NOT_A_REGISTER/*index*/, SCALE_1, (i-XMM0+1)*-16));
//    }

    // Restore RAX (we were using it as scratch) and save its value.
    a.pop_reg64(RAX);
    a.push_reg64(RCX);
    a.mov_reg_imm64(RCX, PTR(&(saved.gp_registers[0])));
    a.mov_rm64_reg(mem_2op_short(RAX, RCX));
    a.pop_reg64(RCX);
}
template <class WriterT>
static void restore_all_regs(Asm::Assembler<WriterT> &a, SavedRegisters &saved, Asm::Register except=Asm::NOT_A_REGISTER)
{
    using namespace Asm;

    // ... using RAX as scratch (it will get restored in a minute).

    // Restore general purpose registers.
    a.mov_reg_imm64(RAX, PTR(saved.gp_registers));
    unsigned i = 1;
    for (; i < sizeof(gp_regs) / sizeof(Register); ++i) {
        if (gp_regs[i] != except)
            a.mov_reg_rm64(mem_2op_short(gp_regs[i], RAX, NOT_A_REGISTER, SCALE_1, i*8));
    }
    // Restore flags register.
//    a.mov_reg_imm64(RAX, PTR(&(saved.flags)));
//    a.push_rm64(reg_1op(RAX));
//    a.popf();
    // Restore XMM registers.
//    a.mov_reg_imm64(RAX, PTR(saved.xmm_registers));
//    for (int i = XMM0; i <= XMM15; ++i) {
//        a.movdqu_mm_mmm128(mem_2op(static_cast<Register>(i)/*reg*/, RAX/*base*/, NOT_A_REGISTER/*index*/, SCALE_1, (i-XMM0+1)*-16));
//    }

    // Restore RAX.
    a.push_reg64(RCX);
    a.mov_reg_imm64(RCX, PTR(&(saved.gp_registers[0])));
    a.mov_reg_rm64(mem_2op_short(RAX, RCX));
    a.pop_reg64(RCX);
}

// Save those registers which
//     (i)  belong to the caller according to the X86-64 ABI.
//     (ii) are used to hold VM registers.
// Returns the number of bytes pushed onto the stack.
template <class WriterT>
static std::size_t save_regs_before_c_funcall(MainLoopState const &mls, Asm::Assembler<WriterT> &a)
{
//    a.emit_save_all_regs();
//    return;

    using namespace Asm;
    std::size_t stack_space_used;
    for (int i = 0; i < NUM_VM_REGS_IN_X86_REGS && i < mls.current_num_vm_registers; ++i) {
//  for (int i = 0; i < sizeof(vm_regs_x86_regs) / sizeof(Register); ++i) {
        if (vm_regs_x86_regs_to_save[i]) {
//      if (true) {
            Register r = vm_regs_x86_regs[i];
            a.push_rm64(reg_1op(r));
            stack_space_used += 8;
//          std::printf("SAVED %s\n", register_name(r));
        }
    }
    a.pushf();

    return stack_space_used;
}
template <class WriterT>
static void restore_regs_after_c_funcall(MainLoopState const &mls, Asm::Assembler<WriterT> &a)
{
//    a.emit_restore_all_regs();
//    return;

    using namespace Asm;
    a.popf();
    for (int i = std::min(static_cast<int>(mls.current_num_vm_registers), static_cast<int>(NUM_VM_REGS_IN_X86_REGS)) - 1; i >= 0; --i) {
//    for (int i = (sizeof(vm_regs_x86_regs) / sizeof(Register)) - 1; i >= 0; --i) {
        if (vm_regs_x86_regs_to_save[i]) {
//        if (true) {
            Register r = vm_regs_x86_regs[i];
            a.pop_rm64(reg_1op(r));
//            std::printf("RESTORED %s\n", register_name(r));
        }
    }
}

template <class WriterT>
static void emit_call(MainLoopState const &mls, Asm::Assembler<WriterT> &a, RegId r, unsigned num_args)
{
    using namespace Asm;

    assert(num_args < MAX_VM_REGS);

    move_vmreg_ptr_to_x86reg(a, RBX, r);
    for (int i = 0; i < NUM_VM_REGS_IN_X86_REGS; ++i) {
        a.push_rm64(reg_1op(vm_regs_x86_regs[i]));
    }
    a.mov_reg_imm64(RDI, num_args);
    a.call_rm64(reg_1op(RBX));
    for (int i = NUM_VM_REGS_IN_X86_REGS; i >=0; --i) {
        a.pop_rm64(reg_1op(vm_regs_x86_regs[i]));
    }
}

template <class WriterT>
static void emit_ret(MainLoopState const &mls, Asm::Assembler<WriterT> &a)
{
    a.ret();
}

template <class WriterT>
static void emit_jump(MainLoopState &mls, Asm::Assembler<WriterT> &a, WriterT &w, Opcode opcode, std::size_t bytecode_offset)
{
    using namespace Asm;

    if (opcode == OP_CJMP) mls.last_instruction_exited = true;

    typedef CountingVectorAssembler::NrDispSetter (CountingVectorAssembler::*jmp_fptr)(Disp<int32_t> const &disp, BranchHint hint);
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
        uint64_t current_addr = w.get_start_addr() + w.size();
        uint64_t target_addr = je->writer->get_start_addr(je->offset);
        int32_t rel = (int32_t)(target_addr - current_addr);
        
        int j;
        for (j = 0; j < sizeof(jmp_fptrs) / sizeof(Pr); ++j) {
            if (jmp_fptrs[j].opcode == opcode) {
                (a.*(jmp_fptrs[j].fptr))(mkdisp<int32_t>(rel, DISP_SUB_ISIZE), jmp_fptrs[j].hint);
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
        call_main_loop_setting_start_to(mls, a, w, bytecode_offset);
    }
}

//
// Layout of a vector:
//     0-3 Number of 64-bit words of memory reserved.
//     4-7 Index of first free element.
//     ... Vector contents.
//
template <class WriterT>
static void emit_mkvec(MainLoopState const &mls,
                       Asm::Assembler<WriterT> &a,
                       WriterT &w,
                       RegId ptr_dest,
                       unsigned type_tag,
                       std::size_t initial_reservation,
                       bool zero_fill)
{
    using namespace Asm;

    // Can't have a vector of vectors or NULLs.
    assert(type_tag != TAG_VECTOR & type_tag != TAG_NULL);
    // Can't zero-fill a vector with no reserved space.
    assert((!zero_fill) || initial_reservation > 0);

    emit_alloc_tagged_mem(mls, a, (initial_reservation * 8) + 8, ptr_dest, TAG_VECTOR, type_tag);
    assert(initial_reservation < (1 << 31));
    // Add size/free pointer info.
    a.mov_reg_imm32(ECX, static_cast<uint32_t>(initial_reservation));
    a.mov_rm32_reg(mem_2op(ECX, RAX));
    a.mov_reg_imm32(ECX, zero_fill ? static_cast<uint32_t>(initial_reservation) - 1 : 0); // If zero-filled, set free pointer to end.
    a.mov_rm32_reg(mem_2op(ECX, RAX, NOT_A_REGISTER/*index*/, SCALE_1, 4));

    // If specified, 0-fill.
    if (zero_fill) {
        // The untagged address of the buffer will still be in RAX.
        a.mov_reg_imm64(RBX, 0); // Index counter.
        // **** TODO ***** MAKE SURE TO SAVE VALUE OF R?? (WHICH IS THE SAME AS XMM0) IF NECESSARY.
        a.pxor_mm_mmm128(reg_2op(XMM0, XMM0)); // XOR XMM0 with itself to ensure that it's 0.
        std::size_t loop_start = w.size();
        a.movdqa_mmm128_mm(mem_2op(XMM0/*reg*/, RAX/*base*/, RBX/*index*/, SCALE_1));
        a.add_rm64_imm8(reg_1op(RBX), 16);
        a.cmp_rm64_imm32(reg_1op(RBX), (initial_reservation*8)-15);
        std::size_t loop_end = w.size();
        a.jl_st_rel8(mkdisp(static_cast<int8_t>(loop_start-loop_end), DISP_SUB_ISIZE));

        // If the buffer size isn't a multiple of 16 (bytes), we'll need to fill the 8
        // remaining bytes at the end.
#ifdef DEBUG
        unsigned remaining_bytes = initial_reservation % 16;
        assert(remaining_bytes == 0 || remaining_bytes == 8);
#endif
        if (initial_reservation % 16 != 0)
            a.movq_mmm64_mm(mem_2op(MM0/*reg*/, RAX/*base*/, RBX/*index*/, SCALE_1));
    }
}

template <class WriterT>
static void emit_refvec(MainLoopState const &mls, Asm::Assembler<WriterT> &a, RegId ptr_array, RegId ptr_index)
{
    
}

static void print_vm_reg(RegId rid, uint64_t tagged_ptr)
{
    uint64_t tag = tagged_ptr & TAG_MASK;
    std::printf("- REGISTER: %i\n- TAG:      %lli (%s)\n", (int)rid, tag, tag_name(tag));
    std::printf("- STORAGE:  ");
    if (vm_reg_is_in_x86reg(rid)) {
        std::printf("x86 reg %s\n", Asm::register_name(RegId_to_x86reg(rid)));
    }
    else {
        std::printf("mem at disp 0x%x\n", static_cast<int>(RegId_to_disp(rid)));
    }

    if (tag == TAG_INT) {
        std::printf("- PTR:      0x%llx\n", (unsigned long long)tagged_ptr);
        std::printf("- VALUE:    %lli\n\n", *((long long *)(tagged_ptr & 0xFFFFFFFFFFFFFFFC)));
    }
    else assert(false);
}
template <class WriterT>
static void emit_debug_printreg(MainLoopState const &mls, Asm::Assembler<WriterT> &a, RegId r)
{
    using namespace Asm;

    std::size_t offset = save_regs_before_c_funcall(mls, a);
    a.mov_reg_imm32(EDI, static_cast<uint32_t>(r));
    move_vmreg_ptr_to_guaranteed_x86reg(a, RSI, r, offset);
    a.mov_reg_imm64(RBX, PTR(print_vm_reg));
    a.mov_reg_imm32(EAX, 0);
    a.call_rm64(reg_1op(RBX));
    restore_regs_after_c_funcall(mls, a);
}

static void sayhi() { std::printf("HI\n"); }
template <class WriterT>
static void emit_debug_sayhi(MainLoopState const &mls, Asm::Assembler<WriterT> &a)
{
    using namespace Asm;

    save_regs_before_c_funcall(mls, a);
    a.mov_reg_imm64(RBX, PTR(sayhi));
    a.mov_reg_imm32(EAX, 0);
    a.call_rm64(reg_1op(RBX));
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

    a.mov_reg_imm64(RBX, PTR(&var));
    a.mov_reg_imm64(RAX, tf ? 1 : 0);
    ASM<WriterT, sizeof(bool)*8>::mov_rmX_reg(a, mem_2op(RAX, RBX));
}

// This could just be inline ASM, but since we already have an assembler,
// we may as well do it without making use of compiler-specific extensions.
#define GET_BASE_POINTER_AND_STACK_POINTER(bp_var, sp_var) \
    do { \
        using namespace Asm; \
        VectorWriter bpw__; \
        VectorAssembler bpa__(bpw__); \
        bpa__.mov_reg_imm64(RBX, PTR(&(bp_var))); \
        bpa__.mov_rm64_reg(mem_2op(RBP, RBX)); \
        bpa__.mov_reg_imm64(RBX, PTR(&(sp_var))); \
        bpa__.mov_rm64_reg(mem_2op(RSP, RBX)); \
        bpa__.ret(); \
        bpw__.get_exec_func()(); \
    } while (0)

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
    a.mov_reg_imm64(RBX, PTR(inner_main_loop));
    a.mov_reg_imm64(RDI, PTR(&mls));
    a.mov_reg_imm64(RAX, 0);
    a.call_rm64(reg_1op(RBX));
}

static uint64_t get_64(std::vector<uint8_t>::const_iterator i)
{
#define C(x) static_cast<uint64_t>(x)
    return i[0] + (C(i[1]) << 8) + (C(i[2]) << 16) +
           (C(i[3]) << 24) + (C(i[4]) << 32) +
           (C(i[5]) << 40) + (C(i[6]) << 48) +
           (C(i[7]) << 56);
#undef C
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

    mls.last_instruction_exited = false;
    std::vector<uint8_t>::const_iterator i;
    for (i = mls.instructions.begin() + mls.start;
         i != mls.instructions.end() && i - mls.instructions.begin() - mls.start < mls.BLOB_SIZE*4;
         i += 4) {
        assert(i + 3 < mls.instructions.end());

        mls.last_instruction_exited = false;

        // If this bit of the code is jumped to, cache the location of the generated assembly.
        if (i[3] & FLAG_DESTINATION >> 24)
            mls.ab.mark_bytecode(e, &*i);

        switch (*i) {
            case OP_NULL: assert(false);
            case OP_EXIT: {
                mls.last_instruction_exited = true;
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
                emit_ldi(mls, *a, i[1], get_64(i + 4));
                i += 8;
            } break;
            case OP_CMP: {
                emit_cmp(*a, i[1], i[2]);
            } break;
            case OP_IADD: {
                emit_iadd(mls, *a, *w, i[1], i[2]);
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
                emit_jump(mls, *a, *w, static_cast<Opcode>(*i), i[1] + ((std::size_t)i[2] << 8));
            } break;
            case OP_MKIVEC0:
            case OP_MKIVECD:
            case OP_MKIVEC: {
                std::size_t initial_reservation = 0;
                if (*i == OP_MKIVECD)
                    initial_reservation = 10;
                else if (*i == OP_MKIVEC) {
                    initial_reservation = get_64(i + 4);
                    i += 8;
                }
                    
                emit_mkvec(mls, *a, *w, i[1], TAG_INT, initial_reservation, (bool)(i[2]));
            } break;
            default: assert(false);
        }
#ifdef DEBUG
        a->nop();
#endif
    }

    if (! mls.last_instruction_exited)
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

    mls.type_error_handler = type_error_handler;

    mls.type_error_handler_asm = gen_type_error_handler_asm<Asm::VectorWriter>(mls);

    GET_BASE_POINTER_AND_STACK_POINTER(mls.initial_base_pointer_for_main_loop,
                                       mls.initial_stack_pointer_for_main_loop);

    return inner_main_loop(mls);
}
