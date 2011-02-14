#ifndef VM_HH
#define VM_HH

#include <cstddef>
#include <string>
#include <vector>
#include <asm.hh>
#include <boost/shared_ptr.hpp>

namespace Vm {

enum Opcode {
    OP_NULL    = 0,

    OP_EXIT    = 1,

    OP_INCRW   = 2,
    OP_DECRW   = 3,
    OP_LDI16   = 4,
    OP_LDI64   = 5,

    OP_JMP     = 6,
    OP_CJMP    = 7,
    OP_CALL    = 8,
    OP_RET     = 9,
    OP_CMP     = 10,
    OP_JE      = 11,
    OP_CJE     = 12,
    OP_JNE     = 13,
    OP_CJNE    = 14,
    OP_JG      = 15,
    OP_CJG     = 16,
    OP_JL      = 17,
    OP_CJL     = 18,

    OP_IADD    = 19,
    OP_ISUB    = 20,
    OP_IMUL    = 21,
    OP_IDIV    = 22,

    OP_MKIVEC0  = 23,
    OP_MKIVECD  = 24,
    OP_MKIVEC   = 25,
    OP_REFIVEC  = 26,
    OP_SETIVEC  = 27,

    OP_DEBUG_PRINTREG = 28,
    OP_DEBUG_SAYHI = 29
};
extern const Opcode FIRST_OP;

enum Operand {
    OPR_NULL,
    OPR_IMM16,
    OPR_IMM64,
    OPR_REGISTER,
    OPR_FLAGS
};

// Flags which may be OR'd with any instruction.
extern const uint32_t FLAG_DESTINATION; // Hint that jumps go here.

typedef uint8_t RegId;
extern const unsigned MAX_REG_ID;

extern const unsigned TAG_INT;
extern const unsigned TAG_BOOl;
extern const unsigned TAG_DOUBLE;
extern const unsigned TAG_VECTOR;
extern const unsigned TAG_NULL;

extern const unsigned TAG_MASK;

char const *tag_name(unsigned tag);
char const *op_name(Opcode o);
Operand const *op_operands(Opcode o);
Opcode op_code_by_name(std::string const &name);
uint32_t make_instruction(Opcode opcode);
uint32_t make_rop_instruction(Opcode opcode, RegId reg1, RegId reg2=0, RegId reg3=0);
uint32_t make_imm24_instruction(Opcode opcode, uint32_t immediate);

bool parse_vm_asm(std::string const &input, std::vector<uint8_t> &instructions, std::string &emsg);

class VectorAssemblerBroker {
public:
    struct Entry {
        Entry();
        Entry(Entry const &entry);
        Entry(Asm::CountingVectorWriter *writer, Asm::CountingVectorAssembler *assembler, int64_t offset);

        Asm::CountingVectorWriter *writer;
        Asm::CountingVectorAssembler *assembler;
        int64_t offset; // Offset into the generated assembly corresponding to the bytecode position.
    };

    struct AlwaysDelete {
        bool operator()(Entry const &entry) { return true; }
    };

    typedef std::map<uint8_t const *, boost::shared_ptr<Entry> >::iterator MapIt;
    typedef std::map<uint8_t const *, boost::shared_ptr<Entry> >::const_iterator ConstMapIt;

    VectorAssemblerBroker(const std::size_t MAX_BYTES);

    std::size_t size();
    template <class FuncT>
    Entry const &get_writer_assembler_for(uint8_t const *bytecode, FuncT deletion_criterion=AlwaysDelete());
    uint64_t get_asm_code_addr_for(uint8_t const *bytecode);
    void mark_bytecode(Entry const &e, uint8_t const *bytecode_addr);
    Entry const *known_to_be_local(uint8_t const *bytecode_addr1, uint8_t const *bytecode_addr2);

private:
    Entry const &simple_get_writer_assembler_for(uint8_t const *bytecode);

    std::map<uint8_t const *, boost::shared_ptr<Entry> > items;
    std::map<boost::shared_ptr<Entry>, uint8_t const *> reverse_items;
    const std::size_t MAX_BYTES;
    std::size_t current_size;
};

uint64_t main_loop(std::vector<uint8_t> &instructions, std::size_t start, const std::size_t BLOB_SIZE=20);

}

#endif
