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
    OP_JG      = 12,
    OP_JL      = 13,

    OP_IADD    = 14,
    OP_IMUL    = 15,
    OP_IDIV    = 16,

    OP_MKVEC   = 17,
    OP_REVEC   = 18,
    OP_REFVEC  = 19,
    OP_SETVEC  = 20,

    OP_DEBUG_PRINTREG = 21
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
extern const unsigned TAG_DOUBLE;
extern const unsigned TAG_VECTOR;

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

        bool operator<(Entry const &e) const;
        bool operator==(Entry const &e) const;
        Entry &operator=(Entry const &e);
    };

    typedef std::map<uint8_t const *, boost::shared_ptr<Entry> >::iterator MapIt;
    typedef std::map<uint8_t const *, boost::shared_ptr<Entry> >::const_iterator ConstMapIt;

    VectorAssemblerBroker(const std::size_t MAX_BYTES);

    std::size_t size();
    Entry const &get_writer_assembler_for(uint8_t const *bytecode);
    uint64_t get_asm_code_addr_for(uint8_t const *bytecode);
    void mark_bytecode(Entry const &e, uint8_t const *bytecode_addr);
    Entry const *known_to_be_local(uint8_t const *bytecode_addr1, uint8_t const *bytecode_addr2);

private:
    std::map<uint8_t const *, boost::shared_ptr<Entry> > items;
    std::map<boost::shared_ptr<Entry>, uint8_t const *> reverse_items;
    const std::size_t MAX_BYTES;
    std::size_t current_size;
};

uint64_t main_loop(std::vector<uint8_t> &instructions, std::size_t start, const std::size_t BLOB_SIZE=20);

}

#endif
