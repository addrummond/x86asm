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
    OP_CALL    = 7,
    OP_RET     = 8,
    OP_CMP     = 9,
    OP_JE      = 10,
    OP_JG      = 11,
    OP_JL      = 12,

    OP_IADD    = 13,
    OP_IMUL    = 14,
    OP_IDIV    = 15,

    OP_MKVEC   = 16,
    OP_REVEC   = 17,
    OP_REFVEC  = 18,
    OP_SETVEC  = 19,

    OP_DEBUG_PRINTREG = 20
};
extern const Opcode FIRST_OP;

enum Operand {
    OPR_NULL,
    OPR_IMM16,
    OPR_IMM64,
    OPR_REGISTER,
    OPR_FLAGS
};

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

    typedef std::map<uint8_t *, boost::shared_ptr<Entry> >::iterator MapIt;
    typedef std::map<uint8_t *, boost::shared_ptr<Entry> >::const_iterator ConstMapIt;

    VectorAssemblerBroker(const std::size_t MAX_BYTES);

    std::size_t size();
    Entry const &get_writer_assembler_for(uint8_t *bytecode);

    void mark_bytecode(Entry const &e, uint8_t *bytecode_addr);

private:
    std::map<uint8_t *, boost::shared_ptr<Entry> > items;
    std::map<boost::shared_ptr<Entry>, uint8_t *> reverse_items;
    const std::size_t MAX_BYTES;
    std::size_t current_size;
};

uint64_t main_loop(std::vector<uint8_t> &instructions, std::size_t start, const std::size_t BLOB_SIZE=20);
uint64_t main_loop_debug(std::vector<uint8_t> &instructions, std::size_t start, const std::size_t BLOB_SIZE=20);

}

#endif
