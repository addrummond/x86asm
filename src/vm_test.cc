#include <vm.hh>
#include <cassert>
#include <iostream>
#include <util.hh>

using namespace Asm;
using namespace Vm;

static void parse_or_die(const char *code, std::vector<uint8_t> &instructions)
{
    std::string emsg;
    if (! parse_vm_asm(code, instructions, emsg)) {
        std::cout << emsg;
        assert(false);
    }
}

//
// Simple loading/addition.
// 
void test1()
{
    const char *code =
        " INCRW 2"
        " LDI16 1 2"
        " DEBUG_PRINTREG 1"
        " LDI16 2 3"
        " IADD 1 2"
        " DEBUG_PRINTREG 1"
        " EXIT 1"
        ;

    std::vector<uint8_t> instructions;
    parse_or_die(code, instructions);
    Util::debug_hex_print(&instructions[0], instructions.size());

    uint64_t rval = Vm::main_loop(instructions, 0, 2 /*small BLOB_SIZE to maximize chance of triggering bugs*/);
    assert(rval != 0);
    uint64_t rvali = *((uint64_t*)rval);
    std::printf("TEST1: rval=%lli\n", rvali);
    assert(rvali == 5);
    std::printf("* OK\n\n");
}

//
// Infinite loop.
//
void test2()
{
    const char *code =
        "  LDI16 1 0"
        "  LDI16 2 1"
        " >IADD 1 2"
        "  DEBUG_PRINTREG 1"
        "  CJMP 8"
        ;

    std::vector<uint8_t> instructions;
    parse_or_die(code, instructions);
    Util::debug_hex_print(&instructions[0], instructions.size());

    uint64_t rval = Vm::main_loop(instructions, 0, 100);
}

int main()
{
    test1();
//    test2(); // NOT RUN BY DEFAULT AS IT IS AN INFINITE LOOP.

    return 0;
}
