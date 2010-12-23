#include <vm.hh>
#include <cassert>
#include <iostream>
#include <util.hh>
#include <cstdlib>

using namespace Asm;
using namespace Vm;

static void parse_or_die(const char *code, std::vector<uint8_t> &instructions)
{
    std::string emsg;
    if (! parse_vm_asm(code, instructions, emsg)) {
        std::cout << emsg << "\n";
        std::exit(1);
    }
}

//
// Simple loading/addition.
// 
void test1()
{
    const char *code =
        " INCRW 2"
        " LDI64 1 2"
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
        "  INCRW 2"
        "  LDI16 1 0"
        "  LDI16 2 1"
        " >IADD 1 2"
        "  DEBUG_PRINTREG 1"
        "  CJMP 12"
        ;

    std::vector<uint8_t> instructions;
    parse_or_die(code, instructions);
    Util::debug_hex_print(&instructions[0], instructions.size());

    uint64_t rval = Vm::main_loop(instructions, 0, 100);
}

//
// Counting loop.
//
void test3()
{
    const char *code =
        "  INCRW 3"
        "  LDI16 1 1"  // Counter.
        "  LDI16 2 1"  // Increment.
        "  LDI16 3 3"  // The loop will go round 3 times.
        " >IADD 1 2"
        "  DEBUG_PRINTREG 1"
        "  CMP 1 3"
        "  CJNE 16"
        "  EXIT 1";

    std::vector<uint8_t> instructions;
    parse_or_die(code, instructions);
    Util::debug_hex_print(&instructions[0], instructions.size());

    uint64_t rval = Vm::main_loop(instructions, 0, 100);
    assert(rval != 0);
    uint64_t rvali = *((uint64_t*)rval);
    std::printf("TEST3: rval=%lli\n", rvali);
    assert(rvali == 3);
    std::printf("* OK\n\n");
}

//
// A simple incrementing loop. If compilation is working properly,
// this shouldn't take any perceptible amount of time.
//
void test4()
{
    const char *code =
        "  INCRW 3"
        "  LDI16 1 1" // Counter.
        "  LDI16 2 1" // Increment.
        "  LDI64 3 20000000"  // The loop will go round this many times.
        "  >IADD 1 2"
        "  CMP 1 3"
        "  CJNE 24"
        "  DEBUG_SAYHI"
        "  EXIT 1";

    std::vector<uint8_t> instructions;
    parse_or_die(code, instructions);
    Util::debug_hex_print(&instructions[0], instructions.size());

    uint64_t rval = Vm::main_loop(instructions, 0, 100);
    assert(rval != 0);
    uint64_t rvali = *((uint64_t*)rval);
    std::printf("TEST 4: rval=%lli\n", rvali);
    assert(rvali == 20000000);
    std::printf("* OK\n\n");
}

int main()
{
    test1();
    test2(); // NOT RUN BY DEFAULT AS IT IS AN INFINITE LOOP.
//    test3();
    test4();

    return 0;
}
