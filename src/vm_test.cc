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

static uint64_t test_code(const char *code, std::size_t blob_size)
{
    std::vector<uint8_t> instructions;
    parse_or_die(code, instructions);
    Util::debug_hex_print(&instructions[0], instructions.size());

    return Vm::main_loop(instructions, 0, blob_size);
}

//
// Simple loading.
//
void test1()
{
    const char *code =
        " INCRW 2"
        " LDI64 1 2"
        " LDI16 2 3"
        " DEBUG_PRINTREG 1"
        " DEBUG_PRINTREG 1"
        " EXIT 1";

    uint64_t rval = test_code(code, 2 /*small BLOB_SIZE to maximize chance of triggering bugs*/);
    assert(rval != 0);
    uint64_t rvali = *((uint64_t*)rval);
    std::printf("TEST1: rval=%lli\n", rvali);
    assert(rvali == 2);
    std::printf("* OK\n\n");
}

//
// Simple loading/addition.
// 
void test2()
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

    uint64_t rval = test_code(code, 2 /*small BLOB_SIZE to maximize chance of triggering bugs*/);
    assert(rval != 0);
    uint64_t rvali = *((uint64_t*)rval);
    std::printf("TEST2: rval=%lli\n", rvali);
    assert(rvali == 5);
    std::printf("* OK\n\n");
}

//
// Infinite loop.
//
void test3()
{
    const char *code =
        "  INCRW 2"
        "  LDI16 1 0"
        "  LDI16 2 1"
        " >IADD 1 2"
        "  DEBUG_PRINTREG 1"
        "  CJMP 12"
        ;

    uint64_t rval = test_code(code, 100);
}

//
// Counting loop.
//
void test4()
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

    uint64_t rval = test_code(code, 100);
    assert(rval != 0);
    uint64_t rvali = *((uint64_t*)rval);
    std::printf("TEST4: rval=%lli\n", rvali);
    assert(rvali == 3);
    std::printf("* OK\n\n");
}

//
// A simple incrementing loop. If compilation is working properly,
// this shouldn't take any perceptible amount of time.
//
void test5()
{
    const char *code =
        "  INCRW 3"           // 0
        "  LDI16 1 1"         // 4  Counter.
        "  LDI16 2 1"         // 8  Increment.
        "  LDI64 3 20000000"  // 12 The loop will go round this many times.
        " >IADD 1 2"          // 24 [LDI64 takes up 12 bytes]
        "  CMP 1 3"           // 28
        "  CJNE 24"           // 32
        "  DEBUG_SAYHI"       // 36
        "  EXIT 1";           // 40

    uint64_t rval = test_code(code, 100);
    assert(rval != 0);
    uint64_t rvali = *((uint64_t*)rval);
    std::printf("TEST 5: rval=%lli\n", rvali);
    assert(rvali == 20000000);
    std::printf("* OK\n\n");
}

void test6()
{
     char const *code =
         "  INCRW 20"
         "  LDI16 1 2"
         "  LDI16 2 4"
         "  LDI16 3 6"
         "  LDI16 4 8"
         "  LDI16 5 10"
         "  LDI16 6 12"
         "  LDI16 7 14"
         "  LDI16 8 16"
         "  LDI16 9 18"
         "  LDI16 10 20"
         "  LDI16 11 22"
         "  LDI16 12 24"
         "  LDI16 13 26"
         "  LDI16 14 28"
         "  LDI16 15 30"
         "  LDI16 16 32"
         "  LDI16 17 34"
         "  LDI16 18 36"
         "  LDI16 19 38"
         "  LDI16 20 40"
         "  DEBUG_PRINTREG 1"
         "  DEBUG_PRINTREG 2"
         "  DEBUG_PRINTREG 3"
         "  DEBUG_PRINTREG 4"
         "  DEBUG_PRINTREG 5"
         "  DEBUG_PRINTREG 6"
         "  DEBUG_PRINTREG 7"
         "  DEBUG_PRINTREG 8"
         "  DEBUG_PRINTREG 9"
         "  DEBUG_PRINTREG 13"
         "  DEBUG_PRINTREG 17"
         "  EXIT 20";

     uint64_t rval = test_code(code, 100);
     assert(rval != 0);
     uint64_t rvali = *((uint64_t*)rval);
     std::printf("TEST 6: rval=%lli\n", rvali);
     assert(rvali == 40);
     std::printf("* OK\n\n");
}

int main()
{
    test1();
    test2();
//    test3(); // NOT RUN BY DEFAULT AS IT IS AN INFINITE LOOP.
    test4();
    test5();
    test6();

    return 0;
}
