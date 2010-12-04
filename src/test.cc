#include <cassert>
#include <asm.hh>
#include <cstdio>
#include <iostream>

using namespace Asm;

template <class T>
uint64_t Asm::ptr(T *p) { return reinterpret_cast<uint64_t>(p); }

//
// Tests MOV, INC, DEC, ADD, SUB and IMUL.
//
void test1()
{
    int64_t foo = 0;
    int64_t bar = 0;
    int64_t foobar[3] = { 0, 0, 0 };

    VectorWriter w;
    VectorAssembler a(w);

    // Assembly commented line-by-line in this test only as an example.

    // MOV RAX, 2
    a.mov_reg_imm64(RAX, 1);
    // MOV RDX, 2
    a.mov_reg_imm64(RDX, 2);
    // IMUL RAX, RDX // {RAX now contains 4}
    a.imul_reg_rm(reg_ModrmSib(RAX, RDX));
    a.imul_reg_rm(reg_ModrmSib(RAX, RDX));
    // MOV RDX, RAX
    a.mov_reg_reg(RDX, RAX);
    // INC RDX
    a.inc_reg(RDX);
    // MOV RAX, RDX {could have used mov_reg_reg here instead}
    a.mov_rm_reg(reg_ModrmSib(RDX, RAX));
    // MOV RBX, [imm64 -- address of 'foo']
    a.mov_reg_imm64(RBX, ptr(&foo));
    // MOV [RBX], RDX
    a.mov_rm_reg(mem_ModrmSib2op(RDX, RBX));
    // MOV RAX, [imm64 -- address of 'bar']
    a.mov_moffs64_rax(ptr(&bar));
    // MOV RBX, [imm64 -- address of (first element of) 'foobar']
    a.mov_reg_imm64(RBX, ptr(foobar));
    // MOV RCX, 1
    a.mov_reg_imm64(RCX, 1);
    // MOV [RBX+(RCX*8)+8], RDX // {Unnecessarily complex method of accessing second element of foobar}
    a.mov_rm_reg(mem_ModrmSib2op(RDX, RBX, RCX, SCALE_8, 8));
    // ADD [RBX+(RCX*8)+8], 340
    a.add_rm64_imm32(mem_ModrmSib1op(RBX, RCX, SCALE_8, 8), 340);
    // INC RCX
    a.inc_reg(RCX);
    // ADD [RBX+(RCX*8)], 5 // {Now that RCX has been incremented, we no longer need to add a displacement}
    a.add_rm32_imm32(mem_ModrmSib1op(RBX, RCX, SCALE_8, 0), 5);
    // SUB [RBX+(RCX*8)], 5
    a.sub_rm64_imm32(mem_ModrmSib1op(RBX, RCX, SCALE_8, 0), 5);
    // DEC RCX
    a.dec_reg(RCX);
    // SUB [RBX+(RCX*8)], 5
    a.sub_rm64_imm32(mem_ModrmSib1op(RBX, RCX, SCALE_8, 0), 5);
    // RET
    a.ret();

    w.debug_print();   
    w.get_exec_func()();

    std::printf("TEST 1: foo = 0x%llx, bar = 0x%llx, foobar[1] = 0x%llx, foobar[2] = 0x%llx\n", foo, bar, foobar[1], foobar[2]);
    assert(foo == 5 && bar == 5 && foobar[1] == -5 && foobar[2] == 345);
    std::printf("* OK\n");
}

//
// Tests CMP followed by a JNZ.
//
void test2()
{
    int64_t val = 1;

    VectorWriter w;
    VectorAssembler a(w);

    // Set RAX to 1. Compare RAX with 101. Jump over an instruction
    // setting RAX to 2. Copy value of RAX into 'val'; should = 1.

    a.mov_reg_imm64(RAX, 1);
    a.cmp_rm64_imm8(reg_ModrmSib(RAX), 101);

    VectorWriter w2;
    VectorAssembler a2(w2);
    a2.mov_reg_imm64(RAX, 2);

    a.jnz_st_rel8(static_cast<int8_t>(w2.size()));
    w.a(w2);

    a.mov_moffs64_rax(ptr(&val));
    a.ret();

    w.debug_print();

    std::printf("TEST 2: val = 0x%llx\n", val);
    assert(val == 1);
    std::printf("* OK\n");
}

//
// A simple loop.
//
void test3()
{
    int64_t val;

    VectorWriter w;
    VectorAssembler a(w);

    a.mov_reg_imm64(RDX, 1); // Value to be doubled on each iteration.
    a.mov_reg_imm64(RAX, 0); // Loop counter.
    
    // Code in loop.
    std::size_t s1 = w.size();
    a.mov_reg_imm64(RCX, 2);
    a.imul_reg_rm(reg_ModrmSib(RDX, RCX));
    a.inc_reg(RAX);
    a.cmp_rax_imm32(5);
    std::size_t s2 = w.size();
    // Using an explicitly constructed Disp<int8_t> to ensure that the size of the JL
    // instruction is subtracted from the (negative) jump offset.
    a.jl_st_rel8(mkdisp(static_cast<int8_t>(-(s2-s1)), DISP_SUB_ISIZE), BRANCH_HINT_TAKEN);

    // Move the value of RDX into val (not quite the simplest way, but good to
    // give MOV a bit of a workout).
    a.mov_reg_imm64(RAX, ptr(&val));
    a.mov_rm_reg(mem_ModrmSib2op(RDX, RAX));

    a.ret();

    w.debug_print();
    w.get_exec_func()();

    std::printf("TEST 3: val = 0x%llx\n", val);
    assert(val == 0x20);
    std::printf("* OK\n");
}

int main()
{
    test1();
    test2();
    test3();

    return 0;
}
