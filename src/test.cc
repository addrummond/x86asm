#include <cassert>
#include <asm.hh>
#include <cstdio>
#include <iostream>
#include <util.hh>

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

    // This test also includes some machinary unnecessary for a 0-argument
    // void function (saving the base pointer and then restoring it via LEAVE).

    // PUSH RBP
    a.push_reg(RBP);
    // MOV RBP, RSP
    a.mov_reg_reg(RBP, RSP);
    // MOV RAX, 2
    a.mov_reg_imm64(RAX, 1);
    // MOV RDX, 2
    a.mov_reg_imm64(RDX, 2);
    // IMUL RAX, RDX // {RAX now contains 4}
    a.imul_reg_rm64(reg_ModrmSib(RAX, RDX));
    a.imul_reg_rm64(reg_ModrmSib(RAX, RDX));
    // MOV RDX, RAX
    a.mov_reg_reg(RDX, RAX);
    // INC RDX
    a.inc_reg64(RDX);
    // MOV RAX, RDX {could have used mov_reg_reg here instead}
    a.mov_rm64_reg(reg_ModrmSib(RDX, RAX));
    // MOV RBX, [imm64 -- address of 'foo']
    a.mov_reg_imm64(RBX, ptr(&foo));
    // MOV [RBX], RDX
    a.mov_rm64_reg(mem_ModrmSib2op(RDX, RBX));
    // MOV RAX, [imm64 -- address of 'bar']
    a.mov_moffs64_rax(ptr(&bar));
    // MOV RBX, [imm64 -- address of (first element of) 'foobar']
    a.mov_reg_imm64(RBX, ptr(foobar));
    // MOV RCX, 1
    a.mov_reg_imm64(RCX, 1);
    // MOV [RBX+(RCX*8)+8], RDX // {Unnecessarily complex method of accessing second element of foobar}
    a.mov_rm64_reg(mem_ModrmSib2op(RDX, RBX, RCX, SCALE_8, 8));
    // ADD [RBX+(RCX*8)+8], 340
    a.add_rm64_imm32(mem_ModrmSib1op(RBX, RCX, SCALE_8, 8), 340);
    // INC RCX
    a.inc_reg64(RCX);
    // ADD [RBX+(RCX*8)], 5 // {Now that RCX has been incremented, we no longer need to add a displacement}
    a.add_rm32_imm32(mem_ModrmSib1op(RBX, RCX, SCALE_8, 0), 5);
    // SUB [RBX+(RCX*8)], 5
    a.sub_rm64_imm32(mem_ModrmSib1op(RBX, RCX, SCALE_8, 0), 5);
    // DEC RCX
    a.dec_reg64(RCX);
    // SUB [RBX+(RCX*8)], 5
    a.sub_rm64_imm32(mem_ModrmSib1op(RBX, RCX, SCALE_8, 0), 5);
    // LEAVE
    a.leave();
    // RET
    a.ret();

    w.debug_print();   
    w.get_exec_func()();

    std::printf("TEST 1: foo = 0x%llx, bar = 0x%llx, foobar[1] = 0x%llx, foobar[2] = 0x%llx\n", foo, bar, foobar[1], foobar[2]);
    assert(foo == 5 && bar == 5 && foobar[1] == -5 && foobar[2] == 345);
    std::printf("* OK\n\n");
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
    std::printf("* OK\n\n");
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
    a.imul_reg_rm64(reg_ModrmSib(RDX, RCX));
    a.inc_reg64(RAX);
    a.cmp_rax_imm32(5);
    std::size_t s2 = w.size();
    // Using an explicitly constructed Disp<int8_t> to ensure that the size of the JL
    // instruction is subtracted from the (negative) jump offset.
    a.jl_st_rel8(mkdisp(static_cast<int8_t>(-(s2-s1)), DISP_SUB_ISIZE), BRANCH_HINT_TAKEN);

    // Move the value of RDX into val (not quite the simplest way, but good to
    // give MOV a bit of a workout).
    a.mov_reg_imm64(RAX, ptr(&val));
    a.mov_rm64_reg(mem_ModrmSib2op(RDX, RAX));

    a.ret();

    w.debug_print();
    w.get_exec_func()();

    std::printf("TEST 3: val = 0x%llx\n", val);
    assert(val == 0x20);
    std::printf("* OK\n\n");
}

//
// Loops and tests a few floating point operations.
// (A lot of the back-and-forth between registers and memory is unnecessary,
// but useful for testing.)
//
void test4()
{
    long double fval = 1.0;
    int64_t integer_two = 2;
    long double double_hundred = 100.0;
    double double_point_3 = 0.3;

    VectorWriter w;
    VectorAssembler a(w);

    // Code in loop.
    std:size_t loop_start = w.size();
    // Load fval into the first FP reg.
    a.mov_reg_imm64(RCX, ptr(&fval));
    a.fld_m80fp(mem_ModrmSib1op(RCX));
    // Multiply this value by (integer) 2.
    a.mov_reg_imm64(RCX, ptr(&integer_two));
    a.fimul_st0_m32int(mem_ModrmSib1op(RCX));
    // Divide this value by 0.3
    a.mov_reg_imm64(RCX, ptr(&double_point_3));
    a.fdiv_st0_m64fp(mem_ModrmSib1op(RCX));
    // Compare the result to 100.
    a.mov_reg_imm64(RCX, ptr(&double_hundred));
    a.fld_m80fp(mem_ModrmSib1op(RCX));
    a.fcomp_st0_st(1);
    // Put the result back in 'fval'.
    a.mov_reg_imm64(RCX, ptr(&fval));
    a.fstp_m80fp_st0(mem_ModrmSib1op(RCX));
    std::size_t loop_end = w.size();

    // Loop if 'fval' is less than 100.
    a.ja_st_rel8(mkdisp(static_cast<int8_t>(-(loop_end-loop_start)), DISP_SUB_ISIZE), BRANCH_HINT_TAKEN);

    a.ret();

    w.debug_print();
    w.get_exec_func()();

    // C code to compute the same value as the ASM above.
    long double c_fval = 1.0;
    do {
        c_fval *= integer_two;
        c_fval /= double_point_3;
    } while (double_hundred > c_fval);

    std::printf("TEST 4: fval = %Lf, c_fval = %Lf\n", fval, c_fval);
    assert(c_fval == fval);
    std::printf("* OK\n\n");
}

//
// Call to printf from ASM.
//
void test5()
{
    char const *fstring = "A number %llx and a string %s (printed if 'printf' called successfully).\n";
    char const *astring = "A STRING";
    int ret;

    VectorWriter w;
    VectorAssembler a(w);

    a.push_reg(RBP); // Function preamble (unnecessary since this func doesn't take any args).
    a.mov_reg_reg(RBP, RSP);

    // <<<<< start of args passed in registers (= all of them).
    a.mov_reg_imm64(RDI, ptr(fstring));
    a.mov_reg_imm64(RSI, 15);
    a.mov_reg_imm64(RDX, ptr(astring));
    // end of args passed in registers >>>>>
    a.mov_reg_imm64(RCX, ptr(printf));
    a.mov_reg_imm32(EAX, 0);
    a.call_rm64(reg_ModrmSib(RCX));
    // Move the return value in EAX into the 'ret' var.
    a.mov_reg_imm64(RCX, ptr(&ret));
    a.mov_rm32_reg(mem_ModrmSib2op(EAX, RCX));
    // Clear EAX.
    a.mov_reg_imm32(EAX, 0);

    a.leave();
    a.ret();
    
    w.debug_print();
    w.get_exec_func()();

    std::printf("CHARACTERS PRINTED: %i\n", ret);
    assert(ret == 76);
    std::printf("* OK\n");
}

int main()
{
    test1();
    test2();
    test3();
    test4();
    test5();

    return 0;
}
