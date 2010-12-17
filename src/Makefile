LDFLAGS_=$(LDFLAGS)
INCLUDES_=-I./ $(INCLUDES)
CXX=g++
CXXFLAGS_=-arch x86_64 -Wall $(CXXFLAGS)

INVOKECXX=$(CXX) $(CXXFLAGS_) $(INCLUDES_)

mremap.o: mremap.cc mremap.hh
	$(INVOKECXX) -c mremap.cc -o mremap.o

util.o: util.hh util.cc
	$(INVOKECXX) -c util.cc -o util.o

asm.o: asm.cc asm.hh mremap.o util.o
	$(INVOKECXX) -c asm.cc -o asm.o

asm_test.o: mremap.o asm.o asm_test.cc
	$(INVOKECXX) -c asm_test.cc -o asm_test.o

asm_test: asm_test.o
	$(INVOKECXX) asm.o mremap.o asm_test.o util.o -o asm_test

vm.o: vm.cc vm.hh asm.o mremap.o
	$(INVOKECXX) -c vm.cc -o vm.o

vm_test.o: vm.o vm_test.cc util.o
	$(INVOKECXX) -c vm_test.cc -o vm_test.o

vm_test: vm_test.o
	$(INVOKECXX) vm.o vm_test.o util.o asm.o mremap.o -o vm_test

clean:
	rm *_test ; rm *.o