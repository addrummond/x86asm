BOOST_HEADERS_INCLUDES=-I/usr/include/boost

LDFLAGS_=$(LDFLAGS)
INCLUDES_=-I./ $(BOOST_HEADERS_INCLUDES) $(INCLUDES)
CXX=g++
CXXFLAGS_=-arch x86_64 $(CXXFLAGS)

INVOKECXX=$(CXX) $(CXXFLAGS_) $(INCLUDES_)

mremap.o: mremap.cc mremap.hh
	$(INVOKECXX) -c mremap.cc -o mremap.o

util.o: util.hh util.cc
	$(INVOKECXX) -c util.cc -o util.o

debug.o: debug.hh debug.cc
	$(INVOKECXX) -c debug.cc -o debug.o

asm.o: asm.cc asm.hh mremap.o util.o
	$(INVOKECXX) -c asm.cc -o asm.o

asm_test.o: asm.o asm_test.cc mremap.o debug.o
	$(INVOKECXX) -c asm_test.cc -o asm_test.o

asm_test: asm_test.o
	$(INVOKECXX) $(LDFLAGS) asm.o mremap.o asm_test.o util.o debug.o -o asm_test

mem.o: mem.cc mem.hh asm.o mremap.o
	$(INVOKECXX) -c mem.cc -o mem.o

vm.o: vm.cc vm.hh asm.o mremap.o mem.o
	$(INVOKECXX) -c vm.cc -o vm.o

vm_test.o: vm.o vm_test.cc util.o debug.o
	$(INVOKECXX) -c vm_test.cc -o vm_test.o

vm_test: vm_test.o
	$(INVOKECXX) $(LDFLAGS) vm.o util.o asm.o mremap.o mem.o debug.o vm_test.o -o vm_test

clean:
	rm *_test ; rm *.o
