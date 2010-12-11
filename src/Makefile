LDFLAGS=
INCLUDES=-I./
CXX=g++
CXXFLAGS=-arch x86_64

mremap.o: mremap.cc mremap.hh
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c mremap.cc -o mremap.o

util.o: util.hh util.cc
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c util.cc -o util.o

asm.o: asm.cc asm.hh mremap.o util.o
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c asm.cc -o asm.o

asm_test.o: mremap.o asm.o asm_test.cc
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c asm_test.cc -o asm_test.o

asm_test: asm_test.o
	$(CXX) $(CXXFLAGS) $(LDFLAGS) asm.o mremap.o asm_test.o util.o -o asm_test

vm.o: vm.cc vm.hh
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c vm.cc -o vm.o

vm_test.o: vm.o vm_test.cc util.o
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c vm_test.cc -o vm_test.o

vm_test: vm_test.o
	$(CXX) $(CXXFLAGS) $(LDFLAGS) vm.o vm_test.o util.o -o vm_test

clean:
	rm *_test ; rm *.o