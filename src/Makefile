LDFLAGS=
INCLUDES=-I./
CXX=g++
CXXFLAGS=-arch x86_64

mremap.o: mremap.cc mremap.hh
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c mremap.cc -o mremap.o

asm.o: asm.cc asm.hh mremap.o
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c asm.cc -o asm.o

asm_test.o: mremap.o asm.o asm_test.cc
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c asm_test.cc -o asm_test.o

asm_test: asm_test.o
	$(CXX) $(CXXFLAGS) $(LDFLAGS) asm.o mremap.o asm_test.o -o asm_test

clean:
	rm *_test ; rm *.o