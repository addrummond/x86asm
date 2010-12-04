LDFLAGS=
INCLUDES=-I./
CXX=g++
CXXFLAGS=-arch x86_64

mremap.o: mremap.cc mremap.hh
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c mremap.cc -o mremap.o

asm.o: asm.cc asm.hh mremap.o
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c asm.cc -o asm.o

test.o: mremap.o asm.o test.cc
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c test.cc -o test.o

test: test.o
	$(CXX) $(CXXFLAGS) $(LDFLAGS) asm.o mremap.o test.o -o test

clean:
	rm test ; rm *.o