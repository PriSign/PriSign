export LD_LIBRARY_PATH=./
CXX = g++
CC= gcc
all:
	${CXX} -o test-prisign prisign_test.cpp prisign.cpp bn_pair.cpp   miracl.a -O2 
clean:
	rm -f test-prisign
