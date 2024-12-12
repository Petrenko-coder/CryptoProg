all: cipher_program

cipher_program: cipher_program.o
	g++ -o cipher_program cipher_program.o -lcryptopp

hash_program.o: cipher_program.cpp
	g++ -c cipher_program.cpp -lcryptopp

clean:
	rm -f *.o cipher_program
