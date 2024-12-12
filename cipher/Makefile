OUTPUT = file_encrypt_decrypt
COMPILER = g++
FLAGS = -std=c++17 -Wall -Wextra -O2
LIBS = -lcryptopp

SOURCE = file_encrypt_decrypt.cpp

all: $(OUTPUT)

$(OUTPUT): $(SOURCE)
 $(COMPILER) $(FLAGS) -o $(OUTPUT) $(SOURCE) $(LIBS)

clean:
 rm -f $(OUTPUT)

.PHONY: clean
