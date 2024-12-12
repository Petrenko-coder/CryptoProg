# Задаем имя целевого файла
OUTPUT = file_hash

# Определяем компилятор и его параметры
COMPILER = g++
CFLAGS = -std=c++17 -Wall -Wextra -O2
LIBS = -lcryptopp

# Указываем исходный файл
SOURCE = file_hashing.cpp

# Инструкция по сборке целевого файла
$(OUTPUT): $(SOURCE)
 $(COMPILER) $(CFLAGS) -o $@ $< $(LIBS)

# Команда для удаления собранного файла
clean:
 rm -f $(OUTPUT)

# Специальная цель, которая не требует файлов
.PHONY: clean
