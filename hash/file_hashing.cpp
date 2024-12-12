#include <iostream>
#include <stdexcept>
#include <string>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>

class FileHasher {
public:
    static void Hash(const std::string& filename) {
        std::string digest;

        try {
            ReadFile(filename);

            CryptoPP::SHA256 hash;
            ComputeHash(filename, hash, digest);

            PrintHash(filename, digest);
        } catch (const CryptoPP::Exception& e) {
            std::cerr << "Ошибка Crypto++: " << e.what() << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "Ошибка: " << e.what() << std::endl;
        }
    }

private:
    static void ReadFile(const std::string& filename) {
        std::ifstream file(filename, std::ios::in | std::ios::binary);
        if (!file.is_open()) {
            throw std::runtime_error("Не удалось открыть файл: " + filename);
        }
        file.close();
    }

    static void ComputeHash(const std::string& filename, CryptoPP::SHA256& hash, std::string& digest) {
        CryptoPP::FileSource(filename.c_str(), true,
            new CryptoPP::HashFilter(hash,
                new CryptoPP::HexEncoder(
                    new CryptoPP::StringSink(digest), false // без пробелов
                )
            )
        );
    }

    static void PrintHash(const std::string& filename, const std::string& digest) {
        std::cout << "Хэш файла \"" << filename << "\": " << digest << std::endl;
    }
};

int main() {
    std::string filename;
    std::cout << "Введите путь к файлу: ";
    std::getline(std::cin, filename);

    FileHasher::Hash(filename);

    return 0;
}
