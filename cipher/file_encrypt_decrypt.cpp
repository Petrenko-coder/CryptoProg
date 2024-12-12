#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/aes.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/modes.h>

using byte = CryptoPP::byte;

void DeriveKeyAndIV(const std::string& password, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv) {
    CryptoPP::SHA256 hash;
    CryptoPP::SecByteBlock hashedPassword(CryptoPP::SHA256::DIGESTSIZE);
    
    hash.CalculateDigest(hashedPassword, reinterpret_cast<const byte*>(password.data()), password.size());

    key.Assign(hashedPassword, CryptoPP::AES::DEFAULT_KEYLENGTH);
    iv.Assign(hashedPassword + CryptoPP::AES::DEFAULT_KEYLENGTH, CryptoPP::AES::BLOCKSIZE);
}

void ProcessFile(const std::string& inputFilename, const std::string& outputFilename, const std::string& password, bool encrypt) {
    try {
        CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH), iv(CryptoPP::AES::BLOCKSIZE);
        DeriveKeyAndIV(password, key, iv);

        if (encrypt) {
            CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryptor;
            encryptor.SetKeyWithIV(key, key.size(), iv);
            CryptoPP::FileSource(inputFilename.c_str(), true,
                new CryptoPP::StreamTransformationFilter(encryptor,
                    new CryptoPP::FileSink(outputFilename.c_str())
                )
            );
            std::cout << "Файл зашифрован: " << outputFilename << std::endl;
        } else {
            CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryptor;
            decryptor.SetKeyWithIV(key, key.size(), iv);
            CryptoPP::FileSource(inputFilename.c_str(), true,
                new CryptoPP::StreamTransformationFilter(decryptor,
                    new CryptoPP::FileSink(outputFilename.c_str())
                )
            );
            std::cout << "Файл расшифрован: " << outputFilename << std::endl;
        }
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Ошибка Crypto++: " << e.what() << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
    }
}

int main() {
    std::string mode, inputFilename, outputFilename, password;

    std::cout << "Введите режим (encrypt/decrypt): ";
    std::cin >> mode;
    std::cin.ignore();
    
    std::cout << "Введите путь к файлу: ";
    std::getline(std::cin, inputFilename);

    std::cout << "Введите путь для выхода: ";
    std::getline(std::cin, outputFilename);

    std::cout << "Введите пароль: ";
    std::getline(std::cin, password);

    bool encryptMode = (mode == "encrypt");

    if (mode == "encrypt" || mode == "decrypt") {
        ProcessFile(inputFilename, outputFilename, password, encryptMode);
    } else {
        std::cerr << "Неизвестный режим: " << mode << std::endl;
    }

    return 0;
}
