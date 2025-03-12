#include "kuznechik.h"
#include <iostream>

int main(int argc, char* argv[])
{
    // Проверяем, передан ли аргумент с именем файла
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <input_filename>" << std::endl;
        std::cerr << "Example: " << argv[0] << " beatles.txt" << std::endl;
        return 1;
    }

    char key_1[] = "aaadefgpqrstuvws"; //just random 16-byte key
    char key_2[] = "bBbbbbebbeaaaaas"; //just random 16-byte key
    char key_hex[] = "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"; //hex key

    // Получаем имя входного файла из аргументов
    std::string inputFile = argv[1];
    
    // Формируем имена выходных файлов на основе входного
    std::string encryptedFile = "output/encrypted_" + inputFile;
    std::string decryptedFile = "output/decrypted_" + inputFile;

    // Шифрование и дешифрование
    encrypt_file(inputFile.c_str(), encryptedFile.c_str(), key_1, key_2);
    decrypt_file(encryptedFile.c_str(), decryptedFile.c_str(), key_1, key_2);

    std::cout << "Encryption completed: " << encryptedFile << std::endl;
    std::cout << "Decryption completed: " << decryptedFile << std::endl;

    return 0;
}