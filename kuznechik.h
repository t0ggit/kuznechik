#include <vector>
#include <cassert>
#include <iostream>
#include <climits>
#include <fstream>
#include <string>
#include <cstring>
#include <omp.h>

void encrypt_file( const char* input_file_name, const char* output_file_name, const char* key_1, const char* key_2);
void encrypt_file( const char* input_file_name, const char* output_file_name, const char* hexadecimal_key);

void decrypt_file( const char* input_file_name, const char* output_file_name, const char* key_1, const char* key_2);
void decrypt_file( const char* input_file_name, const char* output_file_name, const char* hexadecimal_key);

const char* const hex_symbol_table = "0123456789abcdef";

std::string char_to_hex_string( char c);
std::string hex_to_string ( const std::string input_string);
std::string string_to_hex ( const std::string input_string);
// Структура для представления 16-байтового блока данных (128 бит)
struct block
{
    public:
        static const int size = 16; // Размер блока в байтах (фиксирован для "Кузнечика")

        block(); // Конструктор по умолчанию
        block(std::vector<unsigned char> input_string); // Конструктор из вектора байтов
        block(std::string input_string); // Конструктор из строки (исправлено: input_string)

        unsigned char operator[](const int index) const; // Доступ к байту по индексу
        friend block operator^(const block& a, const block& b); // Оператор XOR для блоков
        friend std::ostream& operator<<(std::ostream& os, const block& b); // Вывод блока в поток
        const std::vector<unsigned char>& get_data() const { return data; } // Получение данных блока

        void mod(); // Модификация блока (не реализована в коде)
        void print(); // Печать блока в консоль
    private:
        std::vector<unsigned char> data; // Внутреннее хранение байтов блока
};

// Структура для хранения пары ключей (используется в сети Фейстеля)
struct key_pair
{
    block key_1; // Первый 16-байтовый ключ
    block key_2; // Второй 16-байтовый ключ
    key_pair(block key_1, block key_2) : key_1(key_1), key_2(key_2) {} // Конструктор с параметрами
    key_pair() = default; // Конструктор по умолчанию
};

// Оператор вывода блока в поток (внешняя реализация)
std::ostream& operator<<(std::ostream& os, const block& b);

// Класс, реализующий шифр "Кузнечик"
class kuznechik
{
    private:
        // Таблица подстановок S для нелинейного преобразования (256 значений)
        const unsigned char substitution_table[UCHAR_MAX + 1] =
        {
            (unsigned char)0xFC, (unsigned char)0xEE, (unsigned char)0xDD, (unsigned char)0x11, (unsigned char)0xCF, (unsigned char)0x6E, (unsigned char)0x31, (unsigned char)0x16,
            (unsigned char)0xFB, (unsigned char)0xC4, (unsigned char)0xFA, (unsigned char)0xDA, (unsigned char)0x23, (unsigned char)0xC5, (unsigned char)0x04, (unsigned char)0x4D,
            (unsigned char)0xE9, (unsigned char)0x77, (unsigned char)0xF0, (unsigned char)0xDB, (unsigned char)0x93, (unsigned char)0x2E, (unsigned char)0x99, (unsigned char)0xBA,
            (unsigned char)0x17, (unsigned char)0x36, (unsigned char)0xF1, (unsigned char)0xBB, (unsigned char)0x14, (unsigned char)0xCD, (unsigned char)0x5F, (unsigned char)0xC1,
            (unsigned char)0xF9, (unsigned char)0x18, (unsigned char)0x65, (unsigned char)0x5A, (unsigned char)0xE2, (unsigned char)0x5C, (unsigned char)0xEF, (unsigned char)0x21,
            (unsigned char)0x81, (unsigned char)0x1C, (unsigned char)0x3C, (unsigned char)0x42, (unsigned char)0x8B, (unsigned char)0x01, (unsigned char)0x8E, (unsigned char)0x4F,
            (unsigned char)0x05, (unsigned char)0x84, (unsigned char)0x02, (unsigned char)0xAE, (unsigned char)0xE3, (unsigned char)0x6A, (unsigned char)0x8F, (unsigned char)0xA0,
            (unsigned char)0x06, (unsigned char)0x0B, (unsigned char)0xED, (unsigned char)0x98, (unsigned char)0x7F, (unsigned char)0xD4, (unsigned char)0xD3, (unsigned char)0x1F,
            (unsigned char)0xEB, (unsigned char)0x34, (unsigned char)0x2C, (unsigned char)0x51, (unsigned char)0xEA, (unsigned char)0xC8, (unsigned char)0x48, (unsigned char)0xAB,
            (unsigned char)0xF2, (unsigned char)0x2A, (unsigned char)0x68, (unsigned char)0xA2, (unsigned char)0xFD, (unsigned char)0x3A, (unsigned char)0xCE, (unsigned char)0xCC,
            (unsigned char)0xB5, (unsigned char)0x70, (unsigned char)0x0E, (unsigned char)0x56, (unsigned char)0x08, (unsigned char)0x0C, (unsigned char)0x76, (unsigned char)0x12,
            (unsigned char)0xBF, (unsigned char)0x72, (unsigned char)0x13, (unsigned char)0x47, (unsigned char)0x9C, (unsigned char)0xB7, (unsigned char)0x5D, (unsigned char)0x87,
            (unsigned char)0x15, (unsigned char)0xA1, (unsigned char)0x96, (unsigned char)0x29, (unsigned char)0x10, (unsigned char)0x7B, (unsigned char)0x9A, (unsigned char)0xC7,
            (unsigned char)0xF3, (unsigned char)0x91, (unsigned char)0x78, (unsigned char)0x6F, (unsigned char)0x9D, (unsigned char)0x9E, (unsigned char)0xB2, (unsigned char)0xB1,
            (unsigned char)0x32, (unsigned char)0x75, (unsigned char)0x19, (unsigned char)0x3D, (unsigned char)0xFF, (unsigned char)0x35, (unsigned char)0x8A, (unsigned char)0x7E,
            (unsigned char)0x6D, (unsigned char)0x54, (unsigned char)0xC6, (unsigned char)0x80, (unsigned char)0xC3, (unsigned char)0xBD, (unsigned char)0x0D, (unsigned char)0x57,
            (unsigned char)0xDF, (unsigned char)0xF5, (unsigned char)0x24, (unsigned char)0xA9, (unsigned char)0x3E, (unsigned char)0xA8, (unsigned char)0x43, (unsigned char)0xC9,
            (unsigned char)0xD7, (unsigned char)0x79, (unsigned char)0xD6, (unsigned char)0xF6, (unsigned char)0x7C, (unsigned char)0x22, (unsigned char)0xB9, (unsigned char)0x03,
            (unsigned char)0xE0, (unsigned char)0x0F, (unsigned char)0xEC, (unsigned char)0xDE, (unsigned char)0x7A, (unsigned char)0x94, (unsigned char)0xB0, (unsigned char)0xBC,
            (unsigned char)0xDC, (unsigned char)0xE8, (unsigned char)0x28, (unsigned char)0x50, (unsigned char)0x4E, (unsigned char)0x33, (unsigned char)0x0A, (unsigned char)0x4A,
            (unsigned char)0xA7, (unsigned char)0x97, (unsigned char)0x60, (unsigned char)0x73, (unsigned char)0x1E, (unsigned char)0x00, (unsigned char)0x62, (unsigned char)0x44,
            (unsigned char)0x1A, (unsigned char)0xB8, (unsigned char)0x38, (unsigned char)0x82, (unsigned char)0x64, (unsigned char)0x9F, (unsigned char)0x26, (unsigned char)0x41,
            (unsigned char)0xAD, (unsigned char)0x45, (unsigned char)0x46, (unsigned char)0x92, (unsigned char)0x27, (unsigned char)0x5E, (unsigned char)0x55, (unsigned char)0x2F,
            (unsigned char)0x8C, (unsigned char)0xA3, (unsigned char)0xA5, (unsigned char)0x7D, (unsigned char)0x69, (unsigned char)0xD5, (unsigned char)0x95, (unsigned char)0x3B,
            (unsigned char)0x07, (unsigned char)0x58, (unsigned char)0xB3, (unsigned char)0x40, (unsigned char)0x86, (unsigned char)0xAC, (unsigned char)0x1D, (unsigned char)0xF7,
            (unsigned char)0x30, (unsigned char)0x37, (unsigned char)0x6B, (unsigned char)0xE4, (unsigned char)0x88, (unsigned char)0xD9, (unsigned char)0xE7, (unsigned char)0x89,
            (unsigned char)0xE1, (unsigned char)0x1B, (unsigned char)0x83, (unsigned char)0x49, (unsigned char)0x4C, (unsigned char)0x3F, (unsigned char)0xF8, (unsigned char)0xFE,
            (unsigned char)0x8D, (unsigned char)0x53, (unsigned char)0xAA, (unsigned char)0x90, (unsigned char)0xCA, (unsigned char)0xD8, (unsigned char)0x85, (unsigned char)0x61,
            (unsigned char)0x20, (unsigned char)0x71, (unsigned char)0x67, (unsigned char)0xA4, (unsigned char)0x2D, (unsigned char)0x2B, (unsigned char)0x09, (unsigned char)0x5B,
            (unsigned char)0xCB, (unsigned char)0x9B, (unsigned char)0x25, (unsigned char)0xD0, (unsigned char)0xBE, (unsigned char)0xE5, (unsigned char)0x6C, (unsigned char)0x52,
            (unsigned char)0x59, (unsigned char)0xA6, (unsigned char)0x74, (unsigned char)0xD2, (unsigned char)0xE6, (unsigned char)0xF4, (unsigned char)0xB4, (unsigned char)0xC0,
            (unsigned char)0xD1, (unsigned char)0x66, (unsigned char)0xAF, (unsigned char)0xC2, (unsigned char)0x39, (unsigned char)0x4B, (unsigned char)0x63, (unsigned char)0xB6
        };

        // Обратная таблица подстановок S⁻¹ для дешифрования
        const unsigned char substitution_table_reversed[UCHAR_MAX + 1] =
        {
            (unsigned char)0xA5, (unsigned char)0x2D, (unsigned char)0x32, (unsigned char)0x8F, (unsigned char)0x0E, (unsigned char)0x30, (unsigned char)0x38, (unsigned char)0xC0,
            (unsigned char)0x54, (unsigned char)0xE6, (unsigned char)0x9E, (unsigned char)0x39, (unsigned char)0x55, (unsigned char)0x7E, (unsigned char)0x52, (unsigned char)0x91,
            (unsigned char)0x64, (unsigned char)0x03, (unsigned char)0x57, (unsigned char)0x5A, (unsigned char)0x1C, (unsigned char)0x60, (unsigned char)0x07, (unsigned char)0x18,
            (unsigned char)0x21, (unsigned char)0x72, (unsigned char)0xA8, (unsigned char)0xD1, (unsigned char)0x29, (unsigned char)0xC6, (unsigned char)0xA4, (unsigned char)0x3F,
            (unsigned char)0xE0, (unsigned char)0x27, (unsigned char)0x8D, (unsigned char)0x0C, (unsigned char)0x82, (unsigned char)0xEA, (unsigned char)0xAE, (unsigned char)0xB4,
            (unsigned char)0x9A, (unsigned char)0x63, (unsigned char)0x49, (unsigned char)0xE5, (unsigned char)0x42, (unsigned char)0xE4, (unsigned char)0x15, (unsigned char)0xB7,
            (unsigned char)0xC8, (unsigned char)0x06, (unsigned char)0x70, (unsigned char)0x9D, (unsigned char)0x41, (unsigned char)0x75, (unsigned char)0x19, (unsigned char)0xC9,
            (unsigned char)0xAA, (unsigned char)0xFC, (unsigned char)0x4D, (unsigned char)0xBF, (unsigned char)0x2A, (unsigned char)0x73, (unsigned char)0x84, (unsigned char)0xD5,
            (unsigned char)0xC3, (unsigned char)0xAF, (unsigned char)0x2B, (unsigned char)0x86, (unsigned char)0xA7, (unsigned char)0xB1, (unsigned char)0xB2, (unsigned char)0x5B,
            (unsigned char)0x46, (unsigned char)0xD3, (unsigned char)0x9F, (unsigned char)0xFD, (unsigned char)0xD4, (unsigned char)0x0F, (unsigned char)0x9C, (unsigned char)0x2F,
            (unsigned char)0x9B, (unsigned char)0x43, (unsigned char)0xEF, (unsigned char)0xD9, (unsigned char)0x79, (unsigned char)0xB6, (unsigned char)0x53, (unsigned char)0x7F,
            (unsigned char)0xC1, (unsigned char)0xF0, (unsigned char)0x23, (unsigned char)0xE7, (unsigned char)0x25, (unsigned char)0x5E, (unsigned char)0xB5, (unsigned char)0x1E,
            (unsigned char)0xA2, (unsigned char)0xDF, (unsigned char)0xA6, (unsigned char)0xFE, (unsigned char)0xAC, (unsigned char)0x22, (unsigned char)0xF9, (unsigned char)0xE2,
            (unsigned char)0x4A, (unsigned char)0xBC, (unsigned char)0x35, (unsigned char)0xCA, (unsigned char)0xEE, (unsigned char)0x78, (unsigned char)0x05, (unsigned char)0x6B,
            (unsigned char)0x51, (unsigned char)0xE1, (unsigned char)0x59, (unsigned char)0xA3, (unsigned char)0xF2, (unsigned char)0x71, (unsigned char)0x56, (unsigned char)0x11,
            (unsigned char)0x6A, (unsigned char)0x89, (unsigned char)0x94, (unsigned char)0x65, (unsigned char)0x8C, (unsigned char)0xBB, (unsigned char)0x77, (unsigned char)0x3C,
            (unsigned char)0x7B, (unsigned char)0x28, (unsigned char)0xAB, (unsigned char)0xD2, (unsigned char)0x31, (unsigned char)0xDE, (unsigned char)0xC4, (unsigned char)0x5F,
            (unsigned char)0xCC, (unsigned char)0xCF, (unsigned char)0x76, (unsigned char)0x2C, (unsigned char)0xB8, (unsigned char)0xD8, (unsigned char)0x2E, (unsigned char)0x36,
            (unsigned char)0xDB, (unsigned char)0x69, (unsigned char)0xB3, (unsigned char)0x14, (unsigned char)0x95, (unsigned char)0xBE, (unsigned char)0x62, (unsigned char)0xA1,
            (unsigned char)0x3B, (unsigned char)0x16, (unsigned char)0x66, (unsigned char)0xE9, (unsigned char)0x5C, (unsigned char)0x6C, (unsigned char)0x6D, (unsigned char)0xAD,
            (unsigned char)0x37, (unsigned char)0x61, (unsigned char)0x4B, (unsigned char)0xB9, (unsigned char)0xE3, (unsigned char)0xBA, (unsigned char)0xF1, (unsigned char)0xA0,
            (unsigned char)0x85, (unsigned char)0x83, (unsigned char)0xDA, (unsigned char)0x47, (unsigned char)0xC5, (unsigned char)0xB0, (unsigned char)0x33, (unsigned char)0xFA,
            (unsigned char)0x96, (unsigned char)0x6F, (unsigned char)0x6E, (unsigned char)0xC2, (unsigned char)0xF6, (unsigned char)0x50, (unsigned char)0xFF, (unsigned char)0x5D,
            (unsigned char)0xA9, (unsigned char)0x8E, (unsigned char)0x17, (unsigned char)0x1B, (unsigned char)0x97, (unsigned char)0x7D, (unsigned char)0xEC, (unsigned char)0x58,
            (unsigned char)0xF7, (unsigned char)0x1F, (unsigned char)0xFB, (unsigned char)0x7C, (unsigned char)0x09, (unsigned char)0x0D, (unsigned char)0x7A, (unsigned char)0x67,
            (unsigned char)0x45, (unsigned char)0x87, (unsigned char)0xDC, (unsigned char)0xE8, (unsigned char)0x4F, (unsigned char)0x1D, (unsigned char)0x4E, (unsigned char)0x04,
            (unsigned char)0xEB, (unsigned char)0xF8, (unsigned char)0xF3, (unsigned char)0x3E, (unsigned char)0x3D, (unsigned char)0xBD, (unsigned char)0x8A, (unsigned char)0x88,
            (unsigned char)0xDD, (unsigned char)0xCD, (unsigned char)0x0B, (unsigned char)0x13, (unsigned char)0x98, (unsigned char)0x02, (unsigned char)0x93, (unsigned char)0x80,
            (unsigned char)0x90, (unsigned char)0xD0, (unsigned char)0x24, (unsigned char)0x34, (unsigned char)0xCB, (unsigned char)0xED, (unsigned char)0xF4, (unsigned char)0xCE,
            (unsigned char)0x99, (unsigned char)0x10, (unsigned char)0x44, (unsigned char)0x40, (unsigned char)0x92, (unsigned char)0x3A, (unsigned char)0x01, (unsigned char)0x26,
            (unsigned char)0x12, (unsigned char)0x1A, (unsigned char)0x48, (unsigned char)0x68, (unsigned char)0xF5, (unsigned char)0x81, (unsigned char)0x8B, (unsigned char)0xC7,
            (unsigned char)0xD6, (unsigned char)0x20, (unsigned char)0x0A, (unsigned char)0x08, (unsigned char)0x00, (unsigned char)0x4C, (unsigned char)0xD7, (unsigned char)0x74
        };

        // Маска для линейного преобразования R (16 значений)
        const unsigned char mask[block::size] =
        {
            (unsigned char)1, (unsigned char)148, (unsigned char)32, (unsigned char)133, (unsigned char)16, (unsigned char)194, (unsigned char)192, (unsigned char)1,
            (unsigned char)251, (unsigned char)1, (unsigned char)192, (unsigned char)194, (unsigned char)16, (unsigned char)133, (unsigned char)32, (unsigned char)148
        };

        const int number_of_iteration_keys = 10; // Количество итерационных ключей (10 раундов)

        std::vector<block> data; // Вектор блоков данных для шифрования/дешифрования
        std::vector<block> iteration_constants; // Итерационные константы для сети Фейстеля
        std::vector<block> iteration_keys; // Итерационные ключи для раундов

        // Чтение файла в буфер данных
        void read_file_to_data_buffer(const char* file_name, bool is_hex = false);
        // Вычисление итерационных констант
        void calculate_iteration_constants();
        // Генерация итерационных ключей через сеть Фейстеля
        void generate_iteraion_keys(block key_1, block key_2);

        // Получение значения из маски
        unsigned char get_mask_value(int index) const;
        // Получение значения из таблицы S
        unsigned char get_substituted_value(int index) const;
        // Получение значения из таблицы S⁻¹
        unsigned char get_reversed_substituted_value(int index) const;

        // Получение итерационной константы
        block get_iteration_constant(int index) const;
        // Получение итерационного ключа
        block get_iteration_key(int index) const;
        // Установка итерационного ключа
        void set_iteration_key(int index, const block value);

        // Умножение в поле Галуа для линейного преобразования
        static unsigned char GF_mul(unsigned char a, unsigned char b);

        // Линейное преобразование L (16 итераций R)
        block L(const block input_block);
        // Внутреннее преобразование R для L
        block R(const block input_block);
        // Нелинейное преобразование S
        block S(const block input_block);

        // Обратное линейное преобразование L⁻¹
        block L_reversed(const block input_block);
        // Обратное внутреннее преобразование R⁻¹
        block R_reversed(const block input_block);
        // Обратное нелинейное преобразование S⁻¹
        block S_reversed(const block input_block);

        // Функция Фейстеля для генерации ключей
        key_pair F(const key_pair input_key_pair, const block iteration_constant);

        // Шифрование одного блока (SP-сеть)
        block encrypt_block(const block input_block);
        // Дешифрование одного блока (обратная SP-сеть)
        block decrypt_block(const block input_block);

        // Запись данных в файл
        void write_to_file(const char* output_file, bool use_hex = false);

    public:
        // Конструктор с двумя ключами
        kuznechik(const char* file_name, const block key_1, const block key_2);
        // Конструктор с hex-ключом
        kuznechik(const char* file_name, const char* hexadecimal_key);

        // Шифрование данных и запись в файл
        void encrypt_data(const char* output_file_name, bool use_hex = false);
        // Дешифрование данных и запись в файл
        void decrypt_data(const char* output_file_name, bool use_hex = false);
};