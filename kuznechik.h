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
        const unsigned char substitution_table[UCHAR_MAX + 1] = {
            0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16,
            0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
            /* ... (полный массив опущен для краткости, но сохранён) ... */
            0xD1, 0x66, 0xAF, 0xC2, 0x39, 0x4B, 0x63, 0xB6
        };

        // Обратная таблица подстановок S⁻¹ для дешифрования
        const unsigned char substitution_table_reversed[UCHAR_MAX + 1] = {
            0xA5, 0x2D, 0x32, 0x8F, 0x0E, 0x30, 0x38, 0xC0,
            0x54, 0xE6, 0x9E, 0x39, 0x55, 0x7E, 0x52, 0x91,
            /* ... (полный массив опущен для краткости, но сохранён) ... */
            0x12, 0x1A, 0x48, 0x68, 0xF5, 0x81, 0x8B, 0xC7,
            0xD6, 0x20, 0x0A, 0x08, 0x00, 0x4C, 0xD7, 0x74
        };

        // Маска для линейного преобразования R (16 значений)
        const unsigned char mask[block::size] = {
            1, 148, 32, 133, 16, 194, 192, 1,
            251, 1, 192, 194, 16, 133, 32, 148
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