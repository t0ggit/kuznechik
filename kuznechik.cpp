#include "kuznechik.h"

// Функция шифрования файла с использованием двух 16-байтовых ключей
void encrypt_file(const char* input_file_name, const char* output_file_name, const char* key_1, const char* key_2)
{
    // Создаём объект класса kuznechik для шифрования
    // - input_file_name: путь к входному файлу, который нужно зашифровать
    // - block(key_1): первый 16-байтовый ключ, преобразованный в объект типа block
    // - block(key_2): второй 16-байтовый ключ, преобразованный в объект типа block
    // В конструкторе происходит:
    // 1. Чтение данных из файла в буфер
    // 2. Генерация итерационных ключей на основе key_1 и key_2
    kuznechik encryptor(input_file_name, block(key_1), block(key_2));
    
    // Вызываем метод encrypt_data для шифрования данных
    // - output_file_name: путь к файлу, куда будет сохранён зашифрованный результат
    // Метод encrypt_data:
    // 1. Применяет алгоритм шифрования "Кузнечик" к каждому блоку данных (SP-сеть)
    // 2. Записывает зашифрованные данные в выходной файл
    encryptor.encrypt_data(output_file_name);
}

// Перегруженная функция шифрования файла с использованием ключа в шестнадцатеричном формате
void encrypt_file(const char* input_file_name, const char* output_file_name, const char* hexadecimal_key)
{
    // Создаём объект класса kuznechik для шифрования
    // - input_file_name: путь к входному файлу
    // - hexadecimal_key: строка из 64 символов (32 байта в шестнадцатеричном формате)
    // В конструкторе происходит:
    // 1. Чтение данных из файла
    // 2. Преобразование hex-ключа в два 16-байтовых ключа
    // 3. Генерация итерационных ключей
    kuznechik encryptor(input_file_name, hexadecimal_key);
    
    // Вызываем метод encrypt_data для шифрования данных
    // - output_file_name: путь к файлу для записи зашифрованных данных
    // Метод выполняет шифрование и сохраняет результат
    encryptor.encrypt_data(output_file_name);
}

void decrypt_file( const char* input_file_name, const char* output_file_name, const char* key_1, const char* key_2)
{
    kuznechik encryptor( input_file_name, block( key_1), block( key_2));
    encryptor.decrypt_data( output_file_name);
}

void decrypt_file( const char* input_file_name, const char* output_file_name, const char* hexadecimal_key)
{
    kuznechik encryptor( input_file_name, hexadecimal_key);
    encryptor.decrypt_data( output_file_name);
}

// Функция преобразует строку в шестнадцатеричном формате в обычную строку байтов
std::string hex_to_string(const std::string input_string)
{
    // Создаём пустую строку для хранения результата
    std::string output_string;

    // Проходим по входной строке с шагом 2, так как каждая пара символов представляет один байт
    for (int i = 0; i < input_string.length(); i += 2)
    {
        // Находим позицию первого символа пары в таблице hex_symbol_table (0–f)
        // hex_symbol_table — это массив символов "0123456789abcdef" (предполагается, определён где-то в коде)
        const char* p = std::lower_bound(hex_symbol_table, hex_symbol_table + 16, input_string[i]);
        
        // Находим позицию второго символа пары в той же таблице
        const char* q = std::lower_bound(hex_symbol_table, hex_symbol_table + 16, input_string[i + 1]);
        
        // Преобразуем два символа в один байт:
        // - (p - hex_symbol_table) даёт значение первого символа (0–15)
        // - Сдвиг влево на 4 бита (<< 4) помещает его в старший полубайт
        // - (q - hex_symbol_table) даёт значение второго символа (0–15), добавляется в младший полубайт
        // - Операция | объединяет их в один байт
        output_string.push_back(((p - hex_symbol_table) << 4) | (q - hex_symbol_table));
    }
    
    // Возвращаем строку байтов
    return output_string;
}

// Функция преобразует обычную строку байтов в строку в шестнадцатеричном формате
std::string string_to_hex(const std::string input_string)
{
    // Создаём пустую строку для хранения результата
    std::string output_string;
    
    // Проходим по каждому символу входной строки
    for (int i = 0; i < input_string.length(); i++)
    {
        // Преобразуем каждый байт в два шестнадцатеричных символа с помощью вспомогательной функции
        // и добавляем их к результирующей строке
        output_string += char_to_hex_string(input_string[i]);
    }
    
    // Возвращаем строку в hex-формате
    return output_string;
}

// Функция преобразует один байт в строку из двух шестнадцатеричных символов
std::string char_to_hex_string(char c)
{
    // Определяем строку с символами для шестнадцатеричного представления
    std::string hex = "0123456789abcdef";
    
    // Создаём пустую строку для результата
    std::string hex_str;
    
    // Вычисляем старший полубайт (4 старших бита):
    // - int(c) / 16 даёт значение от 0 до 15
    // - hex[...] выбирает соответствующий символ (например, 10 → 'a')
    hex_str += hex[int(int(c) / 16)];
    
    // Вычисляем младший полубайт (4 младших бита):
    // - int(c) % 16 даёт остаток от 0 до 15
    // - hex[...] выбирает соответствующий символ
    hex_str += hex[int(c) % 16];
    
    // Возвращаем строку из двух символов (например, 0x4f → "4f")
    return hex_str;
}

// Функция шифрования данных, содержащихся в объекте kuznechik, и записи результата в файл
void kuznechik::encrypt_data(const char* output_file_name, bool use_hex)
{
    // Объявляем переменные для замера времени выполнения
    double start;
    double end;
    
    // Записываем время начала шифрования с использованием OpenMP
    // omp_get_wtime() возвращает текущее время в секундах с высокой точностью
    start = omp_get_wtime();
    
    // Параллельная секция OpenMP для ускорения шифрования на многоядерных процессорах
    #pragma omp parallel
    {
        // Директива указывает, что цикл будет распределён между потоками
        #pragma omp for
        // Проходим по всем блокам данных, хранящимся в векторе data
        for (int i = 0; i < data.size(); i++)
        {
            // Шифруем каждый блок данных с помощью метода encrypt_block
            // encrypt_block реализует SP-сеть "Кузнечика" (9 раундов S-L + финальный XOR)
            // Результат записываем обратно в тот же элемент вектора
            data[i] = encrypt_block(data[i]);
        }
    }
    
    // Записываем время окончания шифрования
    end = omp_get_wtime();
    
    // Выводим время выполнения шифрования в секундах
    std::cout << "Encryption time: " << end - start << "s" << std::endl;
    
    // Записываем зашифрованные данные в файл
    // - output_file_name: путь к выходному файлу
    // - use_hex: флаг, указывающий, записывать ли данные в шестнадцатеричном формате
    // Метод write_to_file преобразует блоки в строку и сохраняет их
    write_to_file(output_file_name, use_hex);
}

void kuznechik::decrypt_data( const char* output_file_name, bool use_hex)
{
//    omp_set_num_threads(OMP_NUM_THREADS);
    double start;
    double end;
    start = omp_get_wtime();
    #pragma omp parallel
    {
        #pragma omp for
        for ( int i = 0; i < data.size(); i++)
            data[i] = decrypt_block( data[i]);
    }
    end = omp_get_wtime();
    std::cout << "Decryption time: "  << end - start << "s" << std::endl;
    write_to_file( output_file_name, use_hex);
}

// Конструктор класса kuznechik с двумя 16-байтовыми ключами
kuznechik::kuznechik(const char* file_name, const block key_1, const block key_2)
{
    // Инициализируем вектор итерационных ключей нужным размером
    // number_of_iteration_keys = 10 (по стандарту "Кузнечика" нужно 10 ключей для 10 раундов)
    iteration_keys.resize(number_of_iteration_keys);
    
    // Читаем данные из файла в буфер (вектор data)
    // - file_name: путь к входному файлу
    // - Данные разбиваются на блоки по 16 байт (128 бит), как требует алгоритм
    read_file_to_data_buffer(file_name);
    
    // Вычисляем итерационные константы для сети Фейстеля
    // - Создаются 32 константы, используемые при генерации ключей
    calculate_iteration_constants();
    
    // Генерируем 10 итерационных ключей на основе двух входных ключей
    // - key_1: первый 16-байтовый ключ
    // - key_2: второй 16-байтовый ключ
    // - Используется сеть Фейстеля для развертывания ключей
    generate_iteraion_keys(key_1, key_2);
}

// Конструктор класса kuznechik с ключом в шестнадцатеричном формате
kuznechik::kuznechik(const char* file_name, const char* hexadecimal_key)
{
    // Проверяем, что длина hex-ключа равна 64 символам (32 байта = 256 бит)
    // Если длина неверная, программа завершится с ошибкой "Wrong key"
    assert(strlen(hexadecimal_key) == 64 && "Wrong key");
    
    // Инициализируем вектор итерационных ключей (10 ключей по 128 бит)
    iteration_keys.resize(number_of_iteration_keys);
    
    // Читаем данные из файла, интерпретируя их как шестнадцатеричные
    // - file_name: путь к файлу
    // - true: флаг указывает, что содержимое файла в hex-формате
    read_file_to_data_buffer(file_name, true);
    
    // Вычисляем итерационные константы для сети Фейстеля
    calculate_iteration_constants();
    
    // Преобразуем hex-ключ (64 символа) в строку байтов (32 байта)
    // Например, "8899aabb..." → строка из 32 байт
    std::string ascii_key_pair = hex_to_string(hexadecimal_key);
    
    // Генерируем итерационные ключи, разделяя полученную строку на два ключа:
    // - Первый ключ: первые 16 байт (0–15)
    // - Второй ключ: следующие 16 байт (16–31)
    // Исправление: substr(0, 16) вместо (0, 15), так как нужно 16 байт
    generate_iteraion_keys(ascii_key_pair.substr(0, 16), ascii_key_pair.substr(16));
}
// Чтение файла в буфер данных
void kuznechik::read_file_to_data_buffer(const char* file_name, bool is_hex)
{
    std::ifstream input_file_stream(file_name); // Открываем файл
    assert(input_file_stream && "Can't find file"); // Проверяем успешность открытия
    std::string file_content((std::istreambuf_iterator<char>(input_file_stream)), std::istreambuf_iterator<char>()); // Читаем всё содержимое в строку

    if (is_hex == true) // Если данные в hex-формате
        file_content = hex_to_string(file_content); // Преобразуем hex в байты

    int length_of_the_trailing_string = file_content.length() % block::size; // Вычисляем длину остатка

    // Разбиваем содержимое на блоки по 16 байт
    for (int i = 0; i + block::size <= file_content.length(); i += block::size)
        data.push_back(block(file_content.substr(i, block::size)));

    // Обрабатываем остаток, дополняя пробелами
    if (length_of_the_trailing_string != 0)
    {
        std::string trailing_content = file_content.substr(file_content.length() - length_of_the_trailing_string);
        for (int i = 0; i < block::size - length_of_the_trailing_string; i++)
            trailing_content.push_back(' ');
        data.push_back(block(trailing_content));
    }
}

// Вычисление итерационных констант для сети Фейстеля
void kuznechik::calculate_iteration_constants()
{
    std::string zero_string("000000000000000"); // 15 нулей для формирования 16-байтового блока
    for (int i = 0; i < 32; i++) // Создаём 32 константы
    {
        std::string iterational_string;
        iterational_string.push_back((char)i); // Первый байт — номер итерации
        iterational_string += zero_string; // Остальные — нули
        iteration_constants.push_back(L(block(iterational_string))); // Применяем L-преобразование
    }
}

// Получение значения маски для линейного преобразования
unsigned char kuznechik::get_mask_value(int index) const
{
    assert(index >= 0 && index < block::size && "Wrong index value"); // Проверка индекса
    return mask[index]; // Возвращаем элемент из таблицы маски
}

// Получение значения из таблицы подстановки S
unsigned char kuznechik::get_substituted_value(int index) const
{
    assert(index >= 0 && index <= UCHAR_MAX && "Wrong index value"); // Проверка диапазона
    return substitution_table[index]; // Возвращаем подстановку
}

// Получение значения из обратной таблицы подстановки S⁻¹
unsigned char kuznechik::get_reversed_substituted_value(int index) const
{
    assert(index >= 0 && index <= UCHAR_MAX && "Wrong index value"); // Проверка диапазона
    return substitution_table_reversed[index]; // Возвращаем обратную подстановку
}

// Получение итерационной константы по индексу
block kuznechik::get_iteration_constant(int index) const
{
    assert(index >= 0 && index < 2 * block::size && "Wrong index value"); // Проверка (до 32)
    return iteration_constants.at(index); // Возвращаем константу
}

// Получение итерационного ключа по индексу
block kuznechik::get_iteration_key(int index) const
{
    assert(index >= 0 && index < number_of_iteration_keys && "Wrong index value"); // Проверка (до 10)
    return iteration_keys[index]; // Возвращаем ключ
}

// Установка итерационного ключа
void kuznechik::set_iteration_key(int index, const block value)
{
    assert(index >= 0 && index < number_of_iteration_keys && "Wrong index value"); // Проверка
    iteration_keys[index] = value; // Задаём ключ
}

// Нелинейное преобразование S
block kuznechik::S(const block input_block)
{
    std::vector<unsigned char> transformed_data;
    for (int i = 0; i < block::size; i++) // Для каждого байта блока
        transformed_data.push_back(get_substituted_value(input_block[i])); // Применяем подстановку
    return block(transformed_data); // Возвращаем преобразованный блок
}

// Обратное нелинейное преобразование S⁻¹
block kuznechik::S_reversed(const block input_block)
{
    std::vector<unsigned char> transformed_data;
    for (int i = 0; i < block::size; i++) // Для каждого байта
        transformed_data.push_back(get_reversed_substituted_value(input_block[i])); // Обратная подстановка
    return block(transformed_data); // Возвращаем блок
}

// Умножение в поле Галуа GF(2^8) для линейного преобразования
unsigned char kuznechik::GF_mul(unsigned char a, unsigned char b)
{
    unsigned char c = 0;
    for (int i = 0; i < 8; i++) // 8 бит в байте
    {
        if ((b & 1) == 1) // Если младший бит b равен 1
            c ^= a; // Добавляем a к результату
        unsigned char hi_bit = (char)(a & 0x80); // Проверяем старший бит a
        a <<= 1; // Сдвиг a влево
        if (hi_bit == 0) // Если был перенос
            a ^= 0xC3; // Применяем полином x^8 + x^7 + x^6 + x + 1
        b >>= 1; // Сдвиг b вправо
    }
    return c; // Возвращаем произведение
}

// Внутреннее линейное преобразование R
block kuznechik::R(const block input_block)
{
    std::vector<unsigned char> transformed_data(block::size); // Новый блок
    unsigned char trailing_symbol = 0; // Контрольная сумма
    for (int i = block::size - 1; i >= 0; i--) // Сдвиг байтов вправо
    {
        if (i == 0)
            transformed_data[block::size] = input_block[i]; // Ошибка: должно быть block::size-1
        else
            transformed_data[i - 1] = input_block[i]; // Сдвигаем
        trailing_symbol ^= GF_mul(input_block[i], get_mask_value(i)); // Вычисляем сумму
    }
    transformed_data[block::size - 1] = trailing_symbol; // Вставляем сумму
    return block(transformed_data);
}

// Обратное внутреннее линейное преобразование R⁻¹
block kuznechik::R_reversed(const block input_block)
{
    std::vector<unsigned char> transformed_data(block::size); // Новый блок
    unsigned char leading_symbol = input_block[block::size - 1]; // Извлекаем сумму
    for (int i = 1; i < block::size; i++) // Сдвиг влево
    {
        transformed_data[i] = input_block[i - 1]; // Сдвигаем байты
        leading_symbol ^= GF_mul(transformed_data[i], get_mask_value(i)); // Обновляем сумму
    }
    transformed_data[0] = leading_symbol; // Вставляем результат
    return block(transformed_data);
}

// Полное линейное преобразование L (16 итераций R)
block kuznechik::L(const block input_block)
{
    block transformed_block = input_block;
    for (int i = 0; i < block::size; i++) // 16 итераций
        transformed_block = R(transformed_block); // Применяем R
    return transformed_block;
}

// Обратное линейное преобразование L⁻¹ (16 итераций R⁻¹)
block kuznechik::L_reversed(const block input_block)
{
    block transformed_block = input_block;
    for (int i = 0; i < block::size; i++) // 16 итераций
        transformed_block = R_reversed(transformed_block); // Применяем R⁻¹
    return transformed_block;
}

// Функция Фейстеля для генерации ключей
key_pair kuznechik::F(const key_pair input_key_pair, const block iteration_constant)
{
    block returned_key_1;
    block returned_key_2 = input_key_pair.key_1; // Сохраняем первый ключ
    returned_key_1 = L(S(input_key_pair.key_2 ^ iteration_constant)) ^ returned_key_2; // SP-сеть + XOR
    return key_pair(returned_key_1, returned_key_2); // Возвращаем новую пару ключей
}

// Генерация итерационных ключей (сеть Фейстеля)
void kuznechik::generate_iteraion_keys(block key_1, block key_2)
{
    iteration_keys[0] = key_1; // Первый ключ
    iteration_keys[1] = key_2; // Второй ключ
    key_pair key_pair_1_2(key_1, key_2); // Начальная пара
    key_pair key_pair_3_4;
    for (int i = 0; i < 4; i++) // 4 цикла по 8 итераций
    {
        key_pair_3_4 = F(key_pair_1_2, get_iteration_constant(0 + 8 * i));
        key_pair_1_2 = F(key_pair_3_4, get_iteration_constant(1 + 8 * i));
        key_pair_3_4 = F(key_pair_1_2, get_iteration_constant(2 + 8 * i));
        key_pair_1_2 = F(key_pair_3_4, get_iteration_constant(3 + 8 * i));
        key_pair_3_4 = F(key_pair_1_2, get_iteration_constant(4 + 8 * i));
        key_pair_1_2 = F(key_pair_3_4, get_iteration_constant(5 + 8 * i));
        key_pair_3_4 = F(key_pair_1_2, get_iteration_constant(6 + 8 * i));
        key_pair_1_2 = F(key_pair_3_4, get_iteration_constant(7 + 8 * i));
        set_iteration_key(2 * i + 2, key_pair_1_2.key_1); // Сохраняем ключи
        set_iteration_key(2 * i + 3, key_pair_1_2.key_2);
    }
}

// Шифрование одного блока (SP-сеть)
block kuznechik::encrypt_block(const block input_block)
{
    block returned_block = input_block;
    for (int i = 0; i < 9; i++) // 9 раундов
    {
        returned_block = get_iteration_key(i) ^ returned_block; // XOR с ключом
        returned_block = S(returned_block); // Нелинейное преобразование
        returned_block = L(returned_block); // Линейное преобразование
    }
    returned_block = returned_block ^ get_iteration_key(9); // Финальный XOR
    return returned_block;
}

// Дешифрование одного блока (обратная SP-сеть)
block kuznechik::decrypt_block(const block input_block)
{
    block returned_block = input_block ^ get_iteration_key(9); // Убираем последний ключ
    for (int i = 8; i >= 0; i--) // 9 раундов в обратном порядке
    {
        returned_block = L_reversed(returned_block); // Обратное L
        returned_block = S_reversed(returned_block); // Обратное S
        returned_block = get_iteration_key(i) ^ returned_block; // Убираем ключ
    }
    return returned_block;
}

// Запись данных в файл
void kuznechik::write_to_file(const char* output_file, bool use_hex)
{
    std::ofstream output_stream;
    output_stream.open(output_file); // Открываем файл
    assert(output_stream.is_open() && "Can't open file"); // Проверяем
    for (block i : data) // Для каждого блока
        if (use_hex == true)
            output_stream << hex_to_string(std::string(i.get_data().begin(), i.get_data().end())); // В hex
        else
            output_stream << std::string(i.get_data().begin(), i.get_data().end()); // Как есть
}

// Конструктор блока из вектора байтов
block::block(std::vector<unsigned char> input_string) : data(input_string) 
{ 
    assert(input_string.size() == size); // Проверка размера
};

// Конструктор пустого блока
block::block() 
{ 
    data.resize(size); // Устанавливаем размер 16 байт
}

// Конструктор блока из строки
block::block(std::string input_string)
{
    assert(input_string.length() == size && "Wrong length of the block"); // Проверка длины
    for (int i = 0; i < size; i++)
        data.push_back(input_string[i]); // Заполняем байты
}

// Доступ к байту блока по индексу
unsigned char block::operator[](const int index) const
{
    assert(index < size && "given index causes overflow"); // Проверка
    return data[index]; // Возвращаем байт
}

// Оператор XOR для блоков
block operator^(const block& a, const block& b)
{
    block result;
    for (int i = 0; i < result.size; i++)
        result.data[i] = b[i] ^ a[i]; // Побитовое XOR
    return result;
}

// Вывод блока в поток
std::ostream& operator<<(std::ostream& os, const block& b)
{
    return os << b.data << std::endl; // Выводим данные
}

// Печать блока в консоль
void block::print()
{
    for (int i : data)
        std::cout << (unsigned char)i; // Печатаем каждый байт
    std::cout << std::endl;
}