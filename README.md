#  Реализация шифра "Кузнечик" ГОСТ 34.12-2018 в режиме электронной кодовой книги.

### Как

Для сборки нужен установленный компилятор `gcc` / `g++`

```bash
make
```

или

```bash
g++ kuznechik.cpp main.cpp -o kuznechik -fopenmp
```

> *можно попробовать другим компилятором если что*

Запустить:

```bash
./kuznechik beatles.txt
```

Подсчет времени уже реализован (через `omp.h`)

Вывод такого вида:
```
t0g@vm:~/kuznechik$ ./kuznechik beatles.txt 
Encryption time: 0.00830725s
Encryption completed: output/encrypted_beatles.txt
t0g@vm:~/kuznechik$ 
```

Реализация алгоритма взята тут:

https://github.com/agrachiv/kuznechik