// g++ unwind.cpp -o unwind -O2

#include <string>
#include <stdexcept>
#include <iostream>

__attribute__((noinline)) void try_parse_int(const char *arg)
{
    try
    {
        throw std::stoi(arg);
    }
    catch (const std::invalid_argument &ia)
    {
        std::cerr << arg << ": " << ia.what() << std::endl;
        throw 0;
    }
}

__attribute__((noinline)) int accumulate(int argc, char **argv, int (*func)(int, int))
{
    int result = 0;
    for (int i = 1; i < argc; i++)
    {
        // This intentionally uses C++ exceptions for control flow, since the
        // goal is to ensure we don't break EH.
        try
        {
            try_parse_int(argv[i]);
            abort();
        }
        catch (int value)
        {
            result = func(result, value);
        }
    }
    std::cout << result << std::endl;
    return 0;
}

__attribute__((noinline)) int sum(int a, int b) {
    return a + b;
}

int main(int argc, char **argv)
{
    try
    {
        return accumulate(argc, argv, &sum);
    }
    catch (...)
    {
        std::cerr << "fatal error!" << std::endl;
    }
}
