#include <format>
#include <iostream>

#include "test.h"

int main()
{
    std::cout << std::format("Hello {}", stunpp::test);
}