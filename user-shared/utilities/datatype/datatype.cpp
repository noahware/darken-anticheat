#include "datatype.h"
#include <imports.h>
#include <Windows.h>
#include <iomanip>
#include <sstream>

std::string utilities::datatype::guid::to_string(GUID guid)
{
    std::ostringstream string_stream = { };

    string_stream << std::hex << std::uppercase << std::setfill('0');
    string_stream << std::setw(8) << guid.Data1;
    string_stream << std::setw(4) << guid.Data2;
    string_stream << std::setw(4) << guid.Data3;

    for (int i = 0; i < 8; i++)
    {
        string_stream << std::setw(2) << static_cast<int>(guid.Data4[i]);
    }

    return string_stream.str();
}

std::string utilities::datatype::uint32::to_hexadecimal_string(std::uint32_t integral_number)
{
    std::ostringstream string_stream = { };

    string_stream << std::setw(1) << std::hex << integral_number;

    return string_stream.str();
}

std::wstring utilities::datatype::ascii_string::to_unicode(std::string_view string_to_convert)
{
    int32_t source_length = static_cast<int32_t>(string_to_convert.length());

    int32_t character_count = d_import(MultiByteToWideChar)(CP_ACP, 0, string_to_convert.data(), source_length, nullptr, 0);

    std::wstring unicode_string(character_count, L'\0');

    d_import(MultiByteToWideChar)(CP_ACP, 0, string_to_convert.data(), source_length, unicode_string.data(), character_count);

    return unicode_string;
}
