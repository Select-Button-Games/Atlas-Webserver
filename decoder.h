#ifndef DECODER_H
#define DECODER_H

#include <string>

namespace Base64 {
    static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    inline bool is_base64(unsigned char c) {
        return (isalnum(c) || (c == '+') || (c == '/'));
    }

    // Declaration of the decode function
    std::string decode(const std::string& encoded_string);
}

#endif // DECODER_H
