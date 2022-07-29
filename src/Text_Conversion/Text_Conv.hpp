
#ifndef RSA_TEXT_CONV_HPP
#define RSA_TEXT_CONV_HPP
#include <fstream>
#include <string>

using namespace std;

class Text_Conv{
public:
string fileConvToDec(string, string);
string fileConvToAscii(string, string);
string messageConvToDec(string);
string decConvToMessage(string);
};
#endif //RSA_TEXT_CONV_HPP
