#ifndef RSA_Walk_HPP
#define RSA_Walk_HPP

#include "RSA_Object.hpp"

class RSA_Walk{
public:
    RSA_Object rsa_object;
    void rsaPrimer();//will now save key pairs to a file
    void pause();
};
#endif