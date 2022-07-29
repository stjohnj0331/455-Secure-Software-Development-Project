#ifndef RSA_OBJECT_HPP
#define RSA_OBJECT_HPP

#include <vector>
#include <string>
#include <fstream>
#include <string>
#include "../Text_Conversion/Text_Conv.hpp"

using long64 = long long;
using ulong64 = unsigned long long;

using namespace std;

class RSA_Object{
private:
    ulong64 p, q, e, n, phi, inverse;
public:
    std::vector<ulong64> primes;
    std::vector<int> pubKeysVals;

    void setP(ulong64 input){ p = input; }
    void setQ(ulong64 input){ q = input; }
    void setE(ulong64 input){ e = input; }
    void setInverse(ulong64 input){ inverse = input; }
    void setPhi(){ phi = (p - 1) * (q - 1); }
    void setN(){ n = p*q; }

    ulong64 getPhi() { return phi; }
    ulong64 getInverse(){return inverse;}
    ulong64 getN(){ return n;}
    ulong64 getE(){ return e; }

    ulong64 squareAndMultiply(ulong64, ulong64, ulong64);
    ulong64 squareAndMultiplyUpdated(ulong64, ulong64, ulong64);
    void computeInverse(long64, long64);
    bool isCoPrime(ulong64, ulong64);
    bool fermatPrime(ulong64);

    ulong64 encrypt(ulong64, ulong64, ulong64);
    ulong64 decrypt(ulong64, ulong64, ulong64);

    string encryptMessage(string, string, ulong64, ulong64);

    string decryptMessage(string, string, ulong64, ulong64);

    string signMessage(string, string, ulong64, ulong64);

    string verifyMessage(string, string, ulong64, ulong64);

    void loadPrimes();
    void displayPrimes();
    void displayPubVal();
    void setPandQ(int, int);
    void toString();
    void saveRSA();
    long getFileLength(string);

    RSA_Object();
    ~RSA_Object();
};
#endif