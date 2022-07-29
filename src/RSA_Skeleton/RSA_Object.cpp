#include "RSA_Object.hpp"
#include "../Text_Conversion/Text_Conv.hpp"
#include <iostream>
#include <stdio.h>
#include <bitset>
#include <math.h>
#include <time.h>
#include <stdlib.h>
#include <string>
#include <fstream>
#include <vector>
#include <cstdint>
#include <stdint.h>
#include <iomanip>
#include <sys/stat.h>
#include <string.h>
#include <climits>


using namespace std;

using long64 = long long;
using ulong64 = unsigned long long;


RSA_Object::RSA_Object(){
    p = q = e = n = phi = inverse =  0; 
    srand(time(NULL));
    loadPrimes();
}

RSA_Object::~RSA_Object(){
    p = q = e = n = phi = inverse =  0;
    primes.clear();
    pubKeysVals.clear();
}


/**
 *
 * @param plaintext
 * @param e public key value
 * @param n public key value
 * @return
 */
ulong64 RSA_Object::encrypt(ulong64 plaintext, ulong64 e, ulong64 n){
    return squareAndMultiply(plaintext, e, n);
}

/**
 *
 * @param ciphertext
 * @param d private key
 * @param n  public key value
 * @return
 */
ulong64 RSA_Object::decrypt(ulong64 ciphertext, ulong64 d, ulong64 n){
    return squareAndMultiply(ciphertext, d, n);
}

/**
 *
 * @param file string with filepath of signature to decrypt
 * @param fileOut string with filepath for verification output
 * @param e public key value
 * @param n public key value
 * @return
 */
string RSA_Object::encryptMessage(string filename, string outputname, ulong64 e, ulong64 n) {
    Text_Conv textConv;
    string encrypted;
    //get file
    try{
        ifstream fileIn(filename);
        ofstream fileOut(outputname);
        if(!fileIn.is_open()) throw "ERROR::RSA_Object::encryptMessage()::unable to open input file";
        if(!fileOut.is_open()) throw "ERROR::RSA_Object::encryptMessage()::unable to open output file";
        else{
            //get file length
            long fileLength = getFileLength(filename);
            if(fileLength < 0) throw "ERROR::RSA_Object::encryptMessage()::buffer <= 0";
            char* buffer = (char*)malloc((3*fileLength)+1);
            //read file into buffer
            string temp,decStr,subStr;
            while(fileIn.getline(buffer,fileLength*3)) {//--try using a getline() or certain
                //load the file into a decimal string
                decStr += textConv.messageConvToDec(buffer);
                if(!fileIn.eof()) {
                    decStr += "010";
                }
            }
            // If this number numChars is divisible itself by 3,
            // We are done. Otherwise, we need padding.
            int numChars = decStr.length() / 3;
            if(numChars%3 == 1) {
                decStr += "032032";
            }
            else if(numChars%3 == 2) {
                decStr += "032";
            }
            //decStr += "000";
            for(int i = 0 ; i < decStr.length() ; i+=9){
                subStr = decStr.substr(i,9);
                //encrypted += encrypt(stoull(subStr, nullptr,10),e,n);
                fileOut << encrypt(stoull(subStr, nullptr,10),e,n) << endl;
            }
            fileIn.close();
            fileOut.close();
        }
    }catch(const char* msg){
        cerr << msg << endl;
    }
    return encrypted;
}

/**
 *
 * @param file string with filepath of signature to decrypt
 * @param fileOut string with filepath for verification output
 * @param d private key
 * @param n public key value
 * @return
 */
string RSA_Object::decryptMessage(string filename, string outputname, ulong64 d, ulong64 n) {
    Text_Conv textConv;
    //get file
    ifstream fileIn(filename);
    ofstream fileOut(outputname);
    string temp,decStr,subStr,decrypted;
    ulong64 num;
    if(!fileIn.is_open()) throw "ERROR::RSA_Object::decryptMessage()::unable to open input file";
    if(!fileOut.is_open()) throw "ERROR::RSA_Object::decryptMessage()::unable to open output file";
    else {
        long fileLength = getFileLength(filename);
        if(fileLength < 0) throw "ERROR::RSA_Object::encryptMessage()::buffer <= 0";
        char* buffer = (char*)malloc((3*fileLength)+1);
        //load file to string
        while(fileIn >> buffer) {
            num = decrypt(stoull(buffer, nullptr, 10), d, n);
            string temp1 = to_string(num);
            if (temp1.length() < 9)temp1.insert(0, "0");
            decStr += textConv.decConvToMessage(temp1);
        }
        fileOut << decStr;
        fileIn.close();
        fileOut.close();
    }
    return decStr;
}

/**
 *
 * @param file string with filepath of signature to verify
 * @param fileOut string with filepath for verification output
 * @param d private key value
 * @param n public key value
 * @return
 */
string RSA_Object::signMessage(string filename, string outputname, ulong64 d, ulong64 n) {
    string output = encryptMessage(filename, outputname, d, n);
    cout << "signature: " << output << endl;
    return output;
}

/**
 *
 * @param file string with filepath of signature to verify
 * @param fileOut string with filepath for verification output
 * @param e public key value
 * @param n public key value
 * @return
 */
string RSA_Object::verifyMessage(string filename, string outputname, ulong64 e, ulong64 n) {
    string output = decryptMessage(filename, outputname, e, n);
    cout << output << endl;
    return output;
}

/**
 * @brief
 * 
 * @param a 
 * @param b 
 * computes inverse of a mod b (a^-1 mod b)
 * uses the extended Euclidean Algorithm
 * computation. 
 */
void RSA_Object::computeInverse(long64 a, long64 b){
    long64 G=0, mult=0, temp1=0, temp2=0, n=0, t1 = 0, t2 = 1, s1 = 1, s2 = 0;
    long64 placeHoldA = a, placeHoldB = b;
    printf("\n%lld^-1 mod %lld\n\n", a, b);
    printf("%12s| %15s| %12s| %12s","multiplier", "G", "s", "t");
    printf("  |  %25s","G = s*a + t*b\n");
    //printf();
    if(a < b){
        n = b;
        temp1 = a;
        a = b;
        b = temp1;
    }else
        n = a;
    placeHoldA = b, placeHoldB = a;
    printf("%12lld| %15lld| %12d| %12d", mult, a, 1, 0);
    printf("  |  %12lld = %d * %lld + %d * %lld\n", a, 1,a,0,b);//equation
    do{
        G=b;
        mult = (a / b) *  -1;
        printf("%12lld| %15lld| %12lld| %12lld", mult, G, s2, t2);
        printf("  |  %12lld = %lld * %lld + %lld * %lld\n", b, s2,placeHoldB,t2,placeHoldA);//equation
        G = a + b * mult;
        a = b;
        b = G;
        temp1 = t2;
        t2 = t1 + (t2 * mult);
        t1 = temp1;
        temp2 = s2;
        s2 = s1 + (s2 * mult);
        s1 = temp2;
    }while(G > 1);
    if(t2 < 0){
        setInverse(n + t2);
        printf("%12lld| %15lld| %12lld| %12lld|", mult, G, s2, t2);
        printf("  |  %12lld = %lld * %lld + %lld * %lld\n", b, s2,placeHoldB,t2,placeHoldA);//equation
        printf("\n%lld^-1 mod %lld = %lld\n", placeHoldA, placeHoldB, n+t2);
    }else{
        setInverse(t2);
        printf("%12lld| %15lld| %12lld| %12lld", mult, G, s2, t2);
        printf("  |  %12lld = %lld * %lld + %lld * %lld\n", b, s2,placeHoldB,t2,placeHoldA);//equation
        printf("\n%lld^-1 mod %lld = %lld\n", placeHoldA, placeHoldB, t2);
    }
}

/**
 * @brief 
 * 
 * @param a coprime candidate
 * @param b coprime candidate
 * @return true if co-prime
 * @return false if otherwise
 */
bool RSA_Object::isCoPrime(ulong64 a, ulong64 b){
    if(b == 1) return true;
    if(b == 0) return false;
    return isCoPrime(b, a % b);
}

/**
 * Fast exponentiation
 * @param x = base
 * @param h = exponent
 * @param p = modulus
 * @return x^h mod p
 * 
 * bitset<#>(x).to_string() takes ulong64 x and converts it to a
 * string of bits # of "digits" long
 */
ulong64 RSA_Object::squareAndMultiply(ulong64 x, ulong64 h, ulong64 p){
    ulong64 r = x;
    string H = bitset<64>(h).to_string();
    int index = 0;
    while (H[index] != '1') { index++; }
    try {
        for (int i = index + 1; i < H.size(); i++) {
            r = (r * r);
            if (r > ULLONG_MAX || r < 0) throw "ERROR::RSA_Object::squareAndMultiply()::OVERFLOW/UNDERFLOW has occurred";
            r = r % p;
            if (H[i] == '1')
                r = (r * x) % p;
        }
    }catch(const char* msg){
        cerr << msg << endl;
    }
    return r;
}

/**
 * Fast exponentiation, another way
 * @param x = base
 * @param h = exponent
 * @param p = modulus
 * @return x^h mod p
 */
ulong64 RSA_Object::squareAndMultiplyUpdated(ulong64 x, ulong64 h, ulong64 p) {
    unsigned short arrayLength = (unsigned short) floor(log2(h));
    vector<ulong64> powers;
    ulong64 value = x;
    powers.push_back(value);
    for(int i = 1; i <= arrayLength; i++) {
        value = (powers.back() * powers.back()) % p;
        powers.push_back(value);
    }
    // Now we have a vector with the powers of x
    string H = bitset<64>(h).to_string();
    // cout << "H: " << H << endl;
    int index = 0;
    while(H[index] != '1'){ index++;}
    // now our index points to the most significant bit of the binary representation of h
    ulong64 result = 1;
    for(int i = arrayLength; i >= 0; i--) {
        if(H[index++] == '1') {
            result *= powers[i];
            result %= p;
            // Debugging
            // cout << result << endl;
        }
    }
    /* Debugging with original squareAndMultiply
    ulong64 originalResult = squareAndMultiply(x,h,p);
    cout << "Original S&M [" << originalResult << "]\t Updated S&M [" << result << "]" << endl;
    for(ulong64 p : powers) {
        printf("%llu \n", p);
    }
    cout << endl;
    */
    return result;
}

/**
 * @brief 
 * @param num = candidate prime to be checked.
 * @return true if candidate is prime.
 * @return false if candidate is composite.
 * Uses PRNG to generate random compare values, we shouldn't need to implement
 * a CPRNG since the values are not used to generate any crypto values and since this
 * application is intended for educational use.
 */
bool RSA_Object::fermatPrime(ulong64 num){
    ulong64 s = 11;
    //base cases
    if(num == 2 || num == 3)
        return true;
    //for 1 and even numbers
    if(num == 1 || num % 2 == 0)
        return false;
    //for odd numbers
    for(int i = 0 ; i < s ; i++){
        ulong64 base = 2+(rand() % (num-2));
        if(squareAndMultiply(base, num-1, num) != 1)
            return false;
    }
    return true;
}
//58543
/**
 * gets the file from the src directory(primes.txt) and parses it, loading
 * the enclosed prime numbers into a vector that is stored in RSA_Object.hpp
 */
void RSA_Object::loadPrimes(){///mitigation of user input vulnerabilities--------------------------------------
    try{
        ulong64 fileIn;
        int counter = 0;
        ifstream file("primes.txt");
        if(!file) {
            throw "ERROR: RSA_Object.cpp: loadPrimes(): Unable to open the file!";
        }else{
            while (file >> fileIn) {
                if(fermatPrime(fileIn)){
                    primes.push_back(fileIn);
                    counter++;
                }else{
                    cout << "ERROR::RSA_Object::loadPrimes()::line " << counter << " of primes.txt";
                    throw " contained a number that is not prime";
                }

            }
            if (counter < 20)
                throw "ERROR: Input file contained less than the 20 needed primes.";
            if (counter > 20)
                throw "ERROR: Input file contained more than the 20 needed primes.";
        }
        file.close();
    }catch(const char *msg){
        cerr << msg << endl;
        exit(0);
    }
}

void RSA_Object::displayPrimes(){///mitigation of user input vulnerabilities--------------------------------------
    for(int i = 0 ; i < primes.size() ; i ++) {
        cout << setw(6) << i + 1 << ": " << primes[i] << "\t";
        if(i % 2 != 0)
            cout << endl;
    }
}

void RSA_Object::displayPubVal() {///mitigation of user input vulnerabilities--------------------------------------
    //gcd(e, phi(n)) == 1
    cout << "\n\n---Possible public keys---" << endl;
    for(int i = 3 ; i < 50 ; i++){
        if(isCoPrime(i, getPhi())) {
            pubKeysVals.push_back(i);
            cout << i << "  ";
        }
    }
    cout << "\n\n" << endl;
}

void RSA_Object::setPandQ(int index1, int index2){
    setP(primes[index1-1]);
    setQ(primes[index2-1]);
}

void RSA_Object::toString() {
    cout << "\n\n\n\t\t*********************************************\n"
         << "\t\t******         Your RSA Values         ******\n"
         << "\t\t*********************************************\n"
         << "n: " << getN()
         << "\nphi(n): " << getPhi()
         << "\npublic key (n, e): " << getN() << ", " << getE()
         << "\nprivate key (d or e^-1 mod phi(n)): " << getInverse() << "\n\n\n" << endl;
}

void RSA_Object::saveRSA() {
    try{
        ofstream output("RSA_Info.txt");
        if(!output.is_open())throw ("ERROR::RSA_Object::saveRSA() was unable to open RSA_Info.txt");
        else{
            output << getN() << "\n" << getE() << "\n" << getInverse() << endl;
        }
        output.close();
    }catch(const char *msg){
        cerr << msg << endl;
    }
}

//gets length of file
long RSA_Object::getFileLength(string filename){
    struct stat stat_buf;
    int rc = stat(filename.c_str(), &stat_buf);
    return rc == 0 ? stat_buf.st_size : -1;
}

/*char* RSA_Object::loadFileToMemory(string filename, ifstream fileIn){
    //get size of file
    ulong64 buffSize = getFileSize(filename);
    //check for overflow and negative values-----------------------
    //allocate dynamic memory and load file
    char *buff;
    buff = (char*)malloc(buffSize+10);
    string input;
    while(fileIn >> input){
        input+=' ';
        strncpy(buff,input.data(),input.length());
        cout << input;
    }
    return buff;
}*/

/* Testing squareAndMultiplyUpdated
int main() {
    RSA_Object rsa;
    ulong64 x = 3;
    ulong64 h = 13;
    ulong64 p = 25;
    ulong64 result = rsa.squareAndMultiplyUpdated(x, h, p);
    cout << "\nResult: [" << result << "]\n" << endl;
    return 0;
}*/
