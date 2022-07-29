#include <iostream>
#include <string>
#include <limits>
#include "RSA_Object.hpp"
#include "RSA_Walk.hpp"

using namespace std;

//to compile g++ main.cpp RSA_Walk.cpp RSA_Object.cpp -o test.exe
void RSA_Walk::rsaPrimer(){
    RSA_Object rsa;
    int input;
    cout << "\n\n\n\n\n" << endl;
    cout << "\t\t*********************************************\n"
         << "\t\t****** RSA Key Generation Walk Through ******\n"
         << "\t\t*********************************************" << endl;

    //intro to rsa math (quick) the general background
    cout << "\n\n\tRSA is a versatile encryption tool used for encryption/decryption, symmetric\n"
         << "key generation, and digital signatures. What makes RSA secure? At it's core, RSA\n"
         << "relies on the fact that its very difficult to figure out (or factor) what two\n"
         << "primes were multiplied together to get n. Typically RSA relies on VERY large \n"
         << "prime numbers. We're talking 1024-bit long numbers (at a minimum).. To put that\n"
         <<"in perspective, 2,147,483,693 is only 32-bits long." << endl;

    //explain the variable names
    cout << "\tDuring the following walkthrough, we will use variable names that aren't readily\n"
         << "understood. So to start we will go over them.\n\n"
         << "p and q:\n\tThese are simply two large prime numbers.\n\n"
         << "n:\n\tThis is just the product of p and q. This is where RSA gets its security.\n"
         << "\tRemember that knowing only n, its very difficult to figure out p and q.\n" << endl;

    pause();//-------------page break-------------------

    cout << "phi(n):\n\tThis is shorthand for Euler's totient function which counts the number of \n"
         << "\tpositive integers less than n that are coprime to n.\n\n"
         << "e:\n\tThis is your public key value that is in the range {1, ..., phi(n-1)} and where \n"
         << "\tgcd(e, phi(n)) = 1. Which simply means they are relatively prime to eachother.\n\n"
         << "inverse:\n\tThis is your private key. This is computed using the extended euclidean "
         << "algorithm,\n\twhich employes the square and multiply algorithm for fast "
         << "exponentiation.\n\n" << endl;

    pause();//-------------page break-------------------

    //-------------------------pick primes -----------------------------------------
    cout << "The following is a list of numbers are predetermined 16-bit primes. You will choose two\n"
         << "of them to be used in the computation of n.\n**You cannot choose the same prime twice.\n\n" << endl;
    vector<int> inputs;
    rsa.displayPrimes();
    bool cont = true;
    do {
        try{
            for(int i = 0 ; i < 2 ; i++){
                cout << "\nPlease enter the number of a prime from the above list (1-20): ";
                if(cin >> input){
                    if(input < 1 || input > 20) {
                        cont = false;
                        throw "\nOut of range (1-20).\n";
                        break;
                    }else
                        inputs.push_back(input);
                    //check for letters
                }else{
                    cont = false;
                    throw "\nError. Letters not allowed here.\n";
                    break;
                }
                cont = true;
            }
            //check that p and q are not equal
            if(inputs[0] == inputs[1]){
                cont = false;
                throw "\nCannot use the same prime number twice.\n";
            }
        }catch(const char *msg){
            cin.clear();
            cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            inputs.clear();
            cerr << msg << endl;
        }
    }while(!cont);
    rsa.setPandQ(inputs[0],inputs[1]);

    cout << "\np: " << rsa.primes.at(inputs[0]-1) << "\nq: " << rsa.primes.at(inputs[1]-1) << endl;

    //-------------enf of pick primes------------------------

    //-----------no input-------------------
    //compute n (p*q)
    //print out p and q to terminal
    rsa.setN();
    cout << "n = p * q" << endl;
    cout << "n: " << rsa.primes.at(inputs[0]-1) << " * " << rsa.primes.at(inputs[1]-1) << " = " << rsa.getN() << endl;

    //compute totient(n) (p-1)*(q-1)
    //print out phi to terminal
    rsa.setPhi();
    cout << "phi(n) = (p-1) * (q-1)" << endl;
    cout << "phi(" << rsa.getN() << ") = " << rsa.primes.at(inputs[0]-1)-1 << " * "
         << rsa.primes.at(inputs[1]-1)-1 << " = " << rsa.getPhi() << "\n" << endl;

    //----------end of no input------------


    pause();//-------------page break-------------------

    cout << "Now lets pick our public key. The public key is a number that meets\n"
         << "two requirements:\n"
         << "1. that it is in the range of {1, 2, ...., phi(n)-1}\n"
         << "2. that it is relatively prime to phi(n), or gcd(e, phi(n)) = 1" << endl;

    //---------------------------------public key-------------------------
    //select/pick the public exponent e
    rsa.displayPubVal();
    cout << "Please enter one of the above values: ";
    do{
        try{
            //if input is a letter
            if(cin >> input) {
                //check if input is a coprime from the list
                for (int i = 0; i < rsa.pubKeysVals.size(); i++) {
                    //cout << input1 << " == " << rsa.pubKeysVals[i] << endl;
                    if (input == rsa.pubKeysVals[i]) {
                        cont = true;
                        break;
                    } else cont = false;
                }
                if(!cont)
                    cout << "\n" << input << " isn't in this list. \nPlease enter one of the above values: ";
            }
            else throw "\nLetters no allowed. Please enter one of the above numbers: ";
        }catch(const char *msg) {
            cin.clear();
            cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            cont = false;
            cerr << msg << endl;
        }
    }while(!cont);
    rsa.setE(input);

    //---------------------end of public key-----------------

    pause();//-------------page break-------------------

    //-----------------------------private key--------------------------
    //compute the private key d (inverse)
    //using EEA, e, and phi
    cout << "Next we must compute the private key, or d. we compute this with the help\n"
         << "of the Extended Euclidean Algorithm. This efficiently computes e^-1 mod phi(n)." << endl;
    rsa.computeInverse(rsa.getE(), rsa.getPhi());

    //---------------------end private key---------------------------

    cout << "\n\n";
    pause();//-------------page break-------------------
    cout << "Next is the square and multiply algorithm which, as the name states, uses repeated squaring\n"
            << "and multiplying to speed up exponentiation which is critical in RSA encryption and\n"
            << "decryption. A short example of encryption, which utilizes the square and multiply algorithm\n"
            << "looks like :\n"
            << "plaintext: 3\n"
            << "x: 3 (plaintext input that was converted from ascii)\n"
            << "h: 13 (the public key you picked, or e)\n"
            << "p: 25 (n, or p * q)\n"
            << "h = H: 1011 (e in binary)\n"
            << "|  H  |  square  |   square mod 25 |   multiply    |  r mod 25 |\n"
            << "|     |   r=r^2  |                 | if h==1 r=r*x |           |\n"
            << "|  1  |    -     |        -        |      -        |   r=x=3   |\n"
            << "|  1  |  3*3=9   |        9        |      27       |     2     |\n"
            << "|  0  |  2*2=4   |        4        |      ---      |     4     |\n"
            << "|  1  |  4*4=16  |        16       |       48      |     23    |\n"
            << "result: 32\n"
            << "encrypted (ciphertext): 23\n\n"
            << "To decrypt you would go through the same process but with x, h, and p changed.\n"
            << "x: 23 (ciphertext input that was converted from ascii)\n"
            << "h:  (the private key you computed, or d)\n"
            << "p:  (n, or p * q)" << endl;


    pause();//-------------page break-------------------

    //------------------------encryption and decryption test----------------
    cout << "\n\n\n\t\t*********************************************\n"
         << "\t\t****** TEST TEST TEST   TEST TEST TEST ******\n"
         << "\t\t*********************************************" << endl;

    long64 plaintext = 999999999;
    cout << "plaintext: " << plaintext << endl;
    long64 ciphertext = rsa.encrypt(plaintext, rsa.getE(), rsa.getN());
    cout << "encrypted (ciphertext): " << ciphertext << endl;

    //take in ciphertext (y)
    plaintext = rsa.decrypt(ciphertext, rsa.getInverse(), rsa.getN());
    cout << "decrypted (plaintext): " << plaintext << endl;

    //------------------------end encryption and decryption test----------------

    rsa.toString();
    rsa.saveRSA();
    delete &rsa;
}

void RSA_Walk::pause(){
    fflush(stdin);
    printf("Hit enter to continue");
    while(true){
        char in;
        in = fgetc(stdin);
        if(in == 0X0A){
            printf("\b\n");
            break;
        }
    }
}