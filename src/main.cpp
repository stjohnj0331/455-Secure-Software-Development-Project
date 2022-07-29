#include "info.hpp"
#include "RSA_Skeleton/RSA_Walk.hpp"
#include "RSA_Skeleton/RSA_Object.hpp"
#include <iostream>
#include <fstream>

using namespace std;

/*
 * Entry point into program.
 */
int main(int argc, char* argv[]) {
	setflags(argc, argv); // action/file/keypair all selected

	// show all unflagged arguments
	for (int i = optind; i < argc; i++) { // optind is defined by getopts
		printf ("Non-option argument %s\n", argv[i]);
	}


	// put more functions in here for actions
    // check for existence of rsa key. can likely be broken out into another function
    ulong64 n,e,d;
    bool keyFlag = false;
    try{
        if(!ifstream ("RSA_Info.txt")){
            throw ("\nNo key pair detected, please run the program with \nthe -p flag to generate a key pair\n");
        }else{
            cout << "\n------key pair detected------\n" << endl;
            //open rsa_info
            ifstream rsa_info("RSA_Info.txt");
            //get rsa key pairs
            rsa_info >> n;
            rsa_info >> e;
            rsa_info >> d;
            keyFlag = true;
        }
    }catch(const char* msg){
        cerr << msg << endl;
    }

    RSA_Walk rsa_walk;//----------------------------------------
    Text_Conv textConv;
    ifstream fileIn;
    ofstream fileOut;

	switch(action) {
		case NOACTION:
			displayactions();
			break;
		case HELP:
			displayhelp();
			break;
        case KEY:
            rsa_walk.rsaPrimer();
            break;
		case ENCRYPT:
            //check for key pair
            if(!keyFlag){
                //call RSA_Walk if key pair doesn't exist
                rsa_walk.rsaPrimer();
            }else{
                try{
                    rsa_walk.rsa_object.encryptMessage(filename,outputname,e,n);
                }catch(const char *msg){
                    cerr << msg << endl;
                }
            }
            break;
		case DECRYPT:
            //check for key pair
            if(!keyFlag){
                //call RSA_Walk if key pair doesn't exist
                rsa_walk.rsaPrimer();
            }else{
                try{
                    rsa_walk.rsa_object.decryptMessage(filename,outputname,d,n);
                }catch(const char *msg){
                    cerr << msg << endl;
                }
            }
            break;
		case SIGN:
            //check for key pair
            if(!keyFlag){
                //call RSA_Walk if key pair doesn't exist
                rsa_walk.rsaPrimer();
            }else{
                rsa_walk.rsa_object.signMessage(filename,outputname,d,n);
            }
            break;
		case VERIFY:
            //check for key pair
            if(!keyFlag){
                //call RSA_Walk if key pair doesn't exist
                rsa_walk.rsaPrimer();
            }else{
                rsa_walk.rsa_object.verifyMessage(filename,outputname,e,n);
            }
            break;
	}

	return 0; // exit happily, phew!
}

