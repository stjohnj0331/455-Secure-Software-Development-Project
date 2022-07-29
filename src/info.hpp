#include <unistd.h> // getopts

#include <string>
#include <iostream>

using namespace std;

enum actions {NOACTION, HELP, KEY, ENCRYPT, DECRYPT, SIGN, VERIFY} action; // move to header?

string filename; // file to operate on
string keyname; // keypair to operate with
string outputname; // location to send output
int keysize; // size of keys in keypair. Remove if deterministic?

/*
 * Display options used to run this program. Remember to keep options up to
 * date as behavior changes!
 */
void displayhelp() {
	// each \t rounds up to 8 whitespaces
	cout << "Usage:" << endl;
	cout << "  rsa -h                      display this message" << endl;
	cout << "  rsa [options] ... [file]    operate on a file" << endl;
	cout << "" << endl;

	cout << "Options:" << endl;
    cout << "  -p              RSA key generation walk through" << endl;
	cout << "  -e              encrypt plaintext" << endl;
	cout << "  -d              decrypt ciphertext" << endl;
	cout << "  -s              sign message" << endl;
	cout << "  -v              verify signature attached to message" << endl;
	cout << "  -f <file>       specify file to operate on" << endl;
	cout << "  -o <output>     specify location of output" << endl;
	//cout << "  -k <keypair>    specify keys to operate with" << endl;
	//cout << "  -n <keysize>    specify size of key" << endl;
}

/*
 * Display available actions to perform. Run if no flags are given.
 */
void displayactions() {
	cout << "Please specify an action to perform:" << endl;
	cout << "  -h    help" << endl;
    cout << "  -p    RSA key generation" << endl;
	cout << "  -e    encrypt" << endl;
	cout << "  -d    decrypt" << endl;
	cout << "  -s    sign" << endl;
	cout << "  -v    verify" << endl;
}

/*
 * Return true if all characters in str are digits. False otherwise. Used to
 * validate keysize flag -n.
 */
bool isValidNum(string str) {
	for (int i = 0; i < str.length(); i++) {
		if (!isdigit(str[i])) {
			return false;
		}
	}
	return true;
}

/*
 * Use getopts to parse arguments in the form of flags. Ignore non-flag
 * parameters and set action, filename, and keyname as necessary.
 * https://www.gnu.org/software/libc/manual/html_node/Example-of-Getopt.html
 */
void setflags(int ac, char* av[]) {
	opterr = 0; // not sure what this does. Something to do with getopts?

	int option; // consider moving all getopts stuff to own function?
	while ((option = getopt(ac, av, "hpedsvf:o:k:n:")) != -1) {

		// h/e/d/s/v are generic flags, f/k/o/n require arguments
		switch (option) {
			case 'h':
				action = HELP;
				break;
            case 'p':
                action = KEY;
                break;
			case 'e':
				action = ENCRYPT;
				break;
			case 'd':
				action = DECRYPT;
				break;
			case 's': // could e/d and s/v be done simultaneously? If so, split
					  // into two enums instead of one
				action = SIGN;
				break;
			case 'v':
				action = VERIFY;
				break;
			case 'f':
				filename = optarg;
				cout << filename << endl;
				break;
			case 'o':
				outputname = optarg;
				cout << outputname << endl;
				break;
			/*case 'k':
				keyname = optarg;
				cout << keyname << endl;
				break;
			case 'n':
				if (isValidNum(optarg)) {
					keysize = atoi(optarg);
				}
				else {
					fprintf(stderr, "%s is not a valid number\n", optarg);
				}
				break;*/
			case '?':
				// options requiring arguments failed for some reason!
				// consider replacing all this with displayhelp() text?
				// I remember there being some kind of standardized error
				// message codes that could be returned here?
				// or should this be replaced with C++ exceptions?

				if (optopt == 'f' || optopt == 'k' || optopt == 'o' || optopt == 'n') { // no parameters given!
					fprintf(stderr, "-%c requires an argument\n", optopt); // TODO: move to CPP exceptions hierarchy?
				}
				else if (isprint(optopt)) { // check if printable before printing error
					fprintf(stderr, "Unknown option `-%c'.\n", optopt);
				}
				else { // character is unprintable, womp womp. Thank you stdlib!
					fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
				}
				displayhelp(); // show how to actually use this program
				exit(1); // ouch! Use perror or fprintf for reporting here?
			default:
				abort(); // messy quit on failed case match
		}
	}
}

