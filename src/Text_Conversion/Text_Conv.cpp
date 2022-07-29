#include "Text_Conv.hpp"
#include <fstream>
#include <string>
#include <vector>
#include <iostream>
#include <sstream>
#include <exception>

using namespace std;

string Text_Conv::messageConvToDec(string message){
    std::vector<int> str;
    string output;
    for(int i = 0 ; i < message.length(); i++){
        str.push_back((int)message[i]);
        if((int)message[i] < 100)
            output += '0'+ to_string((str[i]));
        else
            output += to_string((str[i]));
    }
    return output;
}

string Text_Conv::decConvToMessage(string message){
    string converted, word;
    int ch;
    istringstream strStream(message);
    for(int i = 0 ; i < message.length(); i+=3){
        word = message.substr(i,3);
        ch = atoi(word.c_str());
        converted += (char)ch;
    }
    return converted;
}

string Text_Conv::fileConvToDec(string inFile, string outFile){
    fstream fileIn(inFile);
    fstream converted(outFile);
    try{
        if(!fileIn.is_open())throw "ERROR::Text_Conv::fileConvToDec::could not oen input file";
        if(!converted.is_open())throw "ERROR::Text_Conv::fileConvToDec::could not oen input file";
        else{
            cout << "converting file" << endl;
            string input;
            while(fileIn >> input){
                string ws = "032";
                string output = messageConvToDec(input);
                converted << output+ws;
            }
        }
    }catch(const char *msg){
        cerr << msg << endl;
    }catch(std::exception& msg){
        cerr << msg.what() << endl;
    }
    fileIn.close();
    converted.close();
    return outFile;
}

string Text_Conv::fileConvToAscii(string inFile, string outFile){
    fstream fileIn(inFile);
    fstream converted(outFile);
    try{
        if(!fileIn.is_open())throw "ERROR::Text_Conv::fileConvToAscii() Unable to open input file.";
        if(!converted.is_open())throw "ERROR::Text_Conv::fileConvToAscii() Unable to open output file.";
        string input;
        while(fileIn >> input){
            string output = decConvToMessage(input);
            converted << output;
        }
    }catch(const char *msg){
        cerr << msg << endl;
    }catch(std::exception& msg){
        cerr << msg.what() << endl;
    }
    fileIn.close();
    converted.close();
    return outFile;
}