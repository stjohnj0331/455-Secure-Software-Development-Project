# CS 455 Spring '22 RSA implementation

Developed by Travis Reid Hopkins, Kara Martin, and Justin St. John.

RSA implementation that aims to educate the user about the basic math and algorithms behind it, implemented with the secure techniques discussed in class.

## Usage

```
rsa.exe -h                      display help message
rsa.exe [options] ... [file]    operate on a file
```

## Options

```
-p    walk through key generation
-e    encrypt plaintext
-d    decrypt ciphertext
-s    sign message
-v    verify message
-f <file>      specify file to operate on
-o <output>    output location
```

## Build instructions

To build `rsa.exe`, run the following script:
```
g++ -o rsa.exe main.cpp RSA_Skeleton/.cpp RSA_Skeleton/.cpp Text_Conversion/*.cpp
```
