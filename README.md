Obscura 🔐
Obscura is a small tool that loads modules (.so files) from a folder called modules.
Right now it comes with encryption and decryption modules (AES based) to protect files.


how it works:
-it scans the modules folder for .so files
-loads them with dlopen
-keeps them in a linked list (name + handler)
-you can then use the functions from those modules


files:
loader.c -> the loader program
modules/ -> where .so modules live (enc.so, dec.so)
include/ -> header files
Makefile -> just type make to build everything


1-Build
/make
-This will build the loader and the modules.
-
2-Run 
/loader [filename]
-

3-Example :
/loader Mysecret.txt
-


Why the name?
Because the tool hides / protects files (like something obscure or hidden).
-



