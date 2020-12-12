


#include "md5.h"
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
using namespace std;

int main(int argc, char *argv[])
{
    string str;
    static const char alphanum[] =
            "0123456789"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz";

    srand( (unsigned) time(NULL) * getpid());

    for (int i = 0; i < 8; ++i)
        str += alphanum[rand() % (sizeof(alphanum) - 1)];


    char pass[40];
    cin >> pass;
    string password = pass;

    cout << "passwd :";
    printf("%s\n",pass);
    cout << "salt :";
    cout << str << endl;
    password.append(str);

    char encrypt[40];
    int j;
    for(j=0; j<password.length(); ++j)
    {
        encrypt[j] = password[j];
    }
    encrypt[j] = '\0';
    cout << "salted passwd :";
    printf("%s\n",encrypt);

    MD5_CTX md5;
    MD5Init(&md5);
    int i;
    unsigned char decrypt[16];

    MD5Update(&md5, reinterpret_cast<unsigned char *>(pass), strlen((char *)pass));
    MD5Final(&md5,decrypt);
    printf("Before encryption: %s\n after encryption (16-word) : ",pass);
    for(i=4;i<12;i++)
    {
        printf("%02x",decrypt[i]);
    }

    printf("\n after encryption (32-word) : ");
    for(i=0;i<16;i++)
    {
        printf("%02x",decrypt[i]);
    }

    MD5Init(&md5);
    MD5Update(&md5, reinterpret_cast<unsigned char *>(encrypt), strlen((char *)encrypt));
    MD5Final(&md5,decrypt);
    printf("\nBefore encryption (salted): %s\n after encryption (16-word) : ",encrypt);
    for(i=4;i<12;i++)
    {
        printf("%02x",decrypt[i]);
    }

    printf("\n after encryption (32-word) : ");
    for(i=0;i<16;i++)
    {
        printf("%02x",decrypt[i]);
    }

    getchar();
    return 0;
}

