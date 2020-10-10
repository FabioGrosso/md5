
#include "md5.h"
#include <iostream>

int main(int argc, char *argv[])
{
    MD5_CTX md5;
    MD5Init(&md5);
    int i;
    unsigned char encrypt[] ="CPT_S-527_Daoce_wang_first_Milestone";//c860afddc59de2dc8d7690b32ae60a57(32) c59de2dc8d7690b3(16)
    unsigned char decrypt[16];
    MD5Update(&md5,encrypt,strlen((char *)encrypt));
    MD5Final(&md5,decrypt);
    printf("Before encryption: %s\n after encryption (16-bit) : ",encrypt);
    for(i=4;i<12;i++)
    {
        printf("%02x",decrypt[i]);
    }

    printf("\nBefore encryption: %s\n after encryption (32-bit) : ",encrypt);
    for(i=0;i<16;i++)
    {
        printf("%02x",decrypt[i]);
    }

    getchar();

    return 0;
}