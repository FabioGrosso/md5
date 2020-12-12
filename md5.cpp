#include <string.h>
#include "md5.h"

unsigned char PADDING[]={0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

void Init(MD5_CTX *ctxt)
{
    ctxt->cnt[0] = 0;
    ctxt->cnt[1] = 0;
    ctxt->s[0] = 0x67452301;
    ctxt->s[1] = 0xEFCDAB89;
    ctxt->s[2] = 0x98BADCFE;
    ctxt->s[3] = 0x10325476;
}
void Update(MD5_CTX *context,unsigned char *in,unsigned int inlen)
{
    unsigned int i = 0,index = 0,partlen = 0;
    index = (context->cnt[0] >> 3) & 0x3F;
    partlen = 64 - index;
    context->cnt[0] += inlen << 3;
    if(context->cnt[0] < (inlen << 3))
        context->cnt[1]++;
    context->cnt[1] += inlen >> 29;

    if(inlen >= partlen)
    {
        memcpy(&context->b[index],in,partlen);
        Transform(context->s,context->b);
        for(i = partlen;i+64 <= inlen;i+=64)
            Transform(context->s,&in[i]);
        index = 0;
    }
    else
    {
        i = 0;
    }
    memcpy(&context->b[index],&in[i],inlen-i);
}

void Encode(unsigned char *out,unsigned int *in,unsigned int l)
{
    unsigned int j = 0,k = 0;
    while(k < l)
    {
        out[k] = in[j] & 0xFF;
        out[k+1] = (in[j] >> 8) & 0xFF;
        out[k+2] = (in[j] >> 16) & 0xFF;
        out[k+3] = (in[j] >> 24) & 0xFF;
        j++;
        k+=4;
    }
}

void Decode(unsigned int *out,unsigned char *in,unsigned int l)
{
    unsigned int j = 0,k = 0;
    while(k < l)
    {
        out[j] = (in[k]) |
                    (in[k+1] << 8) |
                    (in[k+2] << 16) |
                    (in[k+3] << 24);
        j++;
        k+=4;
    }
}

void Final(MD5_CTX *ctxt,unsigned char digest[16])
{
    unsigned int i = 0,pl = 0;
    unsigned char bit[8];
    i = (ctxt->cnt[0] >> 3) & 0x3F;
    if (i < 56)
        pl = 56-i;
    else
        pl = 120-i;
    Encode(bit,ctxt->cnt,8);
    Update(ctxt,PADDING,pl);
    Update(ctxt,bit,8);
    Encode(digest,ctxt->s,16);
}

void Transform(unsigned int s[4],unsigned char block[64])
{
    unsigned int a = s[0];
    unsigned int b = s[1];
    unsigned int c = s[2];
    unsigned int d = s[3];
    unsigned int x[64];
    Decode(x,block,64);
    F_F(a, b, c, d, x[ 0], 7, 0xd76aa478);
    F_F(d, a, b, c, x[ 1], 12, 0xe8c7b756);
    F_F(c, d, a, b, x[ 2], 17, 0x242070db);
    F_F(b, c, d, a, x[ 3], 22, 0xc1bdceee);
    F_F(a, b, c, d, x[ 4], 7, 0xf57c0faf);
    F_F(d, a, b, c, x[ 5], 12, 0x4787c62a);
    F_F(c, d, a, b, x[ 6], 17, 0xa8304613);
    F_F(b, c, d, a, x[ 7], 22, 0xfd469501);
    F_F(a, b, c, d, x[ 8], 7, 0x698098d8);
    F_F(d, a, b, c, x[ 9], 12, 0x8b44f7af);
    F_F(c, d, a, b, x[10], 17, 0xffff5bb1);
    F_F(b, c, d, a, x[11], 22, 0x895cd7be);
    F_F(a, b, c, d, x[12], 7, 0x6b901122);
    F_F(d, a, b, c, x[13], 12, 0xfd987193);
    F_F(c, d, a, b, x[14], 17, 0xa679438e);
    F_F(b, c, d, a, x[15], 22, 0x49b40821);


    G_G(a, b, c, d, x[ 1], 5, 0xf61e2562);
    G_G(d, a, b, c, x[ 6], 9, 0xc040b340);
    G_G(c, d, a, b, x[11], 14, 0x265e5a51);
    G_G(b, c, d, a, x[ 0], 20, 0xe9b6c7aa);
    G_G(a, b, c, d, x[ 5], 5, 0xd62f105d);
    G_G(d, a, b, c, x[10], 9,  0x2441453);
    G_G(c, d, a, b, x[15], 14, 0xd8a1e681);
    G_G(b, c, d, a, x[ 4], 20, 0xe7d3fbc8);
    G_G(a, b, c, d, x[ 9], 5, 0x21e1cde6);
    G_G(d, a, b, c, x[14], 9, 0xc33707d6);
    G_G(c, d, a, b, x[ 3], 14, 0xf4d50d87);
    G_G(b, c, d, a, x[ 8], 20, 0x455a14ed);
    G_G(a, b, c, d, x[13], 5, 0xa9e3e905);
    G_G(d, a, b, c, x[ 2], 9, 0xfcefa3f8);
    G_G(c, d, a, b, x[ 7], 14, 0x676f02d9);
    G_G(b, c, d, a, x[12], 20, 0x8d2a4c8a);


    H_H(a, b, c, d, x[ 5], 4, 0xfffa3942);
    H_H(d, a, b, c, x[ 8], 11, 0x8771f681);
    H_H(c, d, a, b, x[11], 16, 0x6d9d6122);
    H_H(b, c, d, a, x[14], 23, 0xfde5380c);
    H_H(a, b, c, d, x[ 1], 4, 0xa4beea44);
    H_H(d, a, b, c, x[ 4], 11, 0x4bdecfa9);
    H_H(c, d, a, b, x[ 7], 16, 0xf6bb4b60);
    H_H(b, c, d, a, x[10], 23, 0xbebfbc70);
    H_H(a, b, c, d, x[13], 4, 0x289b7ec6);
    H_H(d, a, b, c, x[ 0], 11, 0xeaa127fa);
    H_H(c, d, a, b, x[ 3], 16, 0xd4ef3085);
    H_H(b, c, d, a, x[ 6], 23,  0x4881d05);
    H_H(a, b, c, d, x[ 9], 4, 0xd9d4d039);
    H_H(d, a, b, c, x[12], 11, 0xe6db99e5);
    H_H(c, d, a, b, x[15], 16, 0x1fa27cf8);
    H_H(b, c, d, a, x[ 2], 23, 0xc4ac5665);


    I_I(a, b, c, d, x[ 0], 6, 0xf4292244);
    I_I(d, a, b, c, x[ 7], 10, 0x432aff97);
    I_I(c, d, a, b, x[14], 15, 0xab9423a7);
    I_I(b, c, d, a, x[ 5], 21, 0xfc93a039);
    I_I(a, b, c, d, x[12], 6, 0x655b59c3);
    I_I(d, a, b, c, x[ 3], 10, 0x8f0ccc92);
    I_I(c, d, a, b, x[10], 15, 0xffeff47d);
    I_I(b, c, d, a, x[ 1], 21, 0x85845dd1);
    I_I(a, b, c, d, x[ 8], 6, 0x6fa87e4f);
    I_I(d, a, b, c, x[15], 10, 0xfe2ce6e0);
    I_I(c, d, a, b, x[ 6], 15, 0xa3014314);
    I_I(b, c, d, a, x[13], 21, 0x4e0811a1);
    I_I(a, b, c, d, x[ 4], 6, 0xf7537e82);
    I_I(d, a, b, c, x[11], 10, 0xbd3af235);
    I_I(c, d, a, b, x[ 2], 15, 0x2ad7d2bb);
    I_I(b, c, d, a, x[ 9], 21, 0xeb86d391);
    s[0] += a;
    s[1] += b;
    s[2] += c;
    s[3] += d;
}  