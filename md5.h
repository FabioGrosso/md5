#ifndef MD5_H
#define MD5_H

typedef struct
{
    unsigned int cnt[2];
    unsigned int s[4];
    unsigned char b[64];
}MD5_CTX;

#define F(x,y,z) ((x & y) | (~x & z))
#define G(x,y,z) ((x & z) | (y & ~z))
#define H(x,y,z) (x^y^z)
#define I(x,y,z) (y ^ (x | ~z))
#define ROTATE_LEFT(x,n) ((x << n) | (x >> (32-n)))
#define F_F(a,b,c,d,x,s,ac)\
{\
    a += F(b,c,d) + x + ac;\
    a = ROTATE_LEFT(a,s);\
    a += b;\
}
#define G_G(a,b,c,d,x,s,ac) \
{\
    a += G(b,c,d) + x + ac;\
    a = ROTATE_LEFT(a,s);\
    a += b;\
}
#define H_H(a,b,c,d,x,s,ac)\
{\
    a += H(b,c,d) + x + ac;\
    a = ROTATE_LEFT(a,s);\
    a += b;\
}
#define I_I(a,b,c,d,x,s,ac)\
{\
    a += I(b,c,d) + x + ac;\
    a = ROTATE_LEFT(a,s);\
    a += b;\
}

void Update(MD5_CTX *ctxt,unsigned char *in,unsigned int inlen);
void Decode(unsigned int *out,unsigned char *in,unsigned int l);
void Transform(unsigned int state[4],unsigned char block[64]);
void Init(MD5_CTX *ctxt);
void Final(MD5_CTX *ctxt,unsigned char digest[16]);
void Encode(unsigned char *out,unsigned int *in,unsigned int l);


#endif  