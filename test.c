
#define _FILE_OFFSET_BITS 64

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <emmintrin.h>
#include <stddef.h>

#define TEST_BLOCKLEN 16
#define TEST_keyExpSize 176

struct TEST_ctx
{
  uint8_t Rc[TEST_keyExpSize];
  uint8_t Iv[TEST_BLOCKLEN];
};

#define Nb 4
#define Nk 4
#define Nr 1

typedef uint8_t state_t[4][4];

static const uint8_t box[256] = {
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

static const uint8_t Rcon[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

#define getValue(num) (box[(num)])

static void KeyExpansion(uint8_t* Rc, const uint8_t* Key)
{
  unsigned i, j, k;
  uint8_t tempa[4];
  
  for (i = 0; i < Nk; ++i)
  {
    Rc[(i * 4) + 0] = Key[(i * 4) + 0];
    Rc[(i * 4) + 1] = Key[(i * 4) + 1];
    Rc[(i * 4) + 2] = Key[(i * 4) + 2];
    Rc[(i * 4) + 3] = Key[(i * 4) + 3];
  }

  for (i = Nk; i < Nb * (Nr + 1); ++i)
  {
    {
      k = (i - 1) * 4;
      tempa[0]=Rc[k + 0];
      tempa[1]=Rc[k + 1];
      tempa[2]=Rc[k + 2];
      tempa[3]=Rc[k + 3];

    }

    if (i % Nk == 0)
    {
      {
        const uint8_t u8tmp = tempa[0];
        tempa[0] = tempa[1];
        tempa[1] = tempa[2];
        tempa[2] = tempa[3];
        tempa[3] = u8tmp;
      }

      {
        tempa[0] = getValue(tempa[0]);
        tempa[1] = getValue(tempa[1]);
        tempa[2] = getValue(tempa[2]);
        tempa[3] = getValue(tempa[3]);
      }

      tempa[0] = tempa[0] ^ Rcon[i/Nk];
    }
    j = i * 4; k=(i - Nk) * 4;
    Rc[j + 0] = Rc[k + 0] ^ tempa[0];
    Rc[j + 1] = Rc[k + 1] ^ tempa[1];
    Rc[j + 2] = Rc[k + 2] ^ tempa[2];
    Rc[j + 3] = Rc[k + 3] ^ tempa[3];
  }
}

void TEST_init_ctx_iv(struct TEST_ctx* ctx, const uint8_t* key, const uint8_t* iv)
{
  KeyExpansion(ctx->Rc, key);
  memcpy (ctx->Iv, iv, TEST_BLOCKLEN);
}

static void AddRc(uint8_t round, state_t* state, const uint8_t* Rc)
{
  uint8_t i,j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[i][j] ^= Rc[(round * Nb * 4) + (i * Nb) + j];
    }
  }
}

static void SubBytes(state_t* state)
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[j][i] = getValue((*state)[j][i]);
    }
  }
}

static void ShiftRows(state_t* state)
{
  uint8_t temp;

  temp           = (*state)[0][1];
  (*state)[0][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[3][1];
  (*state)[3][1] = temp;

  temp           = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp           = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  temp           = (*state)[0][3];
  (*state)[0][3] = (*state)[3][3];
  (*state)[3][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[1][3];
  (*state)[1][3] = temp;
}

static uint8_t xtime(uint8_t x)
{
  return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

static void MixColumns(state_t* state)
{
  uint8_t i;
  uint8_t Tmp, Tm, t;
  for (i = 0; i < 4; ++i)
  {  
    t   = (*state)[i][0];
    Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3] ;
    Tm  = (*state)[i][0] ^ (*state)[i][1] ; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][1] ^ (*state)[i][2] ; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][2] ^ (*state)[i][3] ; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][3] ^ t ;              Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp ;
  }
}

static void Ci(state_t* state, const uint8_t* Rc)
{
  uint8_t round = 0;

  AddRc(0, state, Rc);

  for (round = 1; ; ++round)
  {
    SubBytes(state);
    ShiftRows(state);
    if (round == Nr) {
      break;
    }
    MixColumns(state);
    AddRc(round, state, Rc);
  }

  AddRc(Nr, state, Rc);
}

void TEST_next_iv(struct TEST_ctx *ctx)
{
  Ci((state_t*)ctx->Iv, ctx->Rc);
}

unsigned char* xorcpy(unsigned char* dst, const unsigned char* src, unsigned block_size)
{
    __m128i* mto = (__m128i*)dst;
    const __m128i* mfrom = (__m128i*)(src);
    for(int i=(block_size / sizeof(__m128i) - 1); i>=0; i--)
    {
        __m128i xmm1 = _mm_loadu_si128(mto);
        __m128i xmm2 = _mm_loadu_si128(mfrom);

        xmm1 = _mm_xor_si128(xmm1, xmm2);
        _mm_storeu_si128(mto, xmm1);
        ++mto;
        ++mfrom;
    }

    unsigned char* cto = (unsigned char*) mto;
    const unsigned char* cfrom = (const unsigned char*)mfrom;
    for(int i=(block_size % sizeof(__m128i)) - 1; i>=0; i--)
    {
        *cto++ ^= (*cfrom++);
    }
    return dst;
}

#define BUF_LEN (1024*1024)

int main(int argc, char *argv[])
{
    FILE *fin1 = NULL;
    FILE *fin2 = NULL;
    uint8_t *buf1 = NULL;
    uint8_t *buf2 = NULL;
    uint8_t *xorbuf = NULL;

    int iflag = 0;
    char *filename1 = NULL;
    char *filename2 = NULL;
    int index;
    int c;

    opterr = 0;
    while ((c = getopt (argc, argv, "a:b:")) != -1)
        switch (c)
        {
            case 'a':
                filename1 = optarg;
                break;
            case 'b':
                filename2 = optarg;
                break;
            case '?':
                if (optopt == 'a' || optopt == 'b')
                    fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                else
                    fprintf (stderr,
                            "Unknown option character `\\x%x'.\n",
                            optopt);
                return 1;
            default:
                return 1;
        }

    buf1 = (uint8_t *)malloc(BUF_LEN);
    if (!buf1)
        return 2;

    buf2 = (uint8_t *)malloc(BUF_LEN);
    if (!buf2)
        return 2;

    fin1 = fopen(filename1, "rb");
    fin2 = fopen(filename2, "rb");

    uint8_t key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    struct TEST_ctx ctx;

    TEST_init_ctx_iv(&ctx, key, iv);

    xorbuf = (uint8_t *)malloc(BUF_LEN);
    if (!xorbuf)
        return 2;

    memset(xorbuf, 0xff, BUF_LEN);

    size_t len1 = 1;
    size_t len2 = 1;

    int ret = 0;

    while (len1 != 0)
    {
        for(long i=0;i<BUF_LEN/16;i++)
        {
            TEST_next_iv(&ctx);
            memcpy(&xorbuf[i*16], ctx.Iv, 16);
        }
        len1 = fread(buf1, 1, BUF_LEN, fin1);
        len2 = fread(buf2, 1, BUF_LEN, fin2);
        if (len1 != len2)
        {
            ret = 1;
            break;
        }
        xorcpy(buf1, buf2, len1);
        if (memcmp(buf1, xorbuf, len1) != 0)
        {
            ret = 1;
            break;
        }
    }

    if (!ret)
    {
        printf("OK\n");
    }
    else
    {
        size_t i;
        off_t pos1 = ftello(fin1)-len1;
        off_t pos2 = ftello(fin2)-len1;
        for (i=0;i<len1;i++)
        {
            if(buf1[i] != xorbuf[i])
                break;
        }
        printf("Mismatch %jd %jd\n", (intmax_t)pos1+i, (intmax_t)pos2+i);
    }

    free(xorbuf);
    free(buf1);
    free(buf2);

    fclose(fin1);
    fclose(fin2);

    return ret;
}
