/* MD5 implementation - depricated and home rolled. do not use anywhere
   important.

The MIT License (MIT)

Copyright (c) 2013 Joe Jordan

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

 */

#include <stdlib.h>
#include <limits.h>
#include <math.h>

#define uchar unsigned char
#define uint unsigned int
#define ulong unsigned long

/* crypto uses LEFT_CIRCULAR_ROTATE, which has an x86 instruction but no C 
   operator. We define it as a macro here (OS X systems don't have a bitops.h).
   good compilers know to optimise this down to a single x86 instruction.
 */

#define LCROT(VAL, SH) (VAL << SH) | (VAL >> (sizeof(VAL)*CHAR_BIT - SH))

/* MD5 defines some chewing functions: */

#define F(X, Y, Z) X & Y | ~X & Z
#define G(X, Y, Z) X & Z | Y & ~Z
#define H(X, Y, Z) X ^ Y ^ Z
#define I(X, Y, Z) Y ^ (X & ~Z)

/* and some rather fiddly operations */
#define BRACKET_1(A, B, C, D, K, S, STI) macro_temp = (A + F(B, C, D) + buf[K] + s_t[STI-1]); \
  A = B + LCROT(macro_temp, S)

#define BRACKET_2(A, B, C, D, K, S, STI) macro_temp = (A + G(B, C, D) + buf[K] + s_t[STI-1]); \
  A = B + LCROT(macro_temp, S)

#define BRACKET_3(A, B, C, D, K, S, STI) macro_temp = (A + H(B, C, D) + buf[K] + s_t[STI-1]); \
  A = B + LCROT(macro_temp, S)

#define BRACKET_4(A, B, C, D, K, S, STI) macro_temp = (A + I(B, C, D) + buf[K] + s_t[STI-1]); \
  A = B + LCROT(macro_temp, S)

/* and a sine table: */

uint s_t[64];

void build_sin_table() {
  const unsigned long long factor = 4294967296;
  
  uint i;
  
  for (i = 0; i < 64; i++) {
    s_t[i] = (uint)(abs(sin((double)i)) * factor);
  }
}

/* we also use some helper functions to avoid assuming things about endien-ness: */
uint bytes_to_int(uchar* bytes) {
  /* low order bytes are earlier in our input. */
  return ((uint)bytes[0]) | ((uint)bytes[1] * 255) | ((uint)bytes[2] * 65536) | ((uint)bytes[3] * 16777216);
}

void int_to_bytes(uint i, uchar* target) {
  target[0] = i % 255;
  target[1] = (i / 255) % 255;
  target[2] = (i / 65536) % 255;
  target[3] = (i / 16777216) % 255;
}


void c_md5(uchar* msg, long int initial_len, unsigned char* digest) {
  
  /* first, check if the sin table is uninitialised, and initialise it if not: */
  if (!s_t[0]) {
    build_sin_table();
  }
  
  /* define a local variable used in the bracket functions: */
  uint macro_temp;
  
  /* 64 bits for the length, plus a 1 at the start = 65. */
  long int padded_bit_len = initial_len * CHAR_BIT + 65;
  padded_bit_len += padded_bit_len / 512;
  uint tail_byte_len = padded_bit_len / CHAR_BIT - initial_len;
  
  /* allocate a new buffer*/
  unsigned char* tail = (unsigned char*)malloc(sizeof(char) * tail_byte_len);
  
  int i;
  for (i = 0; i < tail_byte_len; i++) tail[i] = 0;
  
  /* write the initial 1: */
  tail[0] = 0x80;
  
  /* and the 64 bit length, where byte order is specified as smaller first: */
  int_to_bytes((initial_len * CHAR_BIT) % 4294967296, tail + (tail_byte_len-8));
  int_to_bytes((initial_len * CHAR_BIT) / 4294967296, tail + (tail_byte_len-4));
  
  /* initialise the hard-coded digest starting point: */
  digest[0]  = 0x01;
  digest[1]  = 0x23;
  digest[2]  = 0x45;
  digest[3]  = 0x67;

  digest[4]  = 0x89;
  digest[5]  = 0xab;
  digest[6]  = 0xcd;
  digest[7]  = 0xef;

  digest[8]  = 0xfe;
  digest[9]  = 0xdc;
  digest[10] = 0xba;
  digest[11] = 0x98;

  digest[12] = 0x76;
  digest[13] = 0x54;
  digest[14] = 0x32;
  digest[15] = 0x10;
  
  /* MD5 uses 32-bit integer arithmetic, although its inputs and outputs are
     8-bit bytes. The byte order is specified, but we convert from those bytes 
     to uints to actually perform the calculations. For this purpose:
   */
  uint A, B, C, D;
  uint cache[4];
  
  A = bytes_to_int(digest);
  B = bytes_to_int(digest + 4);
  C = bytes_to_int(digest + 8);
  D = bytes_to_int(digest + 12);
  
  /* we need a 512-bit (16-int) buffer for each round: */
  uint buf[16];
  uchar tmp[4];
  long int round;
  
  long int last_round = padded_bit_len / 512 - 1;
  int local_tail_start = 64 - tail_byte_len;
  
  for (round = 0; round < padded_bit_len / 512; round++) {
    
    /* copy the next bytes into the buffer, handling the tail correctly */
    
    if (round < last_round) {

      for (i = 0; i < 16; i++) buf[i] = bytes_to_int(msg + (round*16 + i) * 4);

    } else {

      for (i = 0; i < 64; i++) {
        if (i < local_tail_start) {

          tmp[i%4] = msg[round*64 + i];

        } else {

          tmp[i%4] = tail[i - local_tail_start];

        }
        
        if (i % 4 == 3) {
          buf[i/4] = bytes_to_int(tmp);
        }
      }
    }
    
    /* cache the old values for use later: */
    cache[0] = A;
    cache[1] = B;
    cache[2] = C;
    cache[3] = D;
    
    BRACKET_1(A,B,C,D,  0,  7,  1);
    BRACKET_1(D,A,B,C,  1, 12,  2);
    BRACKET_1(C,D,A,B,  2, 17,  3);
    BRACKET_1(B,C,D,A,  3, 22,  4);
    BRACKET_1(A,B,C,D,  4,  7,  5);
    BRACKET_1(D,A,B,C,  5, 12,  6);
    BRACKET_1(C,D,A,B,  6, 17,  7);
    BRACKET_1(B,C,D,A,  7, 22,  8);
    BRACKET_1(A,B,C,D,  8,  7,  9);
    BRACKET_1(D,A,B,C,  9, 12, 10);
    BRACKET_1(C,D,A,B, 10, 17, 11);
    BRACKET_1(B,C,D,A, 11, 22, 12);
    BRACKET_1(A,B,C,D, 12,  7, 13);
    BRACKET_1(D,A,B,C, 13, 12, 14);
    BRACKET_1(C,D,A,B, 14, 17, 15);
    BRACKET_1(B,C,D,A, 15, 22, 16);
    
    BRACKET_2(A,B,C,D,  1,  5, 17);
    BRACKET_2(D,A,B,C,  6,  9, 18);
    BRACKET_2(C,D,A,B, 11, 14, 19);
    BRACKET_2(B,C,D,A,  0, 20, 20);
    BRACKET_2(A,B,C,D,  5,  5, 21);
    BRACKET_2(D,A,B,C, 10,  9, 22);
    BRACKET_2(C,D,A,B, 15, 14, 23);
    BRACKET_2(B,C,D,A,  4, 20, 24);
    BRACKET_2(A,B,C,D,  9,  5, 25);
    BRACKET_2(D,A,B,C, 14,  9, 26);
    BRACKET_2(C,D,A,B,  3, 14, 27);
    BRACKET_2(B,C,D,A,  8, 20, 28);
    BRACKET_2(A,B,C,D, 13,  5, 29);
    BRACKET_2(D,A,B,C,  2,  9, 30);
    BRACKET_2(C,D,A,B,  7, 14, 31);
    BRACKET_2(B,C,D,A, 12, 20, 32);
    
    BRACKET_3(A,B,C,D,  5,  4, 33);
    BRACKET_3(D,A,B,C,  8, 11, 34);
    BRACKET_3(C,D,A,B, 11, 16, 35);
    BRACKET_3(B,C,D,A, 14, 23, 36);
    BRACKET_3(A,B,C,D,  1,  4, 37);
    BRACKET_3(D,A,B,C,  4, 11, 38);
    BRACKET_3(C,D,A,B,  7, 16, 39);
    BRACKET_3(B,C,D,A, 10, 23, 40);
    BRACKET_3(A,B,C,D, 13,  4, 41);
    BRACKET_3(D,A,B,C,  0, 11, 42);
    BRACKET_3(C,D,A,B,  3, 16, 43);
    BRACKET_3(B,C,D,A,  6, 23, 44);
    BRACKET_3(A,B,C,D,  9,  4, 45);
    BRACKET_3(D,A,B,C, 12, 11, 46);
    BRACKET_3(C,D,A,B, 15, 16, 47);
    BRACKET_3(B,C,D,A,  2, 23, 48);
    
    BRACKET_4(A,B,C,D,  0,  6, 49);
    BRACKET_4(D,A,B,C,  7, 10, 50);
    BRACKET_4(C,D,A,B, 14, 15, 51);
    BRACKET_4(B,C,D,A,  5, 21, 52);
    BRACKET_4(A,B,C,D, 12,  6, 53);
    BRACKET_4(D,A,B,C,  3, 10, 54);
    BRACKET_4(C,D,A,B, 10, 15, 55);
    BRACKET_4(B,C,D,A,  1, 21, 56);
    BRACKET_4(A,B,C,D,  8,  6, 57);  
    BRACKET_4(D,A,B,C, 15, 10, 58);
    BRACKET_4(C,D,A,B,  6, 15, 59);
    BRACKET_4(B,C,D,A, 13, 21, 60);
    BRACKET_4(A,B,C,D,  4,  6, 61);  
    BRACKET_4(D,A,B,C, 11, 10, 62);
    BRACKET_4(C,D,A,B,  2, 15, 63);
    BRACKET_4(B,C,D,A,  9, 21, 64);
    
    
    /* finally, add the cached values back into the main variables: */
    A += cache[0];
    B += cache[1];
    C += cache[2];
    D += cache[3];
    
  }
  
  /* copy the final values back into the byte array: */
  int_to_bytes(A, digest);
  int_to_bytes(A, digest + 4);
  int_to_bytes(A, digest + 8);
  int_to_bytes(A, digest + 12);
}
