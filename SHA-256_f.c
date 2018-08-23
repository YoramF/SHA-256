/*
 * SHA_Functions.c
 *
 *  Created on: Aug 23, 2018
 *      Author: yoram
 *
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

// Key values are already set for little endian - no need to convert!
unsigned long key [64] = {
		0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
		0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
		0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
		0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
		0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
		0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
		0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
		0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
	};

// H values are already set for little endian - no need to convert!
unsigned long H0[8] = {
		0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
	};

typedef union _Block
{
	unsigned long W[16];		// 16 words of 32 bits each
	unsigned char bytes[64]; 	// 512 bits
} Block;


// convert 8 bytes unsigned integer from little Endian to Big Endian and vise versa
unsigned long long endianCqw (unsigned long long ull)
{
	union _ull2c
	{
		unsigned long long ull;
		unsigned char c[8];
	} ull2c1, ull2c2;

	int i;

	ull2c1.ull = ull;
	for(i=0; i<8; i++)
		ull2c2.c[i] = ull2c1.c[7-i];

	return ull2c2.ull;
}

// convert 4 bytes unsigned integer from Big Endian to Little Endian and vice versa
unsigned long endianCdw (unsigned long ul)
{
	union _ul2c
	{
		unsigned long ul;
		unsigned char c[4];
	} ul2c1, ul2c2;

	int i;

	ul2c1.ul = ul;
	for (i=0; i<4; i++)
		ul2c2.c[i] = ul2c1.c[3-i];

	return ul2c2.ul;
}

// Left rotate 4 bytes word
unsigned long rotateLdw(unsigned long num, int bits)
{
  return ((num << bits) | (num >> (32 -bits)));
}

// Right rotate 4 bytes word
unsigned long rotateRdw(unsigned long num, int bits)
{
  return ((num >> bits) | (num << (32 -bits)));
}

// Ch function
unsigned long Ch (unsigned long X, unsigned long Y, unsigned long Z)
{
	return (X & Y) ^ ( ~X & Z);
}

// Maj function
unsigned long Maj (unsigned long X, unsigned long Y, unsigned long Z)
{
	return (X & Y) ^ (X & Z) ^ (Y & Z);
}

// Sigma0 function
unsigned long Sigma0 (unsigned long X)
{
	return rotateRdw(X,2) ^ rotateRdw(X,13) ^ rotateRdw(X,22);
}


//Sigma1 function
unsigned long Sigma1 (unsigned long X)
{
	return rotateRdw(X,6) ^ rotateRdw(X,11) ^ rotateRdw(X,25);
}


//sigma0 function
unsigned long sigma0 (unsigned long X)
{
	return rotateRdw(X,7) ^ rotateRdw(X,18) ^ X>>3;
}


// sigma1 function
unsigned long sigma1 (unsigned long X)
{
	return rotateRdw(X,17) ^ rotateRdw(X,19) ^ X>>10;
}


// Generate the 512bit blocks for processing
// Input parameters:
//	String message and its length
// Output parameter:
//	Pointer to first block
// Return valus: number of blocks
int prepare_blocks (char *message, int m_len, Block **bptr)
{
	int bc = m_len+9;	// we need to allocate one byte for end of message + 8 bytes for original message length
	int r;
	Block *bp;
	unsigned char *sp;
	int mi, tb;

	r = bc % 64;			// check if there is a reminder
	bc >>= 6;				// devide by 64 bytes (512 bits)
	bc += (r > 0 ? 1 : 0);	// if there is a reminder than add one more block which will be padded with Zeros

	tb = bc * sizeof(Block);

	// allocate blocks
	if (((*bptr) = malloc(tb)) == NULL)
	{
		printf("prepare_blocks: failed to allocate memory, %s\n", strerror(errno));
		return 0;
	}
	else
	{
		bp = *bptr;
		sp = (unsigned char *)bp;

		// copy message into blocks
		// to make things simple we treat all blocks as one long array of chars
		for (mi = 0; mi<m_len; mi++)
			sp[mi] = message[mi];

		// add 0x80 byte at the end of the message
		sp[mi++] = 0x80;

		// pad the rest of the block with Zeros up to last 8 bytes - leave last 8 bytes for origin message length in quadword
		tb -= 8;
		while (mi < tb)
			sp[mi++] = 0x0;

		// insert last quadword with origin message length in bits to last block
		// all words and qwords in input blocks are assumed to use BIG Endian format.
		// therefore, we must convert message length to Big Endian
 		*(unsigned long long *)&sp[mi] = endianCqw((unsigned long long) m_len*8);

		return bc;
	}
}

// main SAH-256 function.
// input parameters:
//		Messge - string
//		Message length - int
// output parameters:
//		DH - Digested Message (5 WORDs)
// Return value - True/False
int calc_hash (char *msg, int m_len, unsigned long DH[])
{
	int i, j, t;
	int bc;
	Block *bptr;
	unsigned long A, B, C, D, E, F, G, H, T1, T2;
	unsigned long W[64];

	// Generate message blocks out of input messgae
	if ((bc = prepare_blocks(msg, m_len, &bptr)) == 0)
		return 0; //  we had memory allocate error - return FALSE
	else
	{
		// Convert the input blocks from BIG Endian to Little Endian to match X86 architecture
		printf("Input message processed to blocks:\n");
		printf("----------------------------------\n");
		for (i=0; i<bc; i++)
			for (j=0; j<16; j++)
			{
				bptr[i].W[j] = endianCdw(bptr[i].W[j]);
				printf("B[%2d] W[%2d] %08X\n",i, j, bptr[i].W[j]);
			}

		// inint DH with initial values
		for (i=0; i<8; i++)
				DH[i] = H0[i];


		// Start the iterations on all blocks and calculate the HAS
		printf("\nCalculating Hash ========\n");
		printf("                  A        B        C        D        E        F        G        H\n");
		for (i=0; i<bc; i++)
		{

			// Block decomposition
			// initialze the W array with the first 16 words from current block
			for (t=0; t<16; t++)
				W[t] = bptr[i].W[t];

			// fill the rest of the 64 words buffer
			// the algorithm uses Bit ROTATE operation
			for (t=16; t<64; t++)
				W[t] = sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15])+ W[t-16];


			A = DH[0];
			B = DH[1];
			C = DH[2];
			D = DH[3];
			E = DH[4];
			F = DH[5];
			G = DH[6];
			H = DH[7];

			for (t=0; t<64; t++)
			{
				T1 = H +Sigma1(E)+ Ch(E,F,G)+ key[t] + W[t];
				T2 = Sigma0(A)+ Maj(A,B,C);
				H = G;
				G = F;
				F = E;
				E = D + T1;
				D = C;
				C = B;
				B = A;
				A = T1 + T2;

				// printout current iteration state
				printf("B[%2d] t[%2d]    %08X %08X %08X %08X %08X %08X %08X %08X\n", i, t, A, B, C, D, E, F, G, H);
			}

			DH[0] += A;
			DH[1] += B;
			DH[2] += C;
			DH[3] += D;
			DH[4] += E;
			DH[5] += F;
			DH[6] += G;
			DH[7] += H;

		}

		free(bptr);	// relese the allocated RAM
		return 1;	// the Digested 5 WORDs are DH[0-4], return TRUE
	}
}

