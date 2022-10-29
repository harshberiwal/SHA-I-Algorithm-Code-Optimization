/*
 * pbkdf2.c
 *
 * A perfectly legitimate implementation of HMAC and PBKDF2, but based
 * on the "ISHA" insecure and bad hashing algorithm.
 * 
 * Author: Howdy Pierce, howdy.pierce@colorado.edu
 */

#include <assert.h>
#include "string.h"
#include "pbkdf2.h"
#include "ticktime.h"

#define TRIM 1
/*uint32_t count_F = 0;
uint32_t total_F = 0;

uint32_t count_Pb = 0;
uint32_t total_Pb = 0;

uint32_t count_H = 0;
uint32_t total_H = 0;*/

uint8_t F_called = 0;

/*
 * See function description in pbkdf2.h
 */
void hmac_isha(const uint8_t *key, size_t key_len,
    const uint8_t *msg, size_t msg_len,
    uint8_t *digest)
{
 /* uint32_t duration_H_end =0;
  uint32_t duration_H =0;
  duration_H = get_timer();*/
  static uint8_t ipad[ISHA_BLOCKLEN];
  static uint8_t opad[ISHA_BLOCKLEN];
  static uint8_t keypad[ISHA_BLOCKLEN];
  uint8_t inner_digest[ISHA_DIGESTLEN];
  size_t i;
  ISHAContext ctx;
  ISHAContext ipad_ctx, opad_ctx;
  if(F_called == 0) {
		memcpy(keypad,key,key_len);
		memset((keypad+key_len), 0, (ISHA_BLOCKLEN - key_len));
		// XOR key into ipad and opad
		for (i=0; i<key_len; i++) {
			ipad[i] = keypad[i] ^ 0x36;
			opad[i] = keypad[i] ^ 0x5c;
		}
		memset(ipad + key_len, 0x36, (ISHA_BLOCKLEN -key_len));
		memset(opad + key_len, 0x5C, (ISHA_BLOCKLEN -key_len));
		//ISHAReset(&ctx);
		 ISHAReset(&ipad_ctx);    //Just makes Length as 0 and MD resets
		 ISHAInput(&ipad_ctx, ipad, ISHA_BLOCKLEN);  //Update Length and Changes MBlock in that
		ISHAReset(&opad_ctx);
		ISHAInput(&opad_ctx, opad, ISHA_BLOCKLEN);
  }
  ctx = ipad_ctx;
  ISHAInput(&ctx, msg, msg_len);
  ISHAResult(&ctx, inner_digest);

  ctx = opad_ctx;
  ISHAInput(&ctx, inner_digest, ISHA_DIGESTLEN);
  ISHAResult(&ctx, digest);
}


/*
 * Implements the F function as defined in RFC 8018 section 5.2
 *
 * Parameters:
 *   pass      The password
 *   pass_len  length of pass
 *   salt      The salt
 *   salt_len  length of salt
 *   iter      The iteration count ("c" in RFC 8018)
 *   blkidx    the block index ("i" in RFC 8018)
 *   result    The result, which is ISHA_DIGESTLEN bytes long
 * 
 * Returns:
 *   The result of computing the F function, in result
 */
static void F(const uint8_t *pass, size_t pass_len,
    const uint8_t *salt, size_t salt_len,
    int iter, unsigned int blkidx, uint8_t *result)
{
/*  uint32_t duration_F_end =0;
  uint32_t duration_F =0;
  duration_F = get_timer();	*/									//changes
  uint8_t temp[ISHA_DIGESTLEN];
  uint8_t saltplus[2048];
  size_t i;
  assert(salt_len + 4 <= sizeof(saltplus));

  memcpy(saltplus, salt, salt_len);
  /*for (i=0; i<salt_len; i++)                        //To check why this loop is necessary?
    saltplus[i] = salt[i];							//Runs 9 times as Salt is Buffaloes*/

  // append blkidx in 4 bytes big endian 
  //*(uint32_t*)(saltplus) = __builtin_bswap32(blkidx);
  saltplus[salt_len] = (blkidx & 0xff000000) >> 24 ;
  saltplus[salt_len+1] = (blkidx & 0x00ff0000) >> 16;
  saltplus[salt_len+2] = (blkidx & 0x0000ff00) >> 8;
  saltplus[salt_len+3] = (blkidx & 0x000000ff);

  hmac_isha(pass, pass_len, saltplus, salt_len+4, temp);
  F_called = 1;
  memcpy(result, temp, ISHA_DIGESTLEN);
 /* for (int i=0; i<ISHA_DIGESTLEN; i++)						//Runs 20 times
    result[i] = temp[i];
*/
  for (int j=1; j<iter; j++) {                          	//Will Run 4096 times
    hmac_isha(pass, pass_len, temp, ISHA_DIGESTLEN, temp);
    for (register int i=0; i<ISHA_DIGESTLEN; i++)
      result[i] ^= temp[i];
  }
    //changes
  /*  duration_F_end = get_timer();
    total_F = total_F + (duration_F_end - duration_F);
    count_F++;*/
}

/*
 * See function description in pbkdf2.h
 */
void pbkdf2_hmac_isha(const uint8_t *pass, size_t pass_len,
    const uint8_t *salt, size_t salt_len, int iter, size_t dkLen, uint8_t *DK)
{
  F_called =0;
 /* uint32_t duration_Pb_end =0;
  uint32_t duration_Pb =0;
  duration_Pb = get_timer();*/
  uint8_t accumulator[2560];
  assert(dkLen < sizeof(accumulator));

  int l = dkLen / ISHA_DIGESTLEN + 1;
  for (int i=0; i<l; i++) {
    F(pass, pass_len, salt, salt_len, iter, i+1, accumulator + i*ISHA_DIGESTLEN);
  }
  memcpy(DK, accumulator, dkLen);
  /*for (size_t i=0; i<dkLen; i++) {
    DK[i] = accumulator[i];
  }*/
 /*  duration_Pb_end = get_timer();
   total_Pb += (duration_Pb_end - duration_Pb);
   count_Pb++;*/
}



