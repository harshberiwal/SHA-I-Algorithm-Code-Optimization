/*
 * isha.c
 *
 * A completely insecure and bad hashing algorithm, based loosely on
 * SHA-1 (which is itself no longer considered a good hashing
 * algorithm)
 *
 * Based on code for sha1 processing from Paul E. Jones, available at
 * https://www.packetizer.com/security/sha1/
 */

#include "isha.h"
#include "ticktime.h"
#include "string.h"

/*uint32_t count_IR =0;
uint32_t total_IR =0;


uint32_t count_I =0;
uint32_t total_I =0;

uint32_t count_IPM =0;
uint32_t total_IPM =0;

uint32_t count_IPMB =0;
uint32_t total_IPMB =0;*/

/*
 * circular shift macro
 */
#define ISHACircularShift(bits,word) \
  ((((word) << (bits)) & 0xFFFFFFFF) | ((word) >> (32-(bits))))


/*  
 * Processes the next 512 bits of the message stored in the MBlock
 * array.
 *
 * Parameters:
 *   ctx         The ISHAContext (in/out)
 */
static void ISHAProcessMessageBlock(ISHAContext *ctx)
{/*
	uint32_t duration_IPMB_end =0;
		uint32_t duration_IPMB =0;
			duration_IPMB = get_timer();*/
  uint32_t temp;
  register int t;
  register uint32_t A;
  uint32_t B, C, D, E;
  A = ctx->MD[0];
  B = ctx->MD[1];
  C = ctx->MD[2];
  D = ctx->MD[3];
  E = ctx->MD[4];

  for(t = 0; t < 16; t++)
  {
    temp = ISHACircularShift(5,A) + ((B & C) | ((~B) & D)) + E +__builtin_bswap32(*((uint32_t*)(ctx->MBlock+(t*4))));
    E = D;
    D = C;
    C = ISHACircularShift(30,B);
    B = A;
    A = temp;
  }

  ctx->MD[0] += A;
  ctx->MD[1] += B;
  ctx->MD[2] += C;
  ctx->MD[3] += D;
  ctx->MD[4] += E;

  ctx->MB_Idx = 0;
/*  duration_IPMB_end = get_timer();
  total_IPMB += (duration_IPMB_end - duration_IPMB);
  count_IPMB++;*/
  return;
}


/*  
 * The message must be padded to an even 512 bits.  The first padding
 * bit must be a '1'.  The last 64 bits represent the length of the
 * original message.  All bits in between should be 0. This function
 * will pad the message according to those rules by filling the MBlock
 * array accordingly. It will also call ISHAProcessMessageBlock()
 * appropriately. When it returns, it can be assumed that the message
 * digest has been computed.
 *
 * Parameters:
 *   ctx         The ISHAContext (in/out)
 */
static void ISHAPadMessage(ISHAContext *ctx)
{
  /*
   *  Check to see if the current message block is too small to hold
   *  the initial padding bits and length.  If so, we will pad the
   *  block, process it, and then continue padding into a second
   *  block.
   */

/*	uint32_t duration_IPM_end =0;
	uint32_t duration_IPM =0;
		duration_IPM = get_timer();*/
  if (ctx->MB_Idx > 55)
  {
    ctx->MBlock[ctx->MB_Idx++] = 0x80;
    memset(ctx->MBlock+ctx->MB_Idx, 0, 64 - (ctx->MB_Idx));

    ISHAProcessMessageBlock(ctx);
    memset(ctx->MBlock+ctx->MB_Idx, 0, 60 - (ctx->MB_Idx));
  }
  else
  {
    ctx->MBlock[ctx->MB_Idx++] = 0x80;
    memset(ctx->MBlock+ctx->MB_Idx, 0, 60 - (ctx->MB_Idx));
  }
  *(uint32_t*)(ctx->MBlock + 60) = __builtin_bswap32(ctx->Length_Low);
  ISHAProcessMessageBlock(ctx);
/*  duration_IPM_end = get_timer();
   total_IPM += (duration_IPM_end - duration_IPM);
   count_IPM++;*/
   return;
}


void ISHAReset(ISHAContext *ctx)
{
  ctx->Length_Low  = 0;
  ctx->MB_Idx      = 0;

  ctx->MD[0]       = 0x67452301;
  ctx->MD[1]       = 0xEFCDAB89;
  ctx->MD[2]       = 0x98BADCFE;
  ctx->MD[3]       = 0x10325476;
  ctx->MD[4]       = 0xC3D2E1F0;

  ctx->Computed    = 0;
}


void ISHAResult(ISHAContext *ctx, uint8_t *digest_out)
{
/*	uint32_t duration_IR_end =0;
	uint32_t duration_IR =0;
  duration_IR = get_timer();*/
/*  if (ctx->Corrupted)
  {
    return;
  }*/

  if (!ctx->Computed)
  {
    ISHAPadMessage(ctx);
    ctx->Computed = 1;
  }
  /*for (int i=0; i<20; i+=4)*/
	*(uint32_t*)(digest_out + 0) = __builtin_bswap32(ctx -> MD[0]);
	*(uint32_t*)(digest_out + 4) = __builtin_bswap32(ctx -> MD[1]);
	*(uint32_t*)(digest_out + 8) = __builtin_bswap32(ctx -> MD[2]);
	*(uint32_t*)(digest_out + 12) = __builtin_bswap32(ctx -> MD[3]);
	*(uint32_t*)(digest_out + 16) = __builtin_bswap32(ctx -> MD[4]);

	 // *(uint32_t*)digest_out[i] = __builtin_bswap32(tx -> MD + (i/4));
 /* for (int i=0; i<20; i+=4) {
    digest_out[i]   = (ctx->MD[i/4] & 0xff000000) >> 24;
    digest_out[i+1] = (ctx->MD[i/4] & 0x00ff0000) >> 16;
    digest_out[i+2] = (ctx->MD[i/4] & 0x0000ff00) >> 8;
    digest_out[i+3] = (ctx->MD[i/4] & 0x000000ff);
  }*/
 /* duration_IR_end = get_timer();
  total_IR += (duration_IR_end - duration_IR);
  count_IR++;*/
  return;
}


void ISHAInput(ISHAContext *ctx, const uint8_t *message_array, size_t length)
{
/*	uint32_t duration_I_end =0;
		uint32_t duration_I =0;
	duration_I = get_timer();*/
  ctx->Length_Low += (8 * length);

  while(length--) {
    ctx->MBlock[ctx->MB_Idx++] = *message_array++;
    if (ctx->MB_Idx == 64) {
      ISHAProcessMessageBlock(ctx);
    }
  }
  /*duration_I_end = get_timer();
  total_I += (duration_I_end - duration_I);
  count_I++;*/
  return;
}


