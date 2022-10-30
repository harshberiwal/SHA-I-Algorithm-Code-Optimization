/*
 * isha.c
 *
 * A completely insecure and bad hashing algorithm, based loosely on
 * SHA-1 (which is itself no longer considered a good hashing
 * algorithm)
 *
 * Based on code for sha1 processing from Paul E. Jones, available at
 * https://www.packetizer.com/security/sha1/
 *
 * Edited By - Harsh Beriwal.
 *
 * Edits: The IshaPadMessageBlock was removed and
 * included in assembly as given in optimize_message_block.s.
 * 2) Used highly optimized library functions like memset, memcpy, bswap to
 * speed up the execution
 * 3) Used Loop unrolling and removed some checks which reduces the generality
 * of the functions but makes the execution faster as those checks are not needed
 * for this application and test cases.
 *
 * IDE Used: MCUXpresso IDE v11.6.0 [Build 8187] [2022-07-13]
 *
 * Github Link: https://github.com/harshberiwal/PES_Assignment_5
 *
 */

#include "isha.h"
#include "string.h"
#include "optimize_message_block.h"

#define ISHACircularShift(bits,word) \
  ((((word) << (bits)) & 0xFFFFFFFF) | ((word) >> (32-(bits))))


// HB - Removed IshaProcessMessageBlock and included that in asm in
// optimize_message_block.s file.

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
  if (ctx->MB_Idx > 55)
  {
    ctx->MBlock[ctx->MB_Idx++] = 0x80;
    //******************Setting all Values in Message Block to 0******************
    memset(ctx->MBlock+ctx->MB_Idx, 0, 64 - (ctx->MB_Idx));

    ISHAProcessMessageBlock(ctx);
    //****************Padding 0 for everything after Block process****************
    memset(ctx->MBlock+ctx->MB_Idx, 0, 60 - (ctx->MB_Idx));
  }
  else
  {
    ctx->MBlock[ctx->MB_Idx++] = 0x80;
    //****************Padding 0 for everything after Block process****************
    memset(ctx->MBlock+ctx->MB_Idx, 0, 60 - (ctx->MB_Idx));
  }
  //*****************Calculating from index 60 to 63 using Length*****************
  *(uint32_t*)(ctx->MBlock + 60) = __builtin_bswap32(ctx->Length_Low);
  ISHAProcessMessageBlock(ctx);
   return;
}


void ISHAReset(ISHAContext *ctx)
{
  //**************Removed Corrupted and Length High as we don't need it***********
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
//HB - Limitation - Check to see if the message is Corrupted removed
  if (!ctx->Computed)
  {
    ISHAPadMessage(ctx);
    ctx->Computed = 1;
  }
  //*************LOOP UNROLLING AND USING BUILTIN BSWAP FOR SPEED*****************
	*(uint32_t*)(digest_out + 0) = __builtin_bswap32(ctx -> MD[0]);
	*(uint32_t*)(digest_out + 4) = __builtin_bswap32(ctx -> MD[1]);
	*(uint32_t*)(digest_out + 8) = __builtin_bswap32(ctx -> MD[2]);
	*(uint32_t*)(digest_out + 12) = __builtin_bswap32(ctx -> MD[3]);
	*(uint32_t*)(digest_out + 16) = __builtin_bswap32(ctx -> MD[4]);
  return;
}


void ISHAInput(ISHAContext *ctx, const uint8_t *message_array, size_t length)
{
//HB - Limitation - Check to see if the message length is zero or Corrupted removed
//*****************CALCULATING LENGTH DIRECTLY WITHOUT LOOP************************
  ctx->Length_Low += (8 * length);
  while(length--)
  {
	//**************REMOVED ANYTHING RELATED TO LEGNTH HIGH************************
    ctx->MBlock[ctx->MB_Idx++] = *message_array++;
    if (ctx->MB_Idx == 64)
    {
      ISHAProcessMessageBlock(ctx);
    }
  }
  return;
}


