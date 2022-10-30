/*
 * Assembly code for IshaProcessMessageBlock declaration that is called by Isha_result
 * and ISHA_Pad_message
 *
 * Author: Harsh Beriwal
 * IDE Used: MCUXpresso IDE v11.6.0 [Build 8187] [2022-07-13]
 *
 * Github Link: https://github.com/harshberiwal/PES_Assignment_5
 *
 */

#ifndef OPTIMIZE_MESSAGE_BLOCK_H_
#define OPTIMIZE_MESSAGE_BLOCK_H_
#include "isha.h"

/*
 * Processes the next 512 bits of the message stored in the MBlock
 * array.
 *
 * Parameters:
 *   ctx         The ISHAContext (in/out)
 */
void ISHAProcessMessageBlock(ISHAContext *ctx);

#endif /* OPTIMIZE_MESSAGE_BLOCK_H_ */
