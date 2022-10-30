/*
 * Assembly code for IshaProcessMessageBlock that is called by Isha_result
 * and ISHA_Pad_message
 *
 * Author: Harsh Beriwal
 * IDE Used: MCUXpresso IDE v11.6.0 [Build 8187] [2022-07-13]
 *
 * Github Link: https://github.com/harshberiwal/PES_Assignment_5
 *
 */

.cpu cortex-m0
.syntax unified

.text
.globl ISHAProcessMessageBlock
.type ISHAProcessMessageBlock, %function

@ void ISHAProcessMessageBlock(ISHAContext *ctx)

ISHAProcessMessageBlock:
   push    {r4, r5, r6, r7, lr}				// Pushing all the parameters and Link Register in the SP
   mov     r6, r9
   mov     r5, r8
   mov     lr, r11
   mov     r7, r10
   movs    r3, r0							// A = ctx->MD[0];
   mov     r11, r0
   push    {r5, r6, r7, lr}
   ldr     r2, [r3, #12]					// D = ctx->MD[3];
   ldr     r3, [r3, #16]					// E = ctx->MD[4];
   sub     sp, #36
   mov     r12, r3							// E = ctx->MD[4];
   movs    r1, #88
   str     r3, [sp, #28]
   movs    r3, #27							// Doing IshaCircular Shift for new A
   //temp = ISHACircularShift(5,A) + ((B & C) | ((~B) & D)) + E +__builtin_bswap32(*((uint32_t*)(ctx->MBlock+(t*4))));
   mov     r6, r11
   ldr     r7, [r0, #0]						//A = ctx->MD[0];
   ldr     r5, [r0, #4]						//B = ctx->MD[1];
   ldr     r0, [r0, #8]						//C = ctx->MD[2];
   mov     r9, r3
   add     r1, r11
   subs    r3, #25
   mov     r8, r3
   mov     r4, r12
   str     r7, [sp, #12]
   str     r5, [sp, #16]
   str     r0, [sp, #20]					//D = ctx->MD[3];
   str     r2, [sp, #24]
   adds    r6, #24
   str     r1, [sp, #8]
   b.n     JUMP1
JUMP2: movs    r2, r0
   movs    r7, r3							// C = ISHACircularShift(30,B);
   mov     r0, r12
JUMP1: ldmia   r6!, {r3}
   movs    r1, r7
   rev     r3, r3
   mov     r10, r3
   movs    r3, r0
   eors    r3, r2
   ands    r3, r5
   //temp = ISHACircularShift(5,A) + ((B & C) | ((~B) & D)) + E +__builtin_bswap32(*((uint32_t*)(ctx->MBlock+(t*4)))
   eors    r3, r2
   str     r3, [sp, #4]
   mov     r3, r9
   rors    r1, r3
   mov     r12, r1
   mov     r1, r8
   rors    r5, r1
   ldr     r3, [sp, #4]
   add     r12, r10
   ldr     r1, [sp, #8]
   add     r3, r12
   adds    r3, r3, r4
   mov     r12, r5
   movs    r4, r2					// for(t = 0; t < 16; t++)
   movs    r5, r7
   cmp     r1, r6
   bne.n   JUMP2
   ldr     r4, [sp, #12]			//ctx->MD[0] += A;
   mov     r1, r12
   mov     r12, r4
   mov     r4, r11
   add     r3, r12
   str     r3, [r4, #0]				//ctx->MD[1] += B;
   ldr     r3, [sp, #16]
   mov     r12, r3
   ldr     r3, [sp, #20]			//ctx->MD[2] += C;
   add     r7, r12
   mov     r12, r3
   ldr     r3, [sp, #24]			//ctx->MD[3] += D;
   add     r1, r12
   mov     r12, r3
   ldr     r3, [sp, #28]			//ctx->MD[4] += E;
   add     r0, r12
   mov     r12, r3
   movs    r3, #0					//ctx->MB_Idx = 0;
   add     r2, r12
   str     r7, [r4, #4]				//ctx->MD[1] += B;
   str     r1, [r4, #8]
   str     r0, [r4, #12]			//ctx->MD[3] += D;
   str     r2, [r4, #16]
   str     r3, [r4, #88]			// ctx->MB_Idx = 0;
   add     sp, #36
   pop     {r4, r5, r6, r7}
   mov     r11, r7
   mov     r10, r6
   mov     r9, r5
   mov     r8, r4					//ctx->Length_Low  = 0;
   pop     {r4, r5, r6, r7, pc}
   nop

