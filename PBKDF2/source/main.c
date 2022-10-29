/*
 * PBKDF2_Optimization.c
 *
 * Application entry point, and test timing
 * 
 * Author: Howdy Pierce, howdy.pierce@colorado.edu
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "board.h"
#include "peripherals.h"
#include "pin_mux.h"
#include "clock_config.h"
#include "MKL25Z4.h"
#include "fsl_debug_console.h"

#include "pbkdf2.h"
#include "pbkdf2_test.h"
#include "ticktime.h"

/*extern uint32_t count_F;
extern uint32_t total_F;


extern uint32_t count_Pb;
extern uint32_t total_Pb;

extern uint32_t count_H;
extern uint32_t total_H;

extern uint32_t count_IR;
extern uint32_t total_IR;

extern uint32_t count_I;
extern uint32_t total_I;

extern uint32_t count_IPM;
extern uint32_t total_IPM;

extern uint32_t count_IPMB;
extern uint32_t total_IPMB;*/

/*
 * Times a single call to the pbkdf2_hmac_isha function, and prints
 * the resulting duration
 */
static void time_pbkdf2_hmac_isha()
{
  const char *pass = "Boulder";
  const char *salt = "Buffaloes";
  int iterations = 4096;
  size_t dk_len = 48;
  int passlen, saltlen;
  uint8_t act_result[512];
  uint8_t exp_result[512];
  const char *exp_result_hex = "7577B5FFB058195DE3978773B472E92D0216873EE1A2"\
    "170157C2054EDC41E58D7F949050253F8CE1D55E6B86E62AED3F";
    
  ticktime_t duration = 0;

  assert(dk_len <= sizeof(act_result));

  hexstr_to_bytes(exp_result, exp_result_hex, dk_len);passlen = strlen(pass);
  saltlen = strlen(salt);
/*  total_F = 0;
  count_F = 0;
  total_Pb = 0;
  count_Pb = 0;
  count_H = 0;
  total_H = 0;
  count_IR =0;
  total_IR =0;
  count_I =0;
  total_I =0;
  count_IPM =0;
  total_IPM =0;
  count_IPMB =0;
  total_IPMB =0;*/
  reset_timer();
  pbkdf2_hmac_isha((const uint8_t *)pass, passlen, (const uint8_t *)salt, saltlen,
      iterations, dk_len, act_result);
  duration = get_timer();

  if (cmp_bin(act_result, exp_result, dk_len)) {
    printf("%s: %u iterations took %u msec\r\n", __FUNCTION__,
        iterations, duration/10);
  } else {
    printf("FAILURE on timed test\r\n");
  }
/*  printf("Number of Times Function F is called is %d\n\r", count_F);
  printf("Total time taken by Function F is %d msec\n\r", total_F/10);
  printf("Number of Times Function pbkdf2_hmac_isha is called is %d\n\r", count_Pb);
  printf("Total time taken by Function pbkdf2_hmac_isha is %d msec\n\r", total_Pb/10);
  printf("Number of Times Function hmac_isha is called is %d\n\r", count_H);
  printf("Total time taken by Function hmac_isha is %d msec\n\r", total_H/10);
  printf("Number of Times Function isha_result is called is %d\n\r", count_IR);
   printf("Total time taken by Function isha_result is %d msec\n\r", total_IR/10);
   printf("Number of Times Function isha_input is called is %d\n\r", count_I);
      printf("Total time taken by Function isha_input is %d msec\n\r", total_I/10);
      printf("Number of Times Function ishaPadmessage is called is %d\n\r", count_IPM);
      printf("Total time taken by Function ishaPadmessage is %d msec\n\r", total_IPM/10);
      printf("Number of Times Function ishaProcessMessageBlock is called is %d\n\r", count_IPMB);
  printf("Total time taken by Function ishaProcessMessageBlock is %d msec\n\r", total_IPMB/10);*/
/*  printf("Number of Times Function isha_reset is called is %d\n\r", count_R);
  printf("Number of Times Function isha_input is called is %d\n\r", count_I);
  printf("Number of Times Function isha_result is called is %d\n\r", count_IR);
  printf("Number of Times Function ishaPadmessage is called is %d\n\r", count_IPM);
  printf("Number of Times Function ishaProcessMessageBlock is called is %d\n\r", count_IPMB);*/
}


/*
 * Run all the validity checks; exit on failure
 */
static void run_tests()
{
  bool success = true;

  success &= test_isha();
  success &= test_hmac_isha();
  success &= test_pbkdf2_hmac_isha();

  if (success)
    return;

  printf("TEST FAILURES EXIST ... exiting\r\n");

  exit(-1);
}


/*
 * Application entry point.
 */
int main(void) {

  /* Init board hardware. */
	BOARD_InitBootPins();
  BOARD_InitBootClocks();
  BOARD_InitBootPeripherals();
#ifndef BOARD_INIT_DEBUG_CONSOLE_PERIPHERAL
  /* Init FSL debug console. */
  BOARD_InitDebugConsole();
#endif

  init_ticktime();

  printf("Running validity tests...\r\n");
  run_tests();
  printf("All tests passed!\r\n");

  printf("Running timing test...\r\n");
  time_pbkdf2_hmac_isha();

  return 0 ;
}
