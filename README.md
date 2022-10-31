# PES_Assignment_5

 Code Speed Optimization for SHA-I Algorithm Inmplementation 
 
 The code was created by Howdy Pierce but was optimized to be run in 1225 ms without any optimization as opposed to the initial run time of 8744 ms. 

 A completely insecure and bad hashing algorithm, based loosely on
 SHA-1 (which is itself no longer considered a good hashing
 algorithm)

 Based on code for sha1 processing from Paul E. Jones, available at
 https://www.packetizer.com/security/sha1/
 
 Edited By - Harsh Beriwal.
 
 IDE Used: MCUXpresso IDE v11.6.0 [Build 8187] [2022-07-13]
 
 Github Link: https://github.com/harshberiwal/PES_Assignment_5
 
 The porject provided a working implementation of SHA-I algorithm that could encrypt the password using a Hash function leveraging the concept of Salting. 
 The project took like 8744 ms to execute without any optimization with a .text file size of 21056 bytes. 
 
 With the following edits to optimize for speed, I could reach a time of 1225 ms. This also includes a assembly file written for ISHAProcessMessageBlock function. 
 The number of times ISHAReset and ISHAInput, ISHAProcessMessageBLock is called was also reduce because of optimization of loop Invariant code in hmac_isha   function. 
 
** Following Edits were performed in ISHA.c **
 
Edits: 1) The IshaPadMessageBlock was removed and included in assembly as given in optimize_message_block.s.
 2) Used highly optimized library functions like memset, memcpy, bswap to speed up the execution
 3) Used Loop unrolling and removed some checks which reduces the generality of the functions but makes the execution faster as those checks are not needed
 for this application and test cases.
 
 **Following Edits were performed in pbkdf2.c **
 
Edits: 1) The hmac_isha was optimized the most by using a Flag that only get reset after a new key is used (i.e a new test case). This reduces the execution time  by more than 1800 msec.
2) Used highly optimized library functions like memset, memcpy, bswap in hmac_isha and F function to speed up the execution
3) Used Loop unrolling and removed some checks which reduces the generality of the functions but makes the execution faster as those checks are not needed for      this application and test cases.

LIMITATIONS OF THE OPTIMIZATION 

To optimize for the given test cases, there were various unneccesary checks that were removed. Although if the test cases change like change if negative length is passed to ISHAInput for example, we would get wrong result as 2's complement of the length would be used to find the key length and pad the message resulting in wrong answer. Also the corrupted lfag from the ISHAcontext strcuture were removed as it was just getting called more than 49000 times without any use. 

TIME TAKEN BY THE CODE SIZE 

RELEASE MODE : 1225 ms 
DEBUG MODE: 1226 ms 

FINAL .TEXT SIZE 

RELEASE MODE: 19112 bytes 
DEBUG MODE: 20420 bytes   

** Extra Credit**

An assembly program was written for ISHAProcessMessageBlock which reduced the execution time by 483 ms. The O3 optimization code was utilized and updated accordingly to reduce the total execution time and further optimize it. 

THe final execution Time was 1225 ms in the Production code. 





 
 
