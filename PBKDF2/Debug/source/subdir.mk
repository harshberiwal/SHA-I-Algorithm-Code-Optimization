################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../source/isha.c \
../source/main.c \
../source/mtb.c \
../source/pbkdf2.c \
../source/pbkdf2_test.c \
../source/semihost_hardfault.c \
../source/ticktime.c 

S_SRCS += \
../source/optimize_message_block.s 

C_DEPS += \
./source/isha.d \
./source/main.d \
./source/mtb.d \
./source/pbkdf2.d \
./source/pbkdf2_test.d \
./source/semihost_hardfault.d \
./source/ticktime.d 

OBJS += \
./source/isha.o \
./source/main.o \
./source/mtb.o \
./source/optimize_message_block.o \
./source/pbkdf2.o \
./source/pbkdf2_test.o \
./source/semihost_hardfault.o \
./source/ticktime.o 


# Each subdirectory must supply rules for building sources it contributes
source/%.o: ../source/%.c source/subdir.mk
	@echo 'Building file: $<'
	@echo 'Invoking: MCU C Compiler'
	arm-none-eabi-gcc -D__REDLIB__ -DCPU_MKL25Z128VLK4 -DCPU_MKL25Z128VLK4_cm0plus -DFSL_RTOS_BM -DSDK_OS_BAREMETAL -DCR_INTEGER_PRINTF -DPRINTF_FLOAT_ENABLE=0 -DSDK_DEBUGCONSOLE_UART -D__MCUXPRESSO -D__USE_CMSIS -DDEBUG -DSDK_DEBUGCONSOLE=0 -I"D:\CU BOULDER\Coursework\Sem 1 - PES\Assignments\Assignment -5\PBKDF2\board" -I"D:\CU BOULDER\Coursework\Sem 1 - PES\Assignments\Assignment -5\PBKDF2\source" -I"D:\CU BOULDER\Coursework\Sem 1 - PES\Assignments\Assignment -5\PBKDF2" -I"D:\CU BOULDER\Coursework\Sem 1 - PES\Assignments\Assignment -5\PBKDF2\drivers" -I"D:\CU BOULDER\Coursework\Sem 1 - PES\Assignments\Assignment -5\PBKDF2\CMSIS" -I"D:\CU BOULDER\Coursework\Sem 1 - PES\Assignments\Assignment -5\PBKDF2\utilities" -I"D:\CU BOULDER\Coursework\Sem 1 - PES\Assignments\Assignment -5\PBKDF2\startup" -O0 -fno-common -g3 -Wall -c -fmessage-length=0 -fno-builtin -ffunction-sections -fdata-sections -fmerge-constants -fmacro-prefix-map="$(<D)/"= -mcpu=cortex-m0plus -mthumb -D__REDLIB__ -fstack-usage -specs=redlib.specs -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.o)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

source/%.o: ../source/%.s source/subdir.mk
	@echo 'Building file: $<'
	@echo 'Invoking: MCU Assembler'
	arm-none-eabi-gcc -c -x assembler-with-cpp -D__REDLIB__ -I"D:\CU BOULDER\Coursework\Sem 1 - PES\Assignments\Assignment -5\PBKDF2\board" -I"D:\CU BOULDER\Coursework\Sem 1 - PES\Assignments\Assignment -5\PBKDF2\source" -I"D:\CU BOULDER\Coursework\Sem 1 - PES\Assignments\Assignment -5\PBKDF2" -I"D:\CU BOULDER\Coursework\Sem 1 - PES\Assignments\Assignment -5\PBKDF2\drivers" -I"D:\CU BOULDER\Coursework\Sem 1 - PES\Assignments\Assignment -5\PBKDF2\CMSIS" -I"D:\CU BOULDER\Coursework\Sem 1 - PES\Assignments\Assignment -5\PBKDF2\utilities" -I"D:\CU BOULDER\Coursework\Sem 1 - PES\Assignments\Assignment -5\PBKDF2\startup" -g3 -mcpu=cortex-m0plus -mthumb -D__REDLIB__ -specs=redlib.specs -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


clean: clean-source

clean-source:
	-$(RM) ./source/isha.d ./source/isha.o ./source/main.d ./source/main.o ./source/mtb.d ./source/mtb.o ./source/optimize_message_block.o ./source/pbkdf2.d ./source/pbkdf2.o ./source/pbkdf2_test.d ./source/pbkdf2_test.o ./source/semihost_hardfault.d ./source/semihost_hardfault.o ./source/ticktime.d ./source/ticktime.o

.PHONY: clean-source

