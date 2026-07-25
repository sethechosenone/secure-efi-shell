#ifndef SHELL_AUTH_H_
#define SHELL_AUTH_H_

#include <Uefi.h>
#include <IndustryStandard/Tpm20.h>
#include <Library/Tpm2CommandLib.h>
#include <Library/Tpm2DeviceLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/BaseCryptLib.h>

#define MAX_PASSWORD_LEN 64
#define MAX_AUTH_ATTEMPTS 3
#define STRETCH_ITERATIONS 1000000
#define TPM_HANDLE 0x01800001

VOID AuthenticateOrReset(VOID);

#endif
