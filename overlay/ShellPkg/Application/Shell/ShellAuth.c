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
#include "ShellAuth.h"
#define MAX_PASSWORD_LEN 64
#define MAX_AUTH_ATTEMPTS 3
#define STRETCH_ITERATIONS 100000
#define TPM_HANDLE 0x01800001

/*
 * The following function is AI-generated, but it's basically a re-implementation
 * of an already existing EDK function
 */

// TPM2_CC_PolicyPCR is absent from this EDK2 checkout's Tpm2CommandLib.
// Built as a raw byte buffer to avoid struct-layout issues with variable-length
// TPML_PCR_SELECTION (in-memory size != wire size when count < HASH_COUNT).
// Wire order per spec: header ¿ policySession ¿ pcrDigest ¿ pcrs.
STATIC EFI_STATUS PolicyPcr7 (TPMI_SH_POLICY Session) {
  UINT8  Cmd[32] = {0};
  UINT8  Rsp[sizeof(TPM2_RESPONSE_HEADER)] = {0};
  UINT8 *p = Cmd;
  UINT32 RspSize;

  // Header: tag, paramSize (filled after), commandCode
  WriteUnaligned16((UINT16*)p, SwapBytes16(TPM_ST_NO_SESSIONS)); p += 2;
  p += 4;  // paramSize placeholder ¿ filled after size is known
  WriteUnaligned32((UINT32*)p, SwapBytes32(TPM_CC_PolicyPCR));   p += 4;
  // policySession handle
  WriteUnaligned32((UINT32*)p, SwapBytes32(Session));             p += 4;
  // pcrDigest: empty TPM2B (size = 0); TPM computes digest from current PCRs
  WriteUnaligned16((UINT16*)p, 0);                                p += 2;
  // pcrs: TPML_PCR_SELECTION with count=1, sha256 bank, PCR 7 selected
  WriteUnaligned32((UINT32*)p, SwapBytes32(1));                   p += 4;  // count
  WriteUnaligned16((UINT16*)p, SwapBytes16(TPM_ALG_SHA256));      p += 2;  // hash
  *p++ = 3;     // sizeofSelect = 3
  *p++ = 0x80;  // pcrSelect[0]: bit 7 = PCR 7
  *p++ = 0x00;
  *p++ = 0x00;

  UINT32 CmdSize = (UINT32)(p - Cmd);
  WriteUnaligned32((UINT32*)(Cmd + 2), SwapBytes32(CmdSize));  // fill paramSize

  RspSize = sizeof(Rsp);
  EFI_STATUS Status = Tpm2SubmitCommand(CmdSize, Cmd, &RspSize, Rsp);
  ZeroMem(Cmd, sizeof(Cmd));
  if (EFI_ERROR(Status)) return Status;
  if (SwapBytes32(((TPM2_RESPONSE_HEADER*)Rsp)->responseCode) != TPM_RC_SUCCESS)
    return EFI_DEVICE_ERROR;
  return EFI_SUCCESS;
}

/*
 * End AI-generated code
 */

STATIC BOOLEAN ReadExpected(UINT8 *expected) {
  TPMI_SH_AUTH_SESSION session;
  TPM2B_NONCE nonceTPM;
  TPM2B_NONCE nonceCaller = { .size = 20 };
  TPM2B_ENCRYPTED_SECRET salt = { .size = 0 };
  TPMT_SYM_DEF symmetric = { .algorithm = TPM_ALG_NULL };
  Tpm2StartAuthSession(TPM_RH_NULL, TPM_RH_NULL, &nonceCaller, &salt, TPM_SE_POLICY, &symmetric, TPM_ALG_SHA256, &session, &nonceTPM);
  PolicyPcr7(session);
  TPMS_AUTH_COMMAND authCMD = {
    .sessionHandle = session,
    .nonce = { .size = 0 },
    .sessionAttributes = (TPMA_SESSION) { .continueSession = 1 },
    .hmac = { .size = 0 },
  };
  TPM2B_MAX_BUFFER tpmBuf;
  ZeroMem(&tpmBuf, sizeof(tpmBuf));
  if (
    !EFI_ERROR(Tpm2NvRead(TPM_HANDLE, TPM_HANDLE, &authCMD, SHA256_DIGEST_SIZE, 0, &tpmBuf)) &&
    tpmBuf.size == SHA256_DIGEST_SIZE
  ) {
    CopyMem(expected, tpmBuf.buffer, SHA256_DIGEST_SIZE);
    ZeroMem(&tpmBuf, sizeof(tpmBuf));
    Tpm2FlushContext(session);
    return TRUE;
  }
  ZeroMem(&tpmBuf, sizeof(tpmBuf));
  Tpm2FlushContext(session);
  return FALSE;
}


VOID ShutoffOnFailure(CHAR16* reason, EFI_STATUS resetReason) {
  Print(L"[auth] critical error -- %s\n", reason);
  Print(L"[auth] the system is going down NOW!\n");
  gRT->ResetSystem(EfiResetCold, resetReason, 0, NULL);
  CpuDeadLoop();
}

BOOLEAN ComputeHash(VOID *hashContext, CONST UINT8 salt[16], CONST VOID *input, UINTN inputSize, UINT8 *result) {
  return (
    Sha256Init(hashContext) &&
    Sha256Update(hashContext, salt, 16) &&
    Sha256Update(hashContext, input, inputSize) &&
    Sha256Final(hashContext, result)
  );
}

BOOLEAN Authenticate(VOID) {
  const UINT8 salt[16] = { 0xF7, 0x52, 0xD1, 0x4D, 0x1A, 0x0C, 0x1E, 0xC1, 0xF0, 0x73, 0x47, 0x42, 0x96, 0xB7, 0x73, 0xA3 };
  UINT8 expected[32];
  ZeroMem(expected, sizeof(expected));
  CHAR16 buf[MAX_PASSWORD_LEN];
  ZeroMem(buf, sizeof(buf));
  Print(L"[auth] enter password: ");
  UINTN idx = 0;
  for (;;) {
    EFI_INPUT_KEY key;
    UINTN EventIndex;
    gBS->WaitForEvent(1, &gST->ConIn->WaitForKey, &EventIndex);
    EFI_STATUS status = gST->ConIn->ReadKeyStroke(gST->ConIn, &key);
    if (EFI_ERROR(status)) continue;
    if (key.UnicodeChar == CHAR_CARRIAGE_RETURN) {
      Print(L"\n");
      break;
    }
    if (key.UnicodeChar == CHAR_BACKSPACE) {
      if (idx > 0) {
        idx--;
        buf[idx] = 0;
        Print(L"\b \b");
      }
      continue;
    }
    if (idx < MAX_PASSWORD_LEN) {
      buf[idx] = key.UnicodeChar;
      Print(L"*");
      idx++;
    }
    key.UnicodeChar = '\0';
  }
  UINT8 userHash[SHA256_DIGEST_SIZE];
  if (!ReadExpected(expected)) {
    ZeroMem(buf, sizeof(buf));
    ShutoffOnFailure(L"TPM read failure! (is secure boot enabled?)", EFI_SECURITY_VIOLATION);
  }
  VOID *hashContext = AllocatePool(Sha256GetContextSize());
  if (hashContext == NULL) {
    ZeroMem(buf, sizeof(buf));
    ZeroMem(expected, sizeof(expected));
    ShutoffOnFailure(L"cannot allocate memory!", EFI_OUT_OF_RESOURCES);
  }
  if (!ComputeHash(hashContext, salt, buf, sizeof(buf), userHash)) {
    ZeroMem(buf, sizeof(buf));
    ZeroMem(expected, sizeof(expected));
    ZeroMem(hashContext, Sha256GetContextSize());
    ShutoffOnFailure(L"crypto operation failed!", EFI_DEVICE_ERROR);
  }
  ZeroMem(buf, sizeof(buf));
  for (int i = 0; i < STRETCH_ITERATIONS; i++)
    if (!ComputeHash(hashContext, salt, userHash, SHA256_DIGEST_SIZE, userHash)) {
      ZeroMem(expected, sizeof(expected));
      ZeroMem(userHash, SHA256_DIGEST_SIZE);
      ZeroMem(hashContext, Sha256GetContextSize());
      ShutoffOnFailure(L"crypto operation failed!", EFI_DEVICE_ERROR);
    }
  ZeroMem(hashContext, Sha256GetContextSize());
  FreePool(hashContext);
  UINT8 diff = 0;
  for (int i = 0; i < SHA256_DIGEST_SIZE; i++) diff |= userHash[i] ^ expected[i];
  ZeroMem(expected, sizeof(expected));
  ZeroMem(userHash, sizeof(userHash));
  if (!diff) {
    Print(L"access granted!\n");
    return TRUE;
  }
  Print(L"access denied, try again!\n");
  return FALSE;
}

VOID AuthenticateOrReset(VOID) {
  BOOLEAN success = FALSE;
  for (int i = 0; i < MAX_AUTH_ATTEMPTS; i++)
    if (Authenticate()) {
      success = TRUE;
      break;
    }
  if (!success) {
    Print(L"[auth] fuck off\n");
    gRT->ResetSystem(EfiResetCold, EFI_SECURITY_VIOLATION, 0, NULL);
    CpuDeadLoop();
  }
}
