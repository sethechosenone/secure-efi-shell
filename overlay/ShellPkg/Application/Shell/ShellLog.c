#include "ShellLog.h"
#include <Library/BaseMemoryLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

#pragma pack(1)

typedef struct {
  EFI_TIME time;
  UINT8 event;
  UINT8 attempt;
} SHELL_AUTH_LOG_ENTRY;

typedef struct {
  UINT32 version;
  UINT32 totalEvents;
  SHELL_AUTH_LOG_ENTRY entries[SHELL_AUTH_LOG_MAX_ENTRIES];
} SHELL_AUTH_LOG;

STATIC GUID shellGuid = {
  0x13dc1cee, 0x81a0, 0x4cf8, { 0x90, 0x2b, 0x28, 0x33, 0xc8, 0xd8, 0x4c, 0x9f }
};

#pragma pack()

VOID LogAuthEvent(SHELL_AUTH_LOG_EVENT event, UINT8 attempt) {
  SHELL_AUTH_LOG authLog;
  UINTN size = sizeof(authLog);
  ZeroMem(&authLog, size);
  authLog.version = SHELL_AUTH_LOG_VERSION;
  EFI_STATUS getVarStatus = gRT->GetVariable(L"ShellAuthLog", &shellGuid, NULL, &size, &authLog);
  if (getVarStatus != EFI_SUCCESS && getVarStatus != EFI_NOT_FOUND) return;
  EFI_TIME time;
  if (gRT->GetTime(&time, NULL) != EFI_SUCCESS) ZeroMem(&time, sizeof(time));
  SHELL_AUTH_LOG_ENTRY newEntry = {
    .time = time,
    .event = (UINT8) event,
    .attempt = attempt
  };
  authLog.entries[authLog.totalEvents % SHELL_AUTH_LOG_MAX_ENTRIES] = newEntry;
  authLog.totalEvents++;
  gRT->SetVariable(L"ShellAuthLog", &shellGuid,
      EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
      sizeof(authLog), &authLog);
}

VOID LogCmdEvent(CHAR8 *cmd) {}
