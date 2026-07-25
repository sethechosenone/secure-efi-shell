#include "ShellLog.h"
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DevicePathLib.h>
#include <Library/FileHandleLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/SimpleFileSystem.h>

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

VOID LogCmdEvent(CHAR16 *cmd) {
  if (cmd == NULL) return; // guard clause
  STATIC CHAR16 *path = NULL;
  EFI_LOADED_IMAGE_PROTOCOL *loadedImage;
  if (gBS->HandleProtocol(gImageHandle, &gEfiLoadedImageProtocolGuid, (VOID **) &loadedImage) != EFI_SUCCESS) return;
  if (path == NULL) { // this is meaningful due to STATIC
    if ((DevicePathType(loadedImage->FilePath) == MEDIA_DEVICE_PATH) &&
        (DevicePathSubType(loadedImage->FilePath) == MEDIA_FILEPATH_DP)) {
      FILEPATH_DEVICE_PATH *filePath = (FILEPATH_DEVICE_PATH *) loadedImage->FilePath;
      UINTN size = StrSize(filePath->PathName) + sizeof(L"command.log");
      path = AllocateZeroPool(size);
      if (path != NULL) {
        StrCpyS(path, size / sizeof(CHAR16), filePath->PathName);
        PathRemoveLastItem(path);
        StrCatS(path, size / sizeof(CHAR16), L"command.log");
      }
    }
  }
  if (path == NULL) return; // path resolution failed, maybe next time
  EFI_TIME time;
  if (gRT->GetTime(&time, NULL) != EFI_SUCCESS) ZeroMem(&time, sizeof(time));
  UINTN printSize = 23 + StrLen(cmd);
  CHAR8 *line = AllocateZeroPool(printSize);
  if (line == NULL) return;
  AsciiSPrint(line, printSize, "%04d-%02d-%02dT%02d:%02d:%02d %s\r\n", time.Year, time.Month, time.Day, time.Hour, time.Minute, time.Second, cmd);
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fsProtocol;
  EFI_FILE_PROTOCOL *root;
  EFI_FILE_PROTOCOL *file;
  if (gBS->HandleProtocol(loadedImage->DeviceHandle, &gEfiSimpleFileSystemProtocolGuid, (VOID **) &fsProtocol) != EFI_SUCCESS) {
    FreePool(line);
    return;
  }
  if (fsProtocol->OpenVolume(fsProtocol, &root) != EFI_SUCCESS) {
    FreePool(line);
    return;
  }
  if (root->Open(root, &file, path,
      EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
      0) != EFI_SUCCESS) {
    FreePool(line);
    FileHandleClose(root);
    return;
  }
  FileHandleSetPosition(file, 0xFFFFFFFFFFFFFFFF);
  UINTN length = AsciiStrLen(line);
  FileHandleWrite(file, &length, line);
  FileHandleClose(file);
  FileHandleClose(root);
  FreePool(line);
}
