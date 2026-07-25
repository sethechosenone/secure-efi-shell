#ifndef SHELL_LOG_H_
#define SHELL_LOG_H_

#include <Uefi.h>

#define SHELL_AUTH_LOG_MAX_ENTRIES 32
#define SHELL_AUTH_LOG_VERSION 1

typedef enum {
  ShellAuthLogTPMPolicyFailure,
  ShellAuthLogAuthSuccess,
  ShellAuthLogAuthFailure,
  ShellAuthLogAuthLockout
} SHELL_AUTH_LOG_EVENT;

VOID LogAuthEvent(SHELL_AUTH_LOG_EVENT event, UINT8 attempt);

#endif
