#include "define.h"

// 0x410030
IsleApp *g_isle = 0;

// 0x410034
unsigned char g_mousedown = 0;

// 0x410038
unsigned char g_mousemoved = 0;

// 0x41003c
int g_closed = 0;

// 0x410040
RECT g_windowRect = {0, 0, 640, 480};

// 0x410050
int g_rmDisabled = 0;

// 0x410054
int g_waitingForTargetDepth = 1;

// 0x410058
int g_targetWidth = 640;

// 0x41005c
int g_targetHeight = 480;

// 0x410060
int g_targetDepth = 16;

// 0x410064
int g_reqEnableRMDevice = 0;

// 0x4101bc
int g_startupDelay = 200;

// 0x4101c0
long g_lastFrameTime = 0;
