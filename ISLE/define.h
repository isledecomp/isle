#ifndef DEFINE_H
#define DEFINE_H

#include <mxtypes.h>
#include <windows.h>

class IsleApp;

extern IsleApp* g_isle;
extern int g_closed;
// STRING: ISLE 0x4101c4
#define WNDCLASS_NAME "Lego Island MainNoM App"
// STRING: ISLE 0x4101dc
#define WINDOW_TITLE "LEGO\xAE"
extern unsigned char g_mousedown;
extern unsigned char g_mousemoved;
extern RECT g_windowRect;
extern int g_rmDisabled;
extern int g_waitingForTargetDepth;
extern int g_targetWidth;
extern int g_targetHeight;
extern int g_targetDepth;
extern int g_reqEnableRMDevice;
extern int g_startupDelay;
extern MxLong g_lastFrameTime;

#endif // DEFINE_H
