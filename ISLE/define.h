#ifndef DEFINE_H
#define DEFINE_H

#include <Windows.h>

class Isle;

extern Isle *g_isle;
extern int g_closed;
#define WNDCLASS_NAME "Lego Island MainNoM App"
#define WINDOW_TITLE "LEGO\xAE"
extern unsigned char g_mousedown;
extern unsigned char g_mousemoved;
extern RECT g_windowRect;
extern int g_rmDisabled;
extern int g_waitingForTargetDepth;
extern int g_targetWidth;
extern int g_targetHeight;
extern unsigned int g_targetDepth;
extern int g_reqEnableRMDevice;
extern int g_startupDelay;
extern long g_lastFrameTime;

#endif // DEFINE_H
