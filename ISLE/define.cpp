#include "define.h"

Isle *g_isle = 0;
int g_closed = 0; // Set to 1 when the window is closed.

const char *WINDOW_TITLE = "LEGO®";

unsigned char g_mousedown = 0; // 0 if the left mouse button is released, 1 if it is being pressed.
unsigned char g_mousemoved = 0; // 0 if the mouse is not moving, 1 if it is moving.
int g_rmDisabled = 0; // Set to 1 if "RM" is disabled.
int g_targetDepthSet = 1; // Changed to 0 after targetDepth is set for the first time.
int g_targetWidth = 640; // The width and height of a 4:3 480p screen
int g_targetHeight = 480; // isle.cpp checks if the screen resolution is 640x480 then lets LEGO1 know the result to enable "RM" if it is.
unsigned int g_targetDepth = 16; // Also checked along with g_targetWidth and g_targetHeight to check if it is correct.
int g_reqEnableRMDevice = 0; // Set to 1 if "RM" is enabled.
int g_startupDelay = 200; // How many frames to wait for LEGO1 to initialize/freeze before doing anything else on startup.
long g_lastFrameTime = 0; // Set to the value of currentTime during the call of the tick function of isle.cpp
