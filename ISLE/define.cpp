#include "define.h"

Isle *g_isle = 0; // A variable of the Isle class.
int g_closed = 0; // Set to 1 when the window is closed.

const char *WINDOW_TITLE = "LEGO®"; // The title of the window.

unsigned char g_mousedown = 0; // 0 if the left mouse button is released, 1 if it is being pressed.
unsigned char g_mousemoved = 0; // 0 if the mouse is not moving, 1 if it is moving.
int g_rmDisabled = 0; // Has to do with g_targetWidth and g_targetHeight. Set to 1 if the check is false.
int _DAT_00410054 = 1;
int g_targetWidth = 640; // The width and height of a 4:3 480p screen?
int g_targetHeight = 480; // isle.cpp checks if these values are the same as something, then lets LEGO1 know the result?
                          // We may be able to uncover this a bit more as we decompile LEGO1.dll as well?
                          // Doesn't seem like it is checking if a certain feature is compatible considering it would have to be a 640x480 monitor exactly to match...
unsigned int g_targetDepth = 16; // Also checked with g_targetWidth and g_targetHeight.
int g_reqEnableRMDevice = 0; // Also has to with g_targetWidth and g_targetHeight. Set to 1 if the check is true.
int g_startupDelay = 200; // How many frames to wait for LEGO1/freeze before doing anything else.
long g_lastFrameTime = 0; // Set to the value of currentTime during the call of the tick function.
