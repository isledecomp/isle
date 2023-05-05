#include "define.h"

Isle *g_isle = 0;
int g_closed = 0;

const char *WNDCLASS_NAME = "Lego Island MainNoM App";
const char *WINDOW_TITLE = "LEGO®";

unsigned char g_mousedown = 0;
unsigned char g_mousemoved = 0;
int _DAT_00410050 = 0;
int _DAT_00410054 = 1;
int g_targetWidth = 640;
int g_targetHeight = 480;
unsigned int g_targetDepth = 16;
int _DAT_00410064 = 0;
int _DAT_004101bc = 200;
long g_lastFrameTime = 0;
