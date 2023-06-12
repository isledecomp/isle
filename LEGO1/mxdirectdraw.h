#ifndef MXDIRECTDRAW_H
#define MXDIRECTDRAW_H

class MxDirectDraw
{
public:
  __declspec(dllexport) int FlipToGDISurface();
  __declspec(dllexport) static int GetPrimaryBitDepth();
  __declspec(dllexport) int Pause(int);
};

#endif // MXDIRECTDRAW_H
