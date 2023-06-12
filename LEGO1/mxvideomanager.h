#ifndef MXVIDEOMANAGER_H
#define MXVIDEOMANAGER_H

class MxVideoManager
{
public:
  __declspec(dllexport) void InvalidateRect(MxRect32 &);
  __declspec(dllexport) virtual long RealizePalette(MxPalette *);
};

#endif // MXVIDEOMANAGER_H
