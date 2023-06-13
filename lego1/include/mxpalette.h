#ifndef MXPALETTE_H
#define MXPALETTE_H

class MxPalette
{
public:
  __declspec(dllexport) unsigned char operator==(MxPalette &);
  __declspec(dllexport) void Detach();
};

#endif // MXPALETTE_H
