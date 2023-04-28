#ifndef MXOMNI_H
#define MXOMNI_H

class MxOmni
{
public:
  __declspec(dllexport) static const char *GetHD();
  __declspec(dllexport) static const char *GetCD();
  __declspec(dllexport) static void SetHD(const char *s);
  __declspec(dllexport) static void SetCD(const char *s);
  __declspec(dllexport) static void SetSound3D(unsigned char param_1);
  __declspec(dllexport) static void DestroyInstance();
};

#endif // MXOMNI_H
