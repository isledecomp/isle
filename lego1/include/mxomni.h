#ifndef MXOMNI_H
#define MXOMNI_H

class MxOmni
{
public:
  __declspec(dllexport) static void DestroyInstance();
  __declspec(dllexport) static const char * GetCD();
  __declspec(dllexport) static const char * GetHD();
  __declspec(dllexport) static MxOmni * GetInstance();
  __declspec(dllexport) static unsigned char IsSound3D();
  __declspec(dllexport) static void SetCD(const char *s);
  __declspec(dllexport) static void SetHD(const char *s);
  __declspec(dllexport) static void SetSound3D(unsigned char);
};

#endif // MXOMNI_H
