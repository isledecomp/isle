#ifndef REALTIMEVIEW_H
#define REALTIMEVIEW_H

class RealtimeView
{
public:
  __declspec(dllexport) static float GetPartsThreshold();
  __declspec(dllexport) static float GetUserMaxLOD();
  __declspec(dllexport) static void SetPartsThreshold(float);
  static void UpdateMaxLOD();
  __declspec(dllexport) static void SetUserMaxLOD(float);
};

#endif // REALTIMEVIEW_H
