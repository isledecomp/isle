#ifndef LEGONAVCONTROLLER_H
#define LEGONAVCONTROLLER_H

#include "mxcore.h"
#include "mxbool.h"

class LegoNavController : public MxCore
{
public:
  __declspec(dllexport) static void GetDefaults(int *p_mouseDeadzone, float *p_movementMaxSpeed, float *p_turnMaxSpeed,
                                                float *p_movementMaxAccel, float *p_turnMaxAccel, float *p_movementDecel,
                                                float *p_turnDecel, float *p_movementMinAccel, float *p_turnMinAccel,
                                                float *p_rotationSensitivity, MxBool *p_turnUseVelocity);
  __declspec(dllexport) static void SetDefaults(int p_mouseDeadzone, float p_movementMaxSpeed, float p_turnMaxSpeed,
                                                float p_movementMaxAccel, float p_turnMaxAccel, float p_movementDecel,
                                                float p_turnDecel, float p_movementMinAccel, float p_turnMinAccel,
                                                float p_rotationSensitivity, MxBool p_turnUseVelocity);
  void ResetToDefault();

private:
  int unk_08; // known to be set to window width: 640 (default)
  int unk_0C; // known to be set to window height: 480 (default)
  int m_mouseDeadzone;
  float m_zeroThreshold;
  int unk_18[4];
  float m_movementMaxSpeed;
  float m_turnMaxSpeed;
  int unk_30[2];
  float m_movementMaxAccel;
  float m_turnMaxAccel;
  float m_movementMinAccel;
  float m_turnMinAccel;
  float m_movementDecel;
  float m_turnDecel;
  float m_rotationSensitivity;
  MxBool m_turnUseVelocity;
};

#endif // LEGONAVCONTROLLER_H
