#include "legonavcontroller.h"

int g_mouseDeadzone = 40;
float g_zeroThreshold = 0.001f;
float g_movementMaxSpeed = 40.0f;
float g_turnMaxSpeed = 20.0f;
float g_movementMaxAccel = 15.0f;
float g_turnMaxAccel = 30.0f;
float g_movementMinAccel = 4.0f;
float g_turnMinAccel = 15.0f;
float g_movementDecel = 50.0f;
float g_turnDecel = 50.0f;
float g_rotationSensitivity = 0.4f;
MxBool g_turnUseVelocity = 0;

void LegoNavController::GetDefaults(int *p_mouseDeadzone, float *p_movementMaxSpeed, float *p_turnMaxSpeed,
                                    float *p_movementMaxAccel, float *p_turnMaxAccel, float *p_movementDecel,
                                    float *p_turnDecel, float *p_movementMinAccel, float *p_turnMinAccel,
                                    float *p_rotationSensitivity, MxBool *p_turnUseVelocity)
{
  *p_mouseDeadzone = g_mouseDeadzone;
  *p_movementMaxSpeed = g_movementMaxSpeed;
  *p_turnMaxSpeed = g_turnMaxSpeed;
  *p_movementMaxAccel = g_movementMaxAccel;
  *p_turnMaxAccel = g_turnMaxAccel;
  *p_movementDecel = g_movementDecel;
  *p_turnDecel = g_turnDecel;
  *p_movementMinAccel = g_movementMinAccel;
  *p_turnMinAccel = g_turnMinAccel;
  *p_rotationSensitivity = g_rotationSensitivity;
  *p_turnUseVelocity = g_turnUseVelocity;
}

void LegoNavController::SetDefaults(int p_mouseDeadzone, float p_movementMaxSpeed, float p_turnMaxSpeed,
                                    float p_movementMaxAccel, float p_turnMaxAccel, float p_movementDecel,
                                    float p_turnDecel, float p_movementMinAccel, float p_turnMinAccel,
                                    float p_rotationSensitivity, MxBool p_turnUseVelocity)
{
  g_mouseDeadzone = p_mouseDeadzone;
  g_movementMaxSpeed = p_movementMaxSpeed;
  g_turnMaxSpeed = p_turnMaxSpeed;
  g_movementMaxAccel = p_movementMaxAccel;
  g_turnMaxAccel = p_turnMaxAccel;
  g_movementDecel = p_movementDecel;
  g_turnDecel = p_turnDecel;
  g_movementMinAccel = p_movementMinAccel;
  g_turnMinAccel = p_turnMinAccel;
  g_rotationSensitivity = p_rotationSensitivity;
  g_turnUseVelocity = p_turnUseVelocity;
}

void LegoNavController::ResetToDefault()
{
  this->m_mouseDeadzone = g_mouseDeadzone;
  this->m_zeroThreshold = g_zeroThreshold;
  this->m_turnMaxAccel = g_turnMaxAccel;
  this->m_movementMaxAccel = g_movementMaxAccel;
  this->m_turnMinAccel = g_turnMinAccel;
  this->m_movementMinAccel = g_movementMinAccel;
  this->m_turnDecel = g_turnDecel;
  this->m_movementDecel = g_movementDecel;
  this->m_turnMaxSpeed = g_turnMaxSpeed;
  this->m_movementMaxSpeed = g_movementMaxSpeed;
  this->m_turnUseVelocity = g_turnUseVelocity;
  this->m_rotationSensitivity = g_rotationSensitivity;
}