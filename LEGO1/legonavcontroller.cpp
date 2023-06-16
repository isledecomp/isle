#include "legonavcontroller.h"

#include "legoomni.h"
#include "legoutil.h"

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
float g_turnSensitivity = 0.4f;
MxBool g_turnUseVelocity = MX_FALSE;

void LegoNavController::GetDefaults(int *p_mouseDeadzone, float *p_movementMaxSpeed, float *p_turnMaxSpeed,
                                    float *p_movementMaxAccel, float *p_turnMaxAccel, float *p_movementDecel,
                                    float *p_turnDecel, float *p_movementMinAccel, float *p_turnMinAccel,
                                    float *p_turnSensitivity, MxBool *p_turnUseVelocity)
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
  *p_turnSensitivity = g_turnSensitivity;
  *p_turnUseVelocity = g_turnUseVelocity;
}

void LegoNavController::SetDefaults(int p_mouseDeadzone, float p_movementMaxSpeed, float p_turnMaxSpeed,
                                    float p_movementMaxAccel, float p_turnMaxAccel, float p_movementDecel,
                                    float p_turnDecel, float p_movementMinAccel, float p_turnMinAccel,
                                    float p_turnSensitivity, MxBool p_turnUseVelocity)
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
  g_turnSensitivity = p_turnSensitivity;
  g_turnUseVelocity = p_turnUseVelocity;
}

LegoNavController::LegoNavController()
{
  ResetToDefault();

  this->unk_18 = 0.0f;
  this->unk_1C = 0.0f;
  this->m_targetMovementSpeed = 0.0f;
  this->m_targetTurnSpeed = 0.0f;
  this->m_movementAccel = 0.0f;
  this->m_turnAccel = 0.0f;
  this->m_trackDefault = MX_FALSE;
  this->m_unk5D = MX_FALSE;
  this->m_unk6C = MX_FALSE;
  this->m_unk64 = 0;
  this->m_unk68 = 0;
  this->m_unk60 = 0;

  MxTimer *timer = Timer();
  this->m_time = timer->GetTime();

  // LegoInputManager* inputManager = InputManager();
  // inputManager->Register(this);
}

// TODO: VideoManager()
// void LegoNavController::SetControlMax(int p_hMax, int p_vMax)
// {
//   LegoVideoManager* videoManager = VideoManager();

//   this->m_hMax = p_hMax;
//   this->m_vMax = p_vMax;

//   if ((videoManager->m_unk44 & 0x01) != 0)
//   {
//     this->m_hMax = 640;
//     this->m_vMax = 480;
//   }
// }

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
  this->m_turnSensitivity = g_turnSensitivity;
}

void LegoNavController::SetTargets(int p_hPos, int p_vPos, MxBool p_accel)
{
  if (this->m_trackDefault != MX_FALSE)
  {
    ResetToDefault();
  }

  if (p_accel != MX_FALSE)
  {
    this->m_targetTurnSpeed = CalculateNewTargetSpeed(p_hPos, this->m_hMax / 2, this->m_turnMaxSpeed);
    this->m_targetMovementSpeed = CalculateNewTargetSpeed(this->m_vMax - p_vPos, this->m_vMax / 2, this->m_movementMaxSpeed);
    this->m_turnAccel = CalculateNewAccel(p_hPos, this->m_hMax / 2, this->m_turnMaxAccel, (int)this->m_turnMinAccel);
    this->m_movementAccel = CalculateNewAccel(this->m_vMax - p_vPos, this->m_vMax / 2, this->m_movementMaxAccel, (int)this->m_turnMinAccel);
  }
  else
  {
    this->m_targetTurnSpeed = 0.0f;
    this->m_targetMovementSpeed = 0.0f;
    this->m_movementAccel = this->m_movementDecel;
    this->m_turnAccel = this->m_turnDecel;
  }
}

float LegoNavController::CalculateNewTargetSpeed(int p_pos, int p_center, float p_maxSpeed)
{
  float result;
  int diff = p_pos - p_center;

  if (diff > this->m_mouseDeadzone)
    result = (diff - m_mouseDeadzone) * p_maxSpeed / (p_center - m_mouseDeadzone);
  else if (diff < -m_mouseDeadzone)
    result = (diff + m_mouseDeadzone) * p_maxSpeed / (p_center - m_mouseDeadzone);
  else
    result = 0.0f;

  return result;
}

float LegoNavController::CalculateNewAccel(int p_pos, int p_center, float p_maxAccel, int p_minAccel)
{
  float result;
  int diff = p_pos - p_center;

  result = Abs(diff) * p_maxAccel / p_center;

  if (result < p_minAccel)
  {
    result = (float)p_minAccel;
  }

  return result;
}