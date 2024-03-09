#include "legonavcontroller.h"

#include "legoinputmanager.h"
#include "legoutils.h"
#include "legovideomanager.h"
#include "misc.h"
#include "mxmisc.h"

// GLOBAL: LEGO1 0x100f4c28
int g_mouseDeadzone = 40;

// GLOBAL: LEGO1 0x100f4c2c
float g_zeroThreshold = 0.001f;

// GLOBAL: LEGO1 0x100f4c30
float g_movementMaxSpeed = 40.0f;

// GLOBAL: LEGO1 0x100f4c34
float g_turnMaxSpeed = 20.0f;

// GLOBAL: LEGO1 0x100f4c38
float g_movementMaxAccel = 15.0f;

// GLOBAL: LEGO1 0x100f4c3c
float g_turnMaxAccel = 30.0f;

// GLOBAL: LEGO1 0x100f4c40
float g_movementMinAccel = 4.0f;

// GLOBAL: LEGO1 0x100f4c44
float g_turnMinAccel = 15.0f;

// GLOBAL: LEGO1 0x100f4c48
float g_movementDecel = 50.0f;

// GLOBAL: LEGO1 0x100f4c4c
float g_turnDecel = 50.0f;

// GLOBAL: LEGO1 0x100f4c50
float g_turnSensitivity = 0.4f;

// GLOBAL: LEGO1 0x100f4c54
MxBool g_turnUseVelocity = FALSE;

// FUNCTION: LEGO1 0x10054ac0
LegoNavController::LegoNavController()
{
	ResetToDefault();

	this->m_unk0x18 = 0.0f;
	this->m_unk0x1c = 0.0f;
	this->m_targetMovementSpeed = 0.0f;
	this->m_targetTurnSpeed = 0.0f;
	this->m_movementAccel = 0.0f;
	this->m_turnAccel = 0.0f;
	this->m_trackDefault = FALSE;
	this->m_unk0x5d = FALSE;
	this->m_unk0x6c = FALSE;
	this->m_unk0x64 = 0;
	this->m_unk0x68 = 0;
	this->m_unk0x60 = 0;

	MxTimer* timer = Timer();
	this->m_time = timer->GetTime();

	InputManager()->Register(this);
}

// FUNCTION: LEGO1 0x10054c30
LegoNavController::~LegoNavController()
{
	InputManager()->UnRegister(this);
}

// FUNCTION: LEGO1 0x10054ca0
void LegoNavController::SetControlMax(int p_hMax, int p_vMax)
{
	this->m_hMax = p_hMax;
	this->m_vMax = p_vMax;

	if (VideoManager()->GetVideoParam().Flags().GetFullScreen()) {
		this->m_hMax = 640;
		this->m_vMax = 480;
	}
}

// FUNCTION: LEGO1 0x10054cd0
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

// FUNCTION: LEGO1 0x10054d40
void LegoNavController::GetDefaults(
	int* p_mouseDeadzone,
	float* p_movementMaxSpeed,
	float* p_turnMaxSpeed,
	float* p_movementMaxAccel,
	float* p_turnMaxAccel,
	float* p_movementDecel,
	float* p_turnDecel,
	float* p_movementMinAccel,
	float* p_turnMinAccel,
	float* p_turnSensitivity,
	MxBool* p_turnUseVelocity
)
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

// FUNCTION: LEGO1 0x10054dd0
void LegoNavController::SetDefaults(
	int p_mouseDeadzone,
	float p_movementMaxSpeed,
	float p_turnMaxSpeed,
	float p_movementMaxAccel,
	float p_turnMaxAccel,
	float p_movementDecel,
	float p_turnDecel,
	float p_movementMinAccel,
	float p_turnMinAccel,
	float p_turnSensitivity,
	MxBool p_turnUseVelocity
)
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

// FUNCTION: LEGO1 0x10054e40
void LegoNavController::SetTargets(int p_hPos, int p_vPos, MxBool p_accel)
{
	if (this->m_trackDefault != FALSE) {
		ResetToDefault();
	}

	if (p_accel != FALSE) {
		this->m_targetTurnSpeed = CalculateNewTargetSpeed(p_hPos, this->m_hMax / 2, this->m_turnMaxSpeed);
		this->m_targetMovementSpeed =
			CalculateNewTargetSpeed(this->m_vMax - p_vPos, this->m_vMax / 2, this->m_movementMaxSpeed);
		this->m_turnAccel =
			CalculateNewAccel(p_hPos, this->m_hMax / 2, this->m_turnMaxAccel, (int) this->m_turnMinAccel);
		this->m_movementAccel = CalculateNewAccel(
			this->m_vMax - p_vPos,
			this->m_vMax / 2,
			this->m_movementMaxAccel,
			(int) this->m_movementMinAccel
		);
	}
	else {
		this->m_targetTurnSpeed = 0.0f;
		this->m_targetMovementSpeed = 0.0f;
		this->m_movementAccel = this->m_movementDecel;
		this->m_turnAccel = this->m_turnDecel;
	}
}

// FUNCTION: LEGO1 0x10054f10
float LegoNavController::CalculateNewTargetSpeed(int p_pos, int p_center, float p_maxSpeed)
{
	float result;
	int diff = p_pos - p_center;

	if (diff > this->m_mouseDeadzone) {
		result = (diff - m_mouseDeadzone) * p_maxSpeed / (p_center - m_mouseDeadzone);
	}
	else if (diff < -m_mouseDeadzone) {
		result = (diff + m_mouseDeadzone) * p_maxSpeed / (p_center - m_mouseDeadzone);
	}
	else {
		result = 0.0f;
	}

	return result;
}

// FUNCTION: LEGO1 0x10054f90
float LegoNavController::CalculateNewAccel(int p_pos, int p_center, float p_maxAccel, int p_minAccel)
{
	float result;
	int diff = p_pos - p_center;

	result = Abs(diff) * p_maxAccel / p_center;

	if (result < p_minAccel) {
		result = (float) p_minAccel;
	}

	return result;
}

// FUNCTION: LEGO1 0x10054fe0
float LegoNavController::CalculateNewVel(float p_targetVel, float p_currentVel, float p_accel, float p_time)
{
	float newVel = p_currentVel;

	float velDiff = p_targetVel - p_currentVel;
	int vSign = velDiff > 0 ? 1 : -1;

	if (Abs(velDiff) > this->m_zeroThreshold) {
		float deltaVel = p_accel * p_time;
		newVel = p_currentVel + (deltaVel * vSign);

		if (vSign > 0) {
			newVel = Min(newVel, p_targetVel);
		}
		else {
			newVel = Max(newVel, p_targetVel);
		}
	}

	return newVel;
}

// STUB: LEGO1 0x10055620
void LegoNavController::SetLocation(MxU32 p_location)
{
}

// STUB: LEGO1 0x10055a60
MxLong LegoNavController::Notify(MxParam& p_param)
{
	// TODO
	return 0;
}
