#include "legocameracontroller.h"

#include "legoinputmanager.h"
#include "legonotify.h"
#include "legoomni.h"
#include "legovideomanager.h"

DECOMP_SIZE_ASSERT(LegoCameraController, 0xc8);

// FUNCTION: LEGO1 0x10011d50
LegoCameraController::LegoCameraController()
{
	SetWorldTransform(Vector3Data(0, 0, 0), Vector3Data(0, 0, 1), Vector3Data(0, 1, 0));
}

// FUNCTION: LEGO1 0x10011f70
LegoCameraController::~LegoCameraController()
{
	if (InputManager()) {
		if (InputManager()->GetCamera() == this) {
			InputManager()->ClearCamera();
		}
	}
}

// FUNCTION: LEGO1 0x10011ff0
MxResult LegoCameraController::Create()
{
	InputManager()->SetCamera(this);
	return LegoPointOfViewController::Create(VideoManager()->Get3DManager()->GetLego3DView());
}

// STUB: LEGO1 0x10012020
MxLong LegoCameraController::Notify(MxParam& p_param)
{
	// TODO
	return 0;
}

// FUNCTION: LEGO1 0x100121b0
void LegoCameraController::OnLButtonDown(MxPoint32 p_point)
{
	LeftDown(p_point.GetX(), p_point.GetY());
}

// FUNCTION: LEGO1 0x100121d0
void LegoCameraController::OnLButtonUp(MxPoint32 p_point)
{
	LeftUp(p_point.GetX(), p_point.GetY());
}

// FUNCTION: LEGO1 0x100121f0
void LegoCameraController::OnRButtonDown(MxPoint32 p_point)
{
	RightDown(p_point.GetX(), p_point.GetY());
}

// FUNCTION: LEGO1 0x10012210
void LegoCameraController::OnRButtonUp(MxPoint32 p_point)
{
	RightUp(p_point.GetX(), p_point.GetY());
}

// FUNCTION: LEGO1 0x10012230
void LegoCameraController::OnMouseMove(MxU8 p_modifier, MxPoint32 p_point)
{
	if (p_modifier & c_lButtonState)
		LeftDrag(p_point.GetX(), p_point.GetY());
	else if (p_modifier & c_rButtonState)
		RightDrag(p_point.GetX(), p_point.GetY());
}

// FUNCTION: LEGO1 0x10012260
void LegoCameraController::SetWorldTransform(const Vector3Impl& p_at, const Vector3Impl& p_dir, const Vector3Impl& p_up)
{
	CalcLocalTransform(p_at, p_dir, p_up, m_matrix1);
	m_matrix2 = m_matrix1;
}

// STUB: LEGO1 0x100123e0
void LegoCameraController::FUN_100123e0(Matrix4Data& p_transform, MxU32)
{
}

// STUB: LEGO1 0x10012740
Vector3Data& LegoCameraController::FUN_10012740()
{
	// Actually returns reference to a member
	static Vector3Data g_v;
	return g_v;
}

// STUB: LEGO1 0x100127f0
Vector3Data& LegoCameraController::FUN_100127f0()
{
	// Actually returns reference to a member
	static Vector3Data g_v;
	return g_v;
}

// STUB: LEGO1 0x100128a0
Vector3Data& LegoCameraController::FUN_100128a0()
{
	// Actually returns reference to a member
	static Vector3Data g_v;
	return g_v;
}
