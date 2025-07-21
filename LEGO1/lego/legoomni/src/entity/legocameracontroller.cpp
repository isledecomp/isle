#include "legocameracontroller.h"

#include "3dmanager/lego3dmanager.h"
#include "legoinputmanager.h"
#include "legosoundmanager.h"
#include "legovideomanager.h"
#include "misc.h"
#include "mxmisc.h"
#include "mxtimer.h"
#include "realtime/realtime.h"
#include "roi/legoroi.h"

#include <vec.h>

DECOMP_SIZE_ASSERT(LegoCameraController, 0xc8)

// FUNCTION: LEGO1 0x10011d50
LegoCameraController::LegoCameraController()
{
	SetWorldTransform(Mx3DPointFloat(0, 0, 0), Mx3DPointFloat(0, 0, 1), Mx3DPointFloat(0, 1, 0));
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

// FUNCTION: LEGO1 0x10012020
// FUNCTION: BETA10 0x10067852
MxLong LegoCameraController::Notify(MxParam& p_param)
{
	switch (((MxNotificationParam&) p_param).GetNotification()) {
	case c_notificationDragEnd: {
		if (((((LegoEventNotificationParam&) p_param).GetModifier()) & LegoEventNotificationParam::c_lButtonState) ==
			0) {
			OnLButtonUp(MxPoint32(
				((LegoEventNotificationParam&) p_param).GetX(),
				((LegoEventNotificationParam&) p_param).GetY()
			));
		}
		else if (((((LegoEventNotificationParam&) p_param).GetModifier()) & LegoEventNotificationParam::c_rButtonState) == 0) {
			OnRButtonUp(MxPoint32(
				((LegoEventNotificationParam&) p_param).GetX(),
				((LegoEventNotificationParam&) p_param).GetY()
			));
		}
	} break;
	case c_notificationDragStart: {
		if ((((LegoEventNotificationParam&) p_param).GetModifier()) & LegoEventNotificationParam::c_lButtonState) {
			OnLButtonDown(MxPoint32(
				((LegoEventNotificationParam&) p_param).GetX(),
				((LegoEventNotificationParam&) p_param).GetY()
			));
		}
		else if ((((LegoEventNotificationParam&) p_param).GetModifier()) & LegoEventNotificationParam::c_rButtonState) {
			OnRButtonDown(MxPoint32(
				((LegoEventNotificationParam&) p_param).GetX(),
				((LegoEventNotificationParam&) p_param).GetY()
			));
		}
	} break;
	case c_notificationDrag: {
		OnMouseMove(
			((LegoEventNotificationParam&) p_param).GetModifier(),
			MxPoint32(((LegoEventNotificationParam&) p_param).GetX(), ((LegoEventNotificationParam&) p_param).GetY())
		);
	} break;
	}

	return SUCCESS;
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
	if (p_modifier & LegoEventNotificationParam::c_lButtonState) {
		LeftDrag(p_point.GetX(), p_point.GetY());
	}
	else if (p_modifier & LegoEventNotificationParam::c_rButtonState) {
		RightDrag(p_point.GetX(), p_point.GetY());
	}
}

// FUNCTION: LEGO1 0x10012260
void LegoCameraController::SetWorldTransform(const Vector3& p_at, const Vector3& p_dir, const Vector3& p_up)
{
	CalcLocalTransform(p_at, p_dir, p_up, m_currentTransform);
	m_originalTransform = m_currentTransform;
}

// FUNCTION: LEGO1 0x10012290
// FUNCTION: BETA10 0x10068c34
void LegoCameraController::RotateZ(float p_angle)
{
	m_currentTransform = m_originalTransform;
	m_currentTransform.RotateZ(p_angle);
}

// FUNCTION: LEGO1 0x10012320
// FUNCTION: BETA10 0x10068c73
void LegoCameraController::RotateY(float p_angle)
{
	m_currentTransform = m_originalTransform;
	m_currentTransform.RotateY(p_angle);
}

// FUNCTION: LEGO1 0x100123b0
MxResult LegoCameraController::GetPointOfView(Matrix4& p_matrix)
{
	if (m_lego3DView) {
		ViewROI* pov = m_lego3DView->GetPointOfView();
		if (pov) {
			p_matrix = pov->GetLocal2World();
			return SUCCESS;
		}
	}

	return FAILURE;
}

// FUNCTION: LEGO1 0x100123e0
// FUNCTION: BETA10 0x10068cb2
void LegoCameraController::TransformPointOfView(const Matrix4& p_transform, MxU32 p_multiply)
{
	if (m_lego3DView != NULL) {
		ViewROI* pov = m_lego3DView->GetPointOfView();

		if (pov != NULL) {
			MxMatrix mat;

			if (p_multiply) {
				MXM4(mat, m_currentTransform, p_transform);
			}
			else {
				mat = p_transform;
			}

			((TimeROI*) pov)->CalculateWorldVelocity(mat, Timer()->GetTime());
			pov->WrappedSetLocal2WorldWithWorldDataUpdate(mat);
			m_lego3DView->Moved(*pov);

			SoundManager()->UpdateListener(
				pov->GetWorldPosition(),
				pov->GetWorldDirection(),
				pov->GetWorldUp(),
				pov->GetWorldVelocity()
			);
		}
	}
}

// FUNCTION: LEGO1 0x10012740
Mx3DPointFloat LegoCameraController::GetWorldUp()
{
	if (m_lego3DView && m_lego3DView->GetPointOfView()) {
		Mx3DPointFloat vec;
		vec = m_lego3DView->GetPointOfView()->GetWorldUp();
		return Mx3DPointFloat(vec[0], vec[1], vec[2]);
	}
	else {
		return Mx3DPointFloat(0, 0, 0);
	}
}

// FUNCTION: LEGO1 0x100127f0
Mx3DPointFloat LegoCameraController::GetWorldLocation()
{
	if (m_lego3DView && m_lego3DView->GetPointOfView()) {
		Mx3DPointFloat vec;
		vec = m_lego3DView->GetPointOfView()->GetWorldPosition();
		return Mx3DPointFloat(vec[0], vec[1] - m_entityOffsetUp, vec[2]);
	}
	else {
		return Mx3DPointFloat(0, 0, 0);
	}
}

// FUNCTION: LEGO1 0x100128a0
Mx3DPointFloat LegoCameraController::GetWorldDirection()
{
	if (m_lego3DView && m_lego3DView->GetPointOfView()) {
		Mx3DPointFloat vec;
		vec = m_lego3DView->GetPointOfView()->GetWorldDirection();
		return Mx3DPointFloat(vec[0], vec[1], vec[2]);
	}
	else {
		return Mx3DPointFloat(0, 0, 0);
	}
}
