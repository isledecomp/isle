#include "legocarbuildpresenter.h"

#include "legoentity.h"
#include "mxautolock.h"

DECOMP_SIZE_ASSERT(LegoCarBuildAnimPresenter::UnknownListEntry, 0x0c)
DECOMP_SIZE_ASSERT(LegoCarBuildAnimPresenter, 0x150)

// FUNCTION: LEGO1 0x10078400
// FUNCTION: BETA10 0x100707c0
LegoCarBuildAnimPresenter::LegoCarBuildAnimPresenter()
{
	m_unk0xbc = 0;
	m_unk0xbe = 0;
	m_unk0xc0 = 0;
	m_unk0x128 = NULL;
	m_unk0xc4 = NULL;
	m_unk0x130 = 0;
	m_unk0x12c = 0;
	m_unk0x134 = 0;
	m_unk0x138 = 0;
	m_unk0x13c = 0;
	m_unk0x140 = NULL;
	m_unk0x144 = -1;
	m_unk0x148 = -1;
	m_unk0x14c = NULL;
}

// FUNCTION: LEGO1 0x10078500
void LegoCarBuildAnimPresenter::RepeatingTickle()
{
	// empty
}

// FUNCTION: LEGO1 0x10078680
// FUNCTION: BETA10 0x1007091e
LegoCarBuildAnimPresenter::~LegoCarBuildAnimPresenter()
{
	if (m_unk0x128) {
		for (MxS16 i = 0; i < m_unk0xbe; i++) {
			delete m_unk0x128[i].m_unk0x00;
			delete m_unk0x128[i].m_unk0x04;
		}
		delete[] m_unk0x128;
	}

	m_unk0xc8.GetRoot()->SetNumChildren(0);
	*m_unk0xc8.GetRoot()->GetChildren() = NULL;

	if (m_unk0x14c) {
		delete m_unk0x14c;
	}
}

// STUB: LEGO1 0x10078790
void LegoCarBuildAnimPresenter::PutFrame()
{
	// TODO
}

// STUB: LEGO1 0x100788c0
// STUB: BETA10 0x10070b56
void LegoCarBuildAnimPresenter::ReadyTickle()
{
	// TODO
}

// STUB: LEGO1 0x100789e0
// STUB: BETA10 0x10070cdd
void LegoCarBuildAnimPresenter::StreamingTickle()
{
	// TODO
}

// FUNCTION: LEGO1 0x10078db0
// FUNCTION: BETA10 0x100712f3
void LegoCarBuildAnimPresenter::EndAction()
{
	if (m_action) {
		AUTOLOCK(m_criticalSection);
		MxVideoPresenter::EndAction();
		m_unk0xbc = 0;
	}
}

// STUB: LEGO1 0x10079160
void LegoCarBuildAnimPresenter::FUN_10079160()
{
	// called from LegoCarBuildAnimPresenter::StreamingTickle()
	// TODO
}

// FUNCTION: LEGO1 0x10079920
// FUNCTION: BETA10 0x1007225d
void LegoCarBuildAnimPresenter::RotateAroundYAxis(MxFloat p_angle)
{
	if (m_unk0xc4) {
		LegoRotationKey* rotationKey = m_unk0xc4->GetRotationKey(0);

		Mx4DPointFloat
			currentRotation(rotationKey->GetX(), rotationKey->GetY(), rotationKey->GetZ(), rotationKey->GetAngle());
		Mx4DPointFloat additionalRotation(0.0f, 1.0f, 0.0f, -p_angle);
		Mx4DPointFloat newRotation;

		additionalRotation.NormalizeQuaternion();
		newRotation.EqualsHamiltonProduct(&currentRotation, &additionalRotation);

		if (newRotation[3] < 0.9999) {
			rotationKey->FUN_100739a0(TRUE);
		}
		else {
			rotationKey->FUN_100739a0(FALSE);
		}

		m_unk0xc4->GetRotationKey(0)->SetX(newRotation[0]);
		m_unk0xc4->GetRotationKey(0)->SetY(newRotation[1]);
		m_unk0xc4->GetRotationKey(0)->SetZ(newRotation[2]);
		m_unk0xc4->GetRotationKey(0)->SetAngle(newRotation[3]);

		if (m_unk0x140->GetROI()) {
			FUN_1006b9a0(&m_unk0xc8, m_unk0x12c, NULL);
		}
	}
}

// FUNCTION: LEGO1 0x10079b80
// FUNCTION: BETA10 0x1007258f
MxBool LegoCarBuildAnimPresenter::StringEndsOnYOrN(const LegoChar* p_string)
{
	return (p_string[strlen(p_string) - 2] == 'N') || (p_string[strlen(p_string) - 2] == 'n') ||
		   (p_string[strlen(p_string) - 2] == 'Y') || (p_string[strlen(p_string) - 2] == 'y');
}

// STUB: LEGO1 0x10079c30
// STUB: BETA10 0x100726a6
MxBool LegoCarBuildAnimPresenter::FUN_10079c30(const LegoChar* p_name)
{
	// TODO
	return FALSE;
}

// FUNCTION: LEGO1 0x10079ca0
// FUNCTION: BETA10 0x10072740
MxBool LegoCarBuildAnimPresenter::FUN_10079ca0(const LegoChar* p_name)
{
	for (MxS16 i = 0; i < m_unk0xc0; i++) {
		if (strcmpi(p_name, m_unk0x128[i].m_unk0x00) == 0) {
			return TRUE;
		}
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x10079cf0
// FUNCTION: BETA10 0x100727b3
MxBool LegoCarBuildAnimPresenter::FUN_10079cf0(const LegoChar* p_string)
{
	return (p_string[strlen(p_string) - 2] == 'Y') || (p_string[strlen(p_string) - 2] == 'y');
}

// FUNCTION: LEGO1 0x10079e20
// FUNCTION: BETA10 0x10072959
const BoundingSphere& LegoCarBuildAnimPresenter::FUN_10079e20()
{
	LegoROI* roi = m_unk0x140->GetROI();
	return roi->FindChildROI(m_unk0x128[m_unk0xc0].m_unk0x04, roi)->GetWorldBoundingSphere();
}
