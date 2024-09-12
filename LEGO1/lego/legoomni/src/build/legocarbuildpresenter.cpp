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
	m_unk0xc4 = 0;
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

// STUB: LEGO1 0x10079920
// STUB: BETA10 0x1007225d
void LegoCarBuildAnimPresenter::FUN_10079920(float p_param1)
{
	// TODO
}

// FUNCTION: LEGO1 0x10079b80
// FUNCTION: BETA10 0x1007258f
MxBool LegoCarBuildAnimPresenter::StringEndsOnYOrN(const LegoChar* p_string)
{
	return (p_string[strlen(p_string) - 2] == 'N') || (p_string[strlen(p_string) - 2] == 'n') ||
		   (p_string[strlen(p_string) - 2] == 'Y') || (p_string[strlen(p_string) - 2] == 'y');
}

// FUNCTION: LEGO1 0x10079ca0
// FUNCTION: BETA10 0x10072740
MxBool LegoCarBuildAnimPresenter::FUN_10079ca0(const char* p_param1)
{
	// not quite correct yet; something going on with word pointers
	for (MxS16 i = 0; i < m_unk0xc0; i++) {
		if (strcmpi(p_param1, m_unk0x128[i].m_unk0x00) == 0) {
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
const BoundingSphere& LegoCarBuildAnimPresenter::FUN_10079e20()
{
	LegoROI* roi = m_unk0x140->GetROI();
	return roi->FindChildROI(m_unk0x128[m_unk0xc0].m_unk0x04, roi)->GetWorldBoundingSphere();
}
