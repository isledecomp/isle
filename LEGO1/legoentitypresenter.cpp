#include "legoentitypresenter.h"

#include "legoomni.h"
#include "legovideomanager.h"

DECOMP_SIZE_ASSERT(LegoEntityPresenter, 0x50);

// FUNCTION: LEGO1 0x10053440
LegoEntityPresenter::LegoEntityPresenter()
{
	Init();
}

// FUNCTION: LEGO1 0x100535c0
void LegoEntityPresenter::Init()
{
	m_unk0x4c = 0;
}

// FUNCTION: LEGO1 0x100535d0
LegoEntityPresenter::~LegoEntityPresenter()
{
	Destroy(TRUE);
}

// FUNCTION: LEGO1 0x10053630
undefined4 LegoEntityPresenter::VTable0x6c(undefined4 p_unk0x4c)
{
	m_unk0x4c = p_unk0x4c;
	return 0;
}

// FUNCTION: LEGO1 0x10053640
void LegoEntityPresenter::Destroy(MxBool p_fromDestructor)
{
	if (VideoManager()) {
		VideoManager()->RemovePresenter(*this);
	}

	Init();
}

// FUNCTION: LEGO1 0x10053670
void LegoEntityPresenter::Destroy()
{
	Destroy(FALSE);
}
