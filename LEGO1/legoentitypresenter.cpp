#include "legoentitypresenter.h"

#include "legoomni.h"
#include "legovideomanager.h"

// OFFSET: LEGO1 0x10053440
LegoEntityPresenter::LegoEntityPresenter()
{
	Init();
}

// OFFSET: LEGO1 0x100535d0
LegoEntityPresenter::~LegoEntityPresenter()
{
	Destroy();
}

// OFFSET: LEGO1 0x100535c0
void LegoEntityPresenter::Init()
{
	m_unk4c = 0;
}

// OFFSET: LEGO1 0x10053640
undefined4 LegoEntityPresenter::Destroy()
{
	if (VideoManager()) {
		VideoManager()->RemovePresenter(*this);
	}

	return Init();
}

// OFFSET: LEGO1 0x10053630
undefined4 LegoEntityPresenter::vtable6c(undefined4 p_unknown)
{
	m_unk4c = p_unknown;
	return 0;
}
