#include "legoentitypresenter.h"

#include "islepathactor.h"
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
undefined4 LegoEntityPresenter::VTable0x6c(IslePathActor* p_unk0x4c)
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

// FUNCTION: LEGO1 0x10053680
MxResult LegoEntityPresenter::StartAction(MxStreamController* p_controller, MxDSAction* p_action)
{
	MxResult result = MxCompositePresenter::StartAction(p_controller, p_action);

	if (VideoManager()) {
		VideoManager()->AddPresenter(*this);
	}

	return result;
}

// STUB: LEGO1 0x100536c0
void LegoEntityPresenter::ReadyTickle()
{
	// TODO
}

// FUNCTION: LEGO1 0x10053720
void LegoEntityPresenter::RepeatingTickle()
{
	if (m_list.size() == 0) {
		EndAction();
	}
}

// FUNCTION: LEGO1 0x10053750
void LegoEntityPresenter::ParseExtra()
{
	char data[512];
	MxU16 len = m_action->GetExtraLength();
	if (len) {
		memcpy(data, m_action->GetExtraData(), len);
		data[len] = 0;

		len &= MAXWORD;
		m_unk0x4c->ParseAction(data);
	}
}
