#include "mxmediapresenter.h"

DECOMP_SIZE_ASSERT(MxMediaPresenter, 0x50);

// OFFSET: LEGO1 0x1000c550
MxMediaPresenter::~MxMediaPresenter()
{
  Destroy(TRUE);
}

// OFFSET: LEGO1 0x100b5d10 STUB
MxResult MxMediaPresenter::Tickle()
{
  // TODO
  return SUCCESS;
}

// OFFSET: LEGO1 0x100b54e0
void MxMediaPresenter::Init()
{
  this->m_unk40 = NULL;
  this->m_unk44 = NULL;
  this->m_unk48 = NULL;
  this->m_unk4c = NULL;
}

// OFFSET: LEGO1 0x100b54f0 STUB
void MxMediaPresenter::Destroy(MxBool p_fromDestructor)
{
  // TODO
}

// OFFSET: LEGO1 0x100b5d90 STUB
void MxMediaPresenter::StreamingTickle()
{
  // TODO
}

// OFFSET: LEGO1 0x100b5e10 STUB
void MxMediaPresenter::RepeatingTickle()
{
  // TODO
}

// OFFSET: LEGO1 0x100b5ef0
void MxMediaPresenter::DoneTickle()
{
  m_previousTickleStates |= 1 << m_currentTickleState;
  m_currentTickleState = TickleState_Idle;
  EndAction();
}

// OFFSET: LEGO1 0x100b6030 STUB
void MxMediaPresenter::Enable(MxBool p_enable)
{
  // TODO
}

// OFFSET: LEGO1 0x1000c5b0
void MxMediaPresenter::Destroy()
{
  Destroy(FALSE);
}

// OFFSET: LEGO1 0x100b5700 STUB
MxLong MxMediaPresenter::StartAction(MxStreamController * p_controller, MxDSAction * p_action)
{
  return 0;
}

// OFFSET: LEGO1 0x100b5bc0 STUB
void MxMediaPresenter::EndAction()
{
  // TODO
}

// OFFSET: LEGO1 0x100b5f10 STUB
void MxMediaPresenter::VTable0x58()
{
  // TODO
}
