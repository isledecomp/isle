#include "mxpresenter.h"
#include "mxautolocker.h"

#include "decomp.h"

DECOMP_SIZE_ASSERT(MxPresenter, 0x40);

// OFFSET: LEGO1 0x100b4d50
void MxPresenter::Init()
{
  m_currentTickleState = TickleState_Idle;
  m_action = NULL;
  m_unk0x18 = 0;
  m_unk0x3c = 0;
  m_previousTickleStates = 0;
  m_unk0x10 = 0;
  m_unk0x14 = 0;
}

// OFFSET: LEGO1 0x100b4fc0 STUB
void MxPresenter::ParseExtra()
{
  // TODO
}

// OFFSET: LEGO1 0x1000bf00
MxPresenter::~MxPresenter()
{
}

// OFFSET: LEGO1 0x100b5200
MxLong MxPresenter::Tickle()
{
  MxAutoLocker lock(&this->m_criticalSection);

  switch (this->m_currentTickleState) {
    case TickleState_Ready:
      this->ReadyTickle();

      if (m_currentTickleState != TickleState_Starting)
        break;
    case TickleState_Starting:
      this->StartingTickle();

      if (m_currentTickleState != TickleState_Streaming)
        break;
    case TickleState_Streaming:
      this->StreamingTickle();

      if (m_currentTickleState != TickleState_Repeating)
        break;
    case TickleState_Repeating:
      this->RepeatingTickle();

      if (m_currentTickleState != TickleState_unk5)
        break;
    case TickleState_unk5:
      this->Unk5Tickle();

      if (m_currentTickleState != TickleState_Done)
        break;
    case TickleState_Done:
      this->DoneTickle();
    default:
      break;
  }

  return 0;
}

// OFFSET: LEGO1 0x100b4d80 STUB
MxLong MxPresenter::StartAction(MxStreamController *, MxDSAction *)
{
  // TODO

  return 0;
}

// OFFSET: LEGO1 0x100b4e40 STUB
void MxPresenter::EndAction()
{
  // TODO
}

// OFFSET: LEGO1 0x100b52d0
void MxPresenter::Enable(MxBool p_enable)
{
  if (this->m_action && this->IsEnabled() != p_enable) {
    MxU32 flags = this->m_action->GetFlags();

    if (p_enable)
      this->m_action->SetFlags(flags | MxDSAction::Flag_Enabled);
    else
      this->m_action->SetFlags(flags & ~MxDSAction::Flag_Enabled);
  }
}

// OFFSET: LEGO1 0x100b54c0
MxBool MxPresenter::IsEnabled()
{
  return this->m_action && this->m_action->GetFlags() & MxDSAction::Flag_Enabled;
}

// OFFSET: LEGO1 0x1000be30
void MxPresenter::VTable0x14()
{
}

// OFFSET: LEGO1 0x1000be40
void MxPresenter::ReadyTickle()
{
  ParseExtra();

  m_previousTickleStates |= 1 << (unsigned char)m_currentTickleState;
  m_currentTickleState = TickleState_Starting;
}

// OFFSET: LEGO1 0x1000be60
void MxPresenter::StartingTickle()
{
  m_previousTickleStates |= 1 << (unsigned char)m_currentTickleState;
  m_currentTickleState = TickleState_Streaming;
}

// OFFSET: LEGO1 0x1000be80
void MxPresenter::StreamingTickle()
{
  m_previousTickleStates |= 1 << (unsigned char)m_currentTickleState;
  m_currentTickleState = TickleState_Repeating;
}

// OFFSET: LEGO1 0x1000bea0
void MxPresenter::RepeatingTickle()
{
  m_previousTickleStates |= 1 << (unsigned char)m_currentTickleState;
  m_currentTickleState = TickleState_unk5;
}

// OFFSET: LEGO1 0x1000bec0
void MxPresenter::Unk5Tickle()
{
  m_previousTickleStates |= 1 << (unsigned char)m_currentTickleState;
  m_currentTickleState = TickleState_Done;
}

// OFFSET: LEGO1 0x1000bee0
void MxPresenter::DoneTickle()
{
  m_previousTickleStates |= 1 << m_currentTickleState;
  m_currentTickleState = TickleState_Idle;
}

// OFFSET: LEGO1 0x1000bf70
undefined4 MxPresenter::VTable0x34()
{
  return 0;
}

// OFFSET: LEGO1 0x1000bf80
void MxPresenter::InitVirtual()
{
  Init();
}

// OFFSET: LEGO1 0x1000bf90
void MxPresenter::SetTickleState(TickleState p_tickleState)
{
  m_previousTickleStates |= 1 << (unsigned char)m_currentTickleState;
  m_currentTickleState = p_tickleState;
}

// OFFSET: LEGO1 0x1000bfb0
MxBool MxPresenter::HasTickleStatePassed(TickleState p_tickleState)
{
  return m_previousTickleStates & (1 << (unsigned char)p_tickleState);
}

// OFFSET: LEGO1 0x1000bfc0
undefined4 MxPresenter::VTable0x4c()
{
  return 0;
}

// OFFSET: LEGO1 0x1000bfd0
undefined MxPresenter::VTable0x50(undefined4, undefined4)
{
  return 0;
}
