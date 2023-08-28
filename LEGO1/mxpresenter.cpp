#include "mxpresenter.h"

#include "decomp.h"

DECOMP_SIZE_ASSERT(MxPresenter, 0x40);

// OFFSET: LEGO1 0x1000bee0
void MxPresenter::DoneTickle()
{
  m_previousTickleFlags |= 1 << m_currentTickleFlag;
  m_currentTickleFlag = 0;
}

// OFFSET: LEGO1 0x100b4d50
void MxPresenter::Init()
{
  m_currentTickleFlag = 0;
  m_action = NULL;
  m_unk0x18 = 0;
  m_unk0x3c = 0;
  m_previousTickleFlags = 0;
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

// OFFSET: LEGO1 0x100b5200 STUB
MxLong MxPresenter::Tickle()
{
  // TODO

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

// OFFSET: LEGO1 0x100b52d0 STUB
void MxPresenter::Enable(unsigned char)
{
  // TODO
}

// OFFSET: LEGO1 0x1000be30
void MxPresenter::VTable0x14()
{
}

// OFFSET: LEGO1 0x1000be40
void MxPresenter::VTable0x18()
{
  ParseExtra();
  m_previousTickleFlags |= 1 << (unsigned char)m_currentTickleFlag;
  m_currentTickleFlag = 2;
}

// OFFSET: LEGO1 0x1000be60
void MxPresenter::VTable0x1c()
{
  m_previousTickleFlags |= 1 << (unsigned char)m_currentTickleFlag;
  m_currentTickleFlag = 3;
}

// OFFSET: LEGO1 0x1000be80
void MxPresenter::VTable0x20()
{
  m_previousTickleFlags |= 1 << (unsigned char)m_currentTickleFlag;
  m_currentTickleFlag = 4;
}

// OFFSET: LEGO1 0x1000bea0
void MxPresenter::VTable0x24()
{
  m_previousTickleFlags |= 1 << (unsigned char)m_currentTickleFlag;
  m_currentTickleFlag = 5;
}

// OFFSET: LEGO1 0x1000bec0
void MxPresenter::VTable0x28()
{
  m_previousTickleFlags |= 1 << (unsigned char)m_currentTickleFlag;
  m_currentTickleFlag = 6;
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
void MxPresenter::VTable0x44(undefined4 param)
{
  m_previousTickleFlags |= 1 << (unsigned char)m_currentTickleFlag;
  m_currentTickleFlag = param;
}

// OFFSET: LEGO1 0x1000bfb0
unsigned char MxPresenter::VTable0x48(unsigned char param)
{
  return m_previousTickleFlags & (1 << param);
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
