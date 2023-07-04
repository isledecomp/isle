#include "legogamestate.h"
#include "legoomni.h"

// OFFSET: LEGO1 0x10039550
LegoGameState::LegoGameState()
{
  // TODO
}

// OFFSET: LEGO1 0x10039720
LegoGameState::~LegoGameState()
{
  // TODO
}

// OFFSET: LEGO1 0x10039c60
MxResult LegoGameState::Load(MxULong)
{
  // TODO
  return 0;
}

// OFFSET: LEGO1 0x10039980
MxResult LegoGameState::Save(MxULong p)
{
  // TODO
  return 0;
}

// OFFSET: LEGO1 0x1003a2e0
void LegoGameState::SerializePlayersInfo(MxS16 p)
{
  // TODO
}

// OFFSET: LEGO1 0x1003cdd0
void LegoGameState::SerializeScoreHistory(MxS16 p)
{
  // TODO
}

// OFFSET: LEGO1 0x10039f00
void LegoGameState::SetSavePath(char *p_savePath)
{
  if (m_savePath != NULL)
  {
    delete[] m_savePath;
  }
  if (p_savePath)
  {
    m_savePath = new char[strlen(p_savePath) + 1];
    strcpy(m_savePath, p_savePath);
  }
  else
  {
    m_savePath = NULL;
  }
}
