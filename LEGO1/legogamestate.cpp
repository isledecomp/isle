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
void LegoGameState::SetSavePath(char *p_SavePath)
{
  if (m_SavePath != NULL)
  {
    delete[] m_SavePath;
  }
  if (p_SavePath)
  {
    m_SavePath = new char[strlen(p_SavePath) + 1];
    strcpy(m_SavePath, p_SavePath);
  }
  else
  {
    m_SavePath = NULL;
  }
}
