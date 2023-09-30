#include "legogamestate.h"

#include "legoomni.h"
#include "mxvariabletable.h"
#include "decomp.h"

// Based on the highest dword offset (0x42c) referenced in the constructor.
// There may be other members that come after.
DECOMP_SIZE_ASSERT(LegoGameState, 0x430)

// OFFSET: LEGO1 0x10039550
LegoGameState::LegoGameState()
{
  // TODO
  m_backgroundColor = new LegoBackgroundColor("backgroundcolor", "set 56 54 68");
  VariableTable()->SetVariable(m_backgroundColor);

  m_tempBackgroundColor = new LegoBackgroundColor("tempBackgroundcolor", "set 56 54 68");
  VariableTable()->SetVariable(m_tempBackgroundColor);

  m_fullScreenMovie = new LegoFullScreenMovie("fsmovie", "disable");
  VariableTable()->SetVariable(m_fullScreenMovie);

  VariableTable()->SetVariable("lightposition", "2");
  SerializeScoreHistory(1);
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
