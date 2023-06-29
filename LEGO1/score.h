#ifndef SCORE_H
#define SCORE_H

#include "legoworld.h"

// VTABLE 0x100d4018
// SIZE 0x104
class Score : public LegoWorld
{
public:
  Score();
  virtual ~Score() override; // vtable+0x0

  virtual long Notify(MxParam &p) override; // vtable+0x4

};

#endif // SCORE_H
