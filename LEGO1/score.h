#ifndef SCORE_H
#define SCORE_H

#include "legoworld.h"

class Score : public LegoWorld
{
public:
  Score();
  virtual ~Score(); // vtable+0x0

  virtual long Notify(MxParam &p); // vtable+0x4

  // SIZE 0x104
};

#endif // SCORE_H
