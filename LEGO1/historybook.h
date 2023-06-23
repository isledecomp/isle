#ifndef HISTORYBOOK_H
#define HISTORYBOOK_H

#include "legoworld.h"

class HistoryBook : public LegoWorld
{
public:
  HistoryBook();
  virtual ~HistoryBook(); // vtable+0x0

  virtual long Notify(MxParam &p); // vtable+0x4
  // VTABLE 0x100da328
};

#endif // HISTORYBOOK_H
