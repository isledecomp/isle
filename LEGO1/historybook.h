#ifndef HISTORYBOOK_H
#define HISTORYBOOK_H

#include "legoworld.h"

// VTABLE 0x100da328
// SIZE 0x3e4
class HistoryBook : public LegoWorld
{
public:
  HistoryBook();
  virtual ~HistoryBook() override; // vtable+0x0

  virtual long Notify(MxParam &p) override; // vtable+0x4

  // OFFSET: LEGO1 0x10082390
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x100f04bc
    return "HistoryBook";
  }

  // OFFSET: LEGO1 0x100823a0
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, HistoryBook::ClassName()) || LegoWorld::IsA(name);
  }
};

#endif // HISTORYBOOK_H
