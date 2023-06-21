#include "legophonemepresenter.h"

// OFFSET: LEGO1 0x100f064c
static char* g_legoPhonemePresenterClassName = "LegoPhonemePresenter";

// OFFSET: LEGO1 0x1004e340
LegoPhonemePresenter::~LegoPhonemePresenter()
{
  // TODO
}

// OFFSET: LEGO1 0x1004e310
const char *LegoPhonemePresenter::GetClassName() const
{
  return g_legoPhonemePresenterClassName;
}