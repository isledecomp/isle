#ifndef LEGOMODELPRESENTER_H
#define LEGOMODELPRESENTER_H

#include "mxvideopresenter.h"

class LegoModelPresenter : public MxVideoPresenter
{
public:
  __declspec(dllexport) static void configureLegoModelPresenter(int param_1);
};

#endif // LEGOMODELPRESENTER_H
