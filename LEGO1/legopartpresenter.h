#ifndef LEGOPARTPRESENTER_H
#define LEGOPARTPRESENTER_H

class LegoPartPresenter
{
public:
  __declspec(dllexport) static void configureLegoPartPresenter(int param_1, int param_2);
  const char* GetClassName();
};

#endif // LEGOPARTPRESENTER_H
