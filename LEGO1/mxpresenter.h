#ifndef MXPRESENTER_H
#define MXPRESENTER_H

class MxPresenter
{
protected:
  __declspec(dllexport) virtual void DoneTickle();
  __declspec(dllexport) void Init();
  __declspec(dllexport) virtual void ParseExtra();
public:
  __declspec(dllexport) virtual ~MxPresenter();
  __declspec(dllexport) virtual void Enable(unsigned char);
  __declspec(dllexport) virtual void EndAction();
  __declspec(dllexport) virtual long StartAction(MxStreamController *, MxDSAction *);
  __declspec(dllexport) virtual long Tickle();

  const char* GetClassName();
};

#endif // MXPRESENTER_H
