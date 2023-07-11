#ifndef MXLIST_H
#define MXLIST_H

#ifndef ISLE_COMPAT
#include <STL.H>
#define LIST_T List<T>
#else
#include <list>
#define LIST_T std::list<T>
#endif

template <class T>
class MxList : public LIST_T
{
public:
  inline MxList() : LIST_T() {}
  inline ~MxList() {}
};

#endif // MXLIST_H
