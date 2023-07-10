#include "mxnotificationmanager.h"

// OFFSET: LEGO1 0x100ac320 TEMPLATE
// list<unsigned int,allocator<unsigned int> >::~list<unsigned int,allocator<unsigned int> >

// FIXME: Example of template compare functionality, remove before merging.
#include <stl.h>
#include <iostream>
void make_a_list() {
  List<unsigned int> l;
  cout << l.size();
}

// OFFSET: LEGO1 0x100ac450 STUB
MxNotificationManager::~MxNotificationManager()
{
  // TODO
}

// OFFSET: LEGO1 0x100ac800 STUB
MxLong MxNotificationManager::Tickle()
{
  // TODO

  return 0;
}
