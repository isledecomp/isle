#ifndef LEGOENTITY_H
#define LEGOENTITY_H

#include "mxentity.h"

class LegoEntity : public MxEntity
{
public:
	// OFFSET LEGO1 100105f0
	LegoEntity();
  __declspec(dllexport) virtual ~LegoEntity();

  virtual const char* GetClassName() const { return "LegoEntity"; }
};

#endif // LEGOENTITY_H
