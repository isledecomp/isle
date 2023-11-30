// Sample for python unit tests
// Not part of the decomp

#include <stdio.h>

int no_offset_comment()
{
  static int dummy = 123;
  return -1;
}

// OFFSET: TEST 0xdeadbeef
void regular_ole_function()
{
  printf("hi there");
}
