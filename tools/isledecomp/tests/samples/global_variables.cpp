// Sample for python unit tests
// Not part of the decomp

// Global variables inside and outside of functions

// GLOBAL: TEST 0x1000
const char *g_message = "test";

// FUNCTION: TEST 0x1234
void function01()
{
  // GLOBAL: TEST 0x5555
  static int g_hello = 123;
}
