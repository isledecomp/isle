// Sample for python unit tests
// Not part of the decomp

// FUNCTION: TEST 0x1234
void short_function() { static char* msg = "oneliner"; }

// FUNCTION: TEST 0x5555
void function_after_one_liner()
{
  // This function comes after the previous that is on a single line.
  // Do we report the offset for this one correctly?
}
