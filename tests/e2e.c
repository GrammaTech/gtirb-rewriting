// gcc e2e.c -o e2e && ddisasm e2e --ir e2e.gtirb

#include <stdio.h>
#include <unistd.h>

// This is intentionally not called in the program to test that we can insert
// a call and do it according to the platform ABI. It also has more arguments
// than fit in registers so that we test the stack argument passing.
void print_integers(int arg1, int arg2, int arg3, int arg4, int arg5, int arg6,
                    int arg7, int arg8) {
  char buff[256];
  int fmt_len = snprintf(buff, sizeof(buff),
                         "print_integers: %i, %i, %i, %i, %i, %i, %i, %i\n",
                         arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);

  write(1, buff, fmt_len);
}

int main(int argc, char **argv) {
  printf("%i arguments\n", argc);
  return 0;
}
