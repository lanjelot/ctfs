// h4ckit-ctf-2016 tryhard
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
  int i;
  int n;
  int seed;

  seed = atoi(argv[1]);
  srand(seed);

  for (i=0; i < 4; i++) {
    n = rand() % 94 + 33;
    printf("%c", n);
  }
  printf("\n");

  return 0;
}
