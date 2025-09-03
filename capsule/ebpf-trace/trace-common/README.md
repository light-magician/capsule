# trace-common

syscalls per architecture

### how to get syscalls given architecture

```bash
#get architecture
uname -m
# get syscalls formatted [name number]
gcc -E -dM - <<<'#include <asm/unistd.h>' | awk '/^#define __NR_/
{sub("__NR_","",$2); print $2, $3}' | sort -k2,2n
```
