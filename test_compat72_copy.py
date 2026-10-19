#!/usr/bin/env python3
"""Compare the actual Linux 7.2 compatibility helper with libc semantics."""
from pathlib import Path
import subprocess,tempfile
def main():
 s=(Path(__file__).parent/'ndpi-compat72.h').read_text()
 f=s[s.index('static __always_inline char *'):s.index('\n#define strncpy')]
 prefix='''#include <string.h>
#include <stdlib.h>
#include <assert.h>
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
'''
 body='''
int main(void) {
 char source[128],actual[160],expected[160];
 for(size_t length=0;length<128;length++) {
  memset(source,'x',sizeof(source));source[length]=0;
  for(size_t count=0;count<=128;count++) {
   memset(actual,0xa5,sizeof(actual));memset(expected,0xa5,sizeof(expected));
   assert(ndpi_compat_strncpy(actual,source,count)==actual);
   strncpy(expected,source,count);
   assert(!memcmp(actual,expected,sizeof(actual)));
  }
 }
 for(size_t count=1;count<=128;count++) {
  char *fragment=malloc(count);assert(fragment);memset(fragment,'y',count);
  memset(actual,0xa5,sizeof(actual));memset(expected,0xa5,sizeof(expected));
  ndpi_compat_strncpy(actual,fragment,count);strncpy(expected,fragment,count);
  assert(!memcmp(actual,expected,sizeof(actual)));free(fragment);
 }
 return 0;
}
'''
 with tempfile.TemporaryDirectory(prefix='dsg-copy-') as td:
  p=Path(td);(p/'test.c').write_text(prefix+f+body)
  subprocess.run(['clang-21','-fsanitize=address,undefined','-g','-O1',str(p/'test.c'),'-o',str(p/'test')],check=True)
  subprocess.run([str(p/'test')],check=True)
 print('PASS: 16640 copy/padding/fragment cases under ASan/UBSan')
if __name__=='__main__':main()
