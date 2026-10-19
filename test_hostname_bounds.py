#!/usr/bin/env python3
"""Exercise the actual patched hostname formatter with ASan and UBSan locally."""
import argparse,subprocess,tempfile
from pathlib import Path
def main():
 ap=argparse.ArgumentParser();ap.add_argument('source');args=ap.parse_args()
 s=(Path(args.source)/'ndpi-netfilter/src/main.c').read_text()
 function=s[s.index('static char *ndpi_safe_hostname('):s.index('\nstatic void ndpi_host_info(')]
 prefix='''#include <stdlib.h>
#include <string.h>
#include <assert.h>
#define GFP_ATOMIC 0
#define ndpi_min(a,b) ((a)<(b)?(a):(b))
#define kstrndup(s,n,f) strndup(s,n)
'''
 tests=r'''
int main(void) {
 char input[256];
 for (size_t len=0;len<sizeof(input);len++) {
   memset(input,'"',len);input[len]=0;
   char *r=ndpi_safe_hostname(input);assert(r);assert(strlen(r)<=158);free(r);
   memset(input,'\t',len);input[len]=0;
   r=ndpi_safe_hostname(input);assert(r);assert(strlen(r)<=80);free(r);
   memset(input,'a',len);input[len]=0;
   r=ndpi_safe_hostname(input);assert(r);assert(strlen(r)<=78);free(r);
 }
 return 0;
}
'''
 # The raw source string carries one C escape for a tab.
 tests=tests.replace("'\\\\t'", "'\\t'")
 with tempfile.TemporaryDirectory(prefix='dsg-hostname-') as d:
  p=Path(d);(p/'test.c').write_text(prefix+function+tests)
  subprocess.run(['clang-21','-fsanitize=address,undefined','-g','-O1',str(p/'test.c'),'-o',str(p/'test')],check=True)
  subprocess.run([str(p/'test')],check=True)
 print('PASS: 768 actual formatter cases under ASan/UBSan')
if __name__=='__main__':main()
