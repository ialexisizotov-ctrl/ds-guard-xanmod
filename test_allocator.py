#!/usr/bin/env python3
"""Test actual allocator callbacks; original regression must fail under ASan."""
def main():
    from pathlib import Path
    import subprocess,json,hashlib,re
    import argparse,tempfile
    ap=argparse.ArgumentParser();ap.add_argument('source');ap.add_argument('--report');args=ap.parse_args()
    P=Path(__file__).resolve().parent
    source=(Path(args.source)/'ndpi-netfilter/src/main.c').read_text()
    a=source.index('#include <linux/xarray.h>');b=source.index('static void fill_prefix_any',a)
    fixed=source[a:b]
    edits=json.loads((P/'source-edits.json').read_text())['ndpi-netfilter/src/main.c']
    original=next(a for a,b in edits if a.startswith('static void *malloc_wrapper(size_t size)'))
    workspace=tempfile.TemporaryDirectory(prefix='dsg-allocator-test-');T=Path(workspace.name)
    stub=r'''
    #include <stdlib.h>
    #include <stdint.h>
    #include <stdbool.h>
    #include <string.h>
    #include <stdio.h>
    #include <assert.h>
    #include <errno.h>
    #include <limits.h>
    #define GFP_ATOMIC 1
    #define GFP_KERNEL 2
    #define KERNEL_VERSION(a,b,c) (((a)<<16)|((b)<<8)|(c))
    #define LINUX_VERSION_CODE KERNEL_VERSION(6,8,0)
    #define PAGE_SHIFT 12
    #define ZERO_SIZE_PTR ((void *)16)
    #define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))
    #define check_mul_overflow(a,b,p) __builtin_mul_overflow(a,b,p)
    typedef struct {void *p;size_t n;bool vm;} record;
    static record allocations[4096];
    static int atomic_context,fail_alloc,fail_metadata,checks;
    static bool force_vm;
    static int in_atomic(void){return atomic_context;}
    static int irqs_disabled(void){return 0;}
    static int in_interrupt(void){return 0;}
    static int indexof(const void *p){for(int i=0;i<4096;i++)if(allocations[i].p==p)return i;return -1;}
    static void *allocate(size_t n,bool vm){
     if(fail_alloc){fail_alloc--;return NULL;} if(!n)return ZERO_SIZE_PTR;
     void *p=NULL;if(vm){if(posix_memalign(&p,4096,n))return NULL;}else p=malloc(n);
     if(!p)return NULL;for(int i=0;i<4096;i++)if(!allocations[i].p){allocations[i]=(record){p,n,vm};return p;}
     abort();
    }
    static bool is_vmalloc_addr(const void *p){int i=indexof(p);return p&&i>=0&&allocations[i].vm;}
    static void *kmalloc(size_t n,int flags){(void)flags;return allocate(n,false);}
    static void *kvmalloc(size_t n,int flags){(void)flags;return allocate(n,force_vm);}
    static void kvfree(void *p){if(!p||p==ZERO_SIZE_PTR)return;int i=indexof(p);assert(i>=0);allocations[i]=(record){0};free(p);}
    static void *krealloc(void *p,size_t n,int flags){
     (void)flags;if(!p||p==ZERO_SIZE_PTR)return allocate(n,false);if(!n){kvfree(p);return ZERO_SIZE_PTR;}
     if(fail_alloc){fail_alloc--;return NULL;}int i=indexof(p);assert(i>=0&&!allocations[i].vm);
     void *q=realloc(p,n);if(q)allocations[i]=(record){q,n,false};return q;
    }
    struct xa_entry{unsigned long key;void *value;};
    struct xarray{struct xa_entry a[4096];};
    #define DEFINE_XARRAY(name) struct xarray name={0}
    #define xa_mk_value(n) ((void *)(((uintptr_t)(n)<<1)|1))
    #define xa_is_value(n) (((uintptr_t)(n)&1)!=0)
    #define xa_to_value(n) ((uintptr_t)(n)>>1)
    #define xa_is_err(n) ((((uintptr_t)(n)&3)==2)&&((uintptr_t)(n)>=(uintptr_t)-4094))
    static void *xa_store(struct xarray *x,unsigned long k,void *v,int flags){
     (void)flags;if(fail_metadata){fail_metadata--;return (void *)(((uintptr_t)-ENOMEM<<2)|2);}
     for(int i=0;i<4096;i++)if(x->a[i].key==k){void *old=x->a[i].value;x->a[i].value=v;return old;}
     for(int i=0;i<4096;i++)if(!x->a[i].key){x->a[i]=(struct xa_entry){k,v};return NULL;}abort();
    }
    static void *xa_load(struct xarray *x,unsigned long k){for(int i=0;i<4096;i++)if(x->a[i].key==k)return x->a[i].value;return NULL;}
    static void *xa_erase(struct xarray *x,unsigned long k){for(int i=0;i<4096;i++)if(x->a[i].key==k){void *v=x->a[i].value;x->a[i]=(struct xa_entry){0};return v;}return NULL;}
    '''
    test=r'''
    static unsigned char pattern(size_t i){return (unsigned char)(i*37+19);}
    static void one(size_t n,size_t m){
     unsigned char *p=malloc_wrapper(n);assert(p);for(size_t i=0;i<n;i++)p[i]=pattern(i);
     unsigned char *q=realloc_wrapper(p,m);assert(q);for(size_t i=0;i<(n<m?n:m);i++)assert(q[i]==pattern(i));
     free_wrapper(q);checks++;
    }
    int main(void){
     size_t sizes[]={0,1,16,63,64,255,512,2048,2777,4096,32768,32769,65536,262144};
     for(int vm=0;vm<2;vm++){force_vm=vm;for(int atomic=0;atomic<2;atomic++){
      atomic_context=atomic;for(size_t i=0;i<sizeof(sizes)/sizeof(*sizes);i++)for(size_t j=0;j<sizeof(sizes)/sizeof(*sizes);j++)one(sizes[i],sizes[j]);
     }}
     atomic_context=0;force_vm=true;
     for(int vm=0;vm<2;vm++){
      size_t n=vm?65536:2048;unsigned char *p=malloc_wrapper(n);assert(p);memset(p,0x5a,n);
      fail_alloc=1;assert(!realloc_wrapper(p,n*2));for(size_t i=0;i<n;i++)assert(p[i]==0x5a);free_wrapper(p);checks++;
     }
     fail_metadata=1;assert(!malloc_wrapper(65536));checks++;
     unsigned char *p=malloc_wrapper(65536);assert(p&&is_vmalloc_addr(p));memset(p,0x3c,65536);
     atomic_context=1;assert(!realloc_wrapper(p,131072));atomic_context=0;for(size_t i=0;i<65536;i++)assert(p[i]==0x3c);free_wrapper(p);checks++;
     p=malloc_wrapper(65536);assert(p);fail_metadata=1;assert(!realloc_wrapper(p,131072));free_wrapper(p);checks++;
     p=realloc_wrapper(NULL,2048);assert(p);free_wrapper(p);checks++;
     p=calloc_wrapper(32,64);assert(p);for(int i=0;i<2048;i++)assert(p[i]==0);free_wrapper(p);checks++;
     assert(!calloc_wrapper(SIZE_MAX,2));assert(!malloc_wrapper(SIZE_MAX));checks+=2;
     p=malloc_wrapper(2048);assert(p);assert(!realloc_wrapper(p,SIZE_MAX));free_wrapper(p);checks++;
     for(int i=0;i<4096;i++){assert(!allocations[i].p);assert(!ndpi_vmalloc_sizes.a[i].key);}
     printf("PASS %d allocator cases; no remaining allocations or metadata\n",checks);
     return 0;
    }
    '''
    negative=r'''
    int main(void){unsigned char *p=malloc_wrapper(2048);assert(p);memset(p,0x5a,2048);p=realloc_wrapper(p,4096);free_wrapper(p);return 0;}
    '''
    out={'actual_wrapper_sha256':hashlib.sha256(fixed.encode()).hexdigest(),'tests':{}}
    for name,body,tail in [('original',original,negative),('fixed',fixed,test)]:
     src=T/(name+'.c');src.write_text(stub+'\n'+re.sub(r'^#include <linux/[^\n]+\n','',body,flags=re.M)+'\n'+tail)
     subprocess.run(['clang-21','-g','-O1','-fsanitize=address,undefined','-fno-omit-frame-pointer','-Wno-unused-function',str(src),'-o',str(T/name)],check=True)
     r=subprocess.run([str(T/name)],capture_output=True,text=True)
     (T/(name+'.stdout')).write_text(r.stdout);(T/(name+'.stderr')).write_text(r.stderr)
     out['tests'][name]={'rc':r.returncode,'stdout':r.stdout,'heap_buffer_overflow':'heap-buffer-overflow' in r.stderr,'diagnostic_tail':r.stderr[-1500:]}
     assert (r.returncode!=0 and 'heap-buffer-overflow' in r.stderr) if name=='original' else r.returncode==0
    if args.report:Path(args.report).write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps(out,indent=2))
    
    workspace.cleanup()

if __name__ == "__main__": main()
