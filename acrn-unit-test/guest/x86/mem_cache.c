/**
 * Test for x86 cache and memory cache control
 *
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 */

#include "libcflat.h"
#include "desc.h"
#include "processor.h"
#include "alloc.h"
#include "alloc_phys.h"
#include "vmalloc.h"
#include "alloc_page.h"
#include "asm/io.h"
#include "asm/spinlock.h"
#include "vm.h"
#include "misc.h"
#include "types.h"
#include "apic.h"
#include "isr.h"
#include "fwcfg.h"

/*#define CACHE_IN_NATIVE*/

/*#define USE_DEBUG*/
#ifdef USE_DEBUG
#define debug_print(fmt, args...)	printf("[%s:%s] line=%d "fmt"", __FILE__, __func__, __LINE__,  ##args)
#else
#define debug_print(fmt, args...)
#endif
#define debug_error(fmt, args...)	printf("[%s:%s] line=%d "fmt"", __FILE__, __func__, __LINE__,  ##args)

#define CR0_BIT_NW					29
#define CR0_BIT_CD					30
#define CR0_BIT_PG					31

#define CR3_BIT_PWT					3
#define CR3_BIT_PCD					4

#define CR4_BIT_PAE					5
#define CR4_BIT_PGE					7

#define IA32_PAT_MSR				0x00000277
#define IA32_MISC_ENABLE			0x000001A0
#define IA32_MTRR_DEF_TYPE			0x000002FF
#define IA32_MTRRCAP_MSR			0x000000FE
#define IA32_SMRR_PHYSBASE_MSR		0x000001F2
#define IA32_SMRR_PHYSMASK_MSR		0x000001F3

#define IA32_MTRR_PHYSBASE0			0x00000200
#define IA32_MTRR_PHYSMASK0			0x00000201
#define IA32_MTRR_PHYSBASE1			0x00000202
#define IA32_MTRR_PHYSMASK1			0x00000203
#define IA32_MTRR_PHYSBASE2			0x00000204
#define IA32_MTRR_PHYSMASK2			0x00000205
#define IA32_MTRR_PHYSBASE3			0x00000206
#define IA32_MTRR_PHYSMASK3			0x00000207
#define IA32_MTRR_PHYSBASE4			0x00000208
#define IA32_MTRR_PHYSMASK4			0x00000209
#define IA32_MTRR_PHYSBASE5			0x0000020A
#define IA32_MTRR_PHYSMASK5			0x0000020B
#define IA32_MTRR_PHYSBASE6			0x0000020C
#define IA32_MTRR_PHYSMASK6			0x0000020D
#define IA32_MTRR_PHYSBASE7			0x0000020E
#define IA32_MTRR_PHYSMASK7			0x0000020F
#define IA32_MTRR_PHYBASE(i)		(IA32_MTRR_PHYSBASE0+i*2)
#define IA32_MTRR_PHYMASK(i)		(IA32_MTRR_PHYSMASK0+i*2)

#define IA32_MTRR_FIX64K_00000		0x00000250
#define IA32_MTRR_FIX16K_80000		0x00000258
#define IA32_MTRR_FIX4K_C0000		0x00000268

#define PT_PWT						3
#define PT_PCD						4
#define PT_PAT						7
#define PT_PAT_LARGE_PAGE			12

#define PT_PWT_MASK					(1ull << (PT_PWT))
#define PT_PCD_MASK					(1ull << (PT_PCD))
#define PT_PAT_MASK					(1ull << (PT_PAT))

/* init pat to 0x0000000001040506*/
#define PT_MEMORY_TYPE_MASK0		0	/* wb */
#define PT_MEMORY_TYPE_MASK1		(PT_PWT_MASK)	/* wp */
#define PT_MEMORY_TYPE_MASK2		(PT_PCD_MASK)	/* wt */
#define PT_MEMORY_TYPE_MASK3		(PT_PWT_MASK|PT_PCD_MASK)	/* wc */
#define PT_MEMORY_TYPE_MASK4		(PT_PAT_MASK)		/* uc */
#define PT_MEMORY_TYPE_MASK5		(PT_PAT_MASK|PT_PWT_MASK)	/* uc */
#define PT_MEMORY_TYPE_MASK6		(PT_PAT_MASK|PT_PCD_MASK)	/* uc */
#define PT_MEMORY_TYPE_MASK7		(PT_PAT_MASK|PT_PCD_MASK|PT_PWT_MASK)	/* uc */

#define CACHE_TEST_TIME_MAX			40

#define IA32_PAT_STARTUP_VALUE	0x0007040600070406

static volatile int ud;
static volatile int isize;

/* default PAT entry value 0007040600070406 */
u64 cache_type_UC = 0x0;
u64 cache_type_WB = 0x0606060606060600;
u64 cache_type_WC = 0x0101010101010100;
u64 cache_type_WT = 0x0404040404040400;
u64 cache_type_WP = 0x0505050505050500;

u64 cache_line_size = 64;

u64 cache_4k_size = 0x200;			/* 4k/8 */
u64 cache_l1_size = 0x800;			/* 16K/8 */
u64 cache_l2_size = 0x4000;			/* 128K/8 */
u64 cache_l3_size = 0x80000;		/* 4M/8 */
u64 cache_over_l3_size = 0x200000;	/* 16M/8 */
u64 cache_malloc_size = 0x200000;	/* 16M/8 */

u64 *cache_test_array = NULL;
u64 tsc_delay[CACHE_TEST_TIME_MAX] = {0,};
u64 tsc_delay_before[CACHE_TEST_TIME_MAX] = {0,};
u64 tsc_delay_after[CACHE_TEST_TIME_MAX] = {0,};
u64 tsc_delay_delta[CACHE_TEST_TIME_MAX] = {0,};
u64 tsc_delay_delta_total = 0;
u64 tsc_delay_delta_stdev = 0;

#define ERROR_RANG		5

enum cache_size_type {
	CACHE_L1_READ_UC = 0,
	CACHE_L1_READ_WB,
	CACHE_L1_READ_WT,
	CACHE_L1_READ_WC,
	CACHE_L1_READ_WP,

	CACHE_L2_READ_UC = 5,
	CACHE_L2_READ_WB,
	CACHE_L2_READ_WT,
	CACHE_L2_READ_WC,
	CACHE_L2_READ_WP,

	CACHE_L3_READ_UC = 10,
	CACHE_L3_READ_WB,
	CACHE_L3_READ_WT,
	CACHE_L3_READ_WC,
	CACHE_L3_READ_WP,

	CACHE_OVER_L3_READ_UC = 15,
	CACHE_OVER_L3_READ_WB,
	CACHE_OVER_L3_READ_WT,
	CACHE_OVER_L3_READ_WC,
	CACHE_OVER_L3_READ_WP,

	CACHE_L1_WRITE_UC = 20,
	CACHE_L1_WRITE_WB,
	CACHE_L1_WRITE_WT,
	CACHE_L1_WRITE_WC,
	CACHE_L1_WRITE_WP,

	CACHE_L2_WRITE_UC = 25,
	CACHE_L2_WRITE_WB,
	CACHE_L2_WRITE_WT,
	CACHE_L2_WRITE_WC,
	CACHE_L2_WRITE_WP,

	CACHE_L3_WRITE_UC = 30,
	CACHE_L3_WRITE_WB,
	CACHE_L3_WRITE_WT,
	CACHE_L3_WRITE_WC,
	CACHE_L3_WRITE_WP,

	CACHE_OVER_L3_WRITE_UC = 35,
	CACHE_OVER_L3_WRITE_WB,
	CACHE_OVER_L3_WRITE_WT,
	CACHE_OVER_L3_WRITE_WC,
	CACHE_OVER_L3_WRITE_WP,

	CACHE_DEVICE_4K_READ = 40,
	CACHE_4K_READ,
	CACHE_DEVICE_4K_WRITE,
	CACHE_4K_WRITE,

	CACHE_CLFLUSH_DIS_READ = 44,
	CACHE_CLFLUSH_READ,
	CACHE_CLFLUSHOPT_DIS_READ,
	CACHE_CLFLUSHOPT_READ,
	CACHE_WBINVD_DIS_READ,
	CACHE_WBINVD_READ,

	CACHE_SIZE_TYPE_MAX
};

struct cache_data {
	u64 ave;
	u64 std;
};

struct cache_data cache_bench[CACHE_SIZE_TYPE_MAX] = {
	{433796UL, 23647UL},		/*CACHE_L1_READ_UC, 0*/
	{2559UL, 11UL},				/*CACHE_L1_READ_WB,*/
	{2557UL, 11UL},				/*CACHE_L1_READ_WT,*/
	{435176UL, 23877UL},		/*CACHE_L1_READ_WC,*/
	{2557UL, 11UL},				/*CACHE_L1_READ_WP,*/

	{3479968UL, 29924UL},		/*CACHE_L2_READ_UC, 5*/
	{19447UL, 39UL},			/*CACHE_L2_READ_WB,*/
	{19443UL, 35UL},			/*CACHE_L2_READ_WT,*/
	{3480217UL, 29759UL},		/*CACHE_L2_READ_WC,*/
	{19438UL, 34UL},			/*CACHE_L2_READ_WP,*/

	{111318576UL, 4757UL},		/*CACHE_L3_READ_UC, 10*/
	{675272UL, 651UL},			/*CACHE_L3_READ_WB,*/
	{675276UL, 807UL},			/*CACHE_L3_READ_WT,*/
	{111319218UL, 35080UL},		/*CACHE_L3_READ_WC,*/
	{675368UL, 690UL},			/*CACHE_L3_READ_WP,*/

	{445280643UL, 37021UL},		/*CACHE_OVER_L3_READ_UC, 15*/
	{3656013UL, 21757UL},		/*CACHE_OVER_L3_READ_WB,*/
	{3642278UL, 26704UL},		/*CACHE_OVER_L3_READ_WT,*/
	{445276301UL, 42465UL},		/*CACHE_OVER_L3_READ_WC,*/
	{3642478UL, 26895UL},		/*CACHE_OVER_L3_READ_WP,*/

	{337330UL, 50UL},			/*CACHE_L1_WRITE_UC, 20*/
	{3169UL, 16UL},				/*CACHE_L1_WRITE_WB,*/
	{337365UL, 83UL},			/*CACHE_L1_WRITE_WT,*/
	{3385UL, 118UL},			/*CACHE_L1_WRITE_WC,*/
	{337377UL, 81UL},			/*CACHE_L1_WRITE_WP,*/

	{2698424UL, 174UL},			/*CACHE_L2_WRITE_UC, 25*/
	{25060UL, 28UL},			/*CACHE_L2_WRITE_WB,*/
	{2698413UL, 168UL},			/*CACHE_L2_WRITE_WT,*/
	{28373UL, 5996UL},			/*CACHE_L2_WRITE_WC,*/
	{2698451UL, 162UL},			/*CACHE_L2_WRITE_WP,*/

	{86342539UL, 645UL},		/*CACHE_L3_WRITE_UC, 30*/
	{804229UL, 211UL},			/*CACHE_L3_WRITE_WB,*/
	{86342445UL, 693UL},		/*CACHE_L3_WRITE_WT,*/
	{932708UL, 12316UL},		/*CACHE_L3_WRITE_WC,*/
	{86342359UL, 589UL},		/*CACHE_L3_WRITE_WP,*/

	{345369076UL, 1194UL},		/*CACHE_OVER_L3_WRITE_UC, 35*/
	/* Abnormal large test on CI*/
	{5804371UL, 118930UL},		/*CACHE_OVER_L3_WRITE_WB,*/
	{345369505UL, 1590UL},		/*CACHE_OVER_L3_WRITE_WT,*/
	{3733753UL, 26365UL},		/*CACHE_OVER_L3_WRITE_WC,*/
	{345369240UL, 1273UL},		/*CACHE_OVER_L3_WRITE_WP,*/
#if 0
	{2071703UL, 1091UL},/*CACHE_DEVICE_4K_READ, 40*/
	{104626UL, 13887UL},/*CACHE_4K_READ,*/
	{1500492UL, 605UL},/*CACHE_DEVICE_4K_WRITE,*/
	{84378UL, 55UL},/*CACHE_4K_WRITE,*/

	{14750957UL, 127314UL},/*CACHE_CLFLUSH_DIS_READ, 44*/
	{664331UL, 36943UL},/*CACHE_CLFLUSH_READ,*/
	{14743159UL, 147640UL},/*CACHE_CLFLUSHOPT_DIS_READ,*/
	{657227UL, 32265UL},/*CACHE_CLFLUSHOPT_READ,*/
	{15223198UL, 125174UL},/*CACHE_WBINVD_DIS_READ,*/
	{226598UL, 27398UL},/*CACHE_WBINVD_READ,*/
#endif
};

struct case_fun_index {
	int rqmid;
	void (*func)(void);
};
typedef void (*trigger_func)(void *data);

unsigned long long asm_read_tsc(void)
{
	long long r;
#ifdef __x86_64__
	unsigned a, d;

	asm volatile("mfence" ::: "memory");
	asm volatile ("rdtsc" : "=a"(a), "=d"(d));
	r = a | ((long long)d << 32);
#else
	asm volatile ("rdtsc" : "=A"(r));
#endif
	asm volatile("mfence" ::: "memory");
	return r;
}

void asm_mfence()
{
	asm volatile("mfence" ::: "memory");
}

static inline void asm_read_access_memory(u64 *p)
{
#ifdef __x86_64__
	asm volatile("movq (%0), %%rax\n" : : "c"(p) : "rax");
#elif __i386__
	asm volatile("mov (%0), %%eax\n" : : "c"(p) : "eax");
#endif
}

void asm_wbinvd()
{
	asm volatile ("wbinvd\n" : : : "memory");
}

void asm_mfence_wbinvd()
{
	asm_mfence();
	asm_wbinvd();
	asm_mfence();
}

void asm_invd()
{
	asm volatile ("invd\n" : : : "memory");
}

void write_cr0_bybit(u32 bit, u32 bitvalue)
{
	u32 cr0 = read_cr0();
	if (bitvalue) {
		write_cr0(cr0 | (1 << bit));
	} else {
		write_cr0(cr0 & ~(1 << bit));
	}
}

u64 PT_MEMORY_TYPE   = PT_MEMORY_TYPE_MASK0;

/*Modify the PTE/PCD/PWT bit in paging table entry*/
void set_memory_type_pt(void *address, u64 type, u64 size)
{
	unsigned long *ptep;
	u64 *next_addr;
	int i;
	int j = 0;
	int pat = PT_PAT;

	PT_MEMORY_TYPE = type;

	for (i = 0; i < size; i += PAGE_SIZE) {
		j++;
		next_addr = (u64 *)((u8 *)address + i);

		ptep = get_pte_level(current_page_table(), next_addr, 1);
		if (ptep == NULL) {
			pat = PT_PAT_LARGE_PAGE;
		}
		switch (type) {
		case PT_MEMORY_TYPE_MASK0:
			set_page_control_bit(next_addr, PAGE_PTE, PT_PWT, 0, 0);
			set_page_control_bit(next_addr, PAGE_PTE, PT_PCD, 0, 0);
			set_page_control_bit(next_addr, PAGE_PTE, pat, 0, 0);
			break;
		case PT_MEMORY_TYPE_MASK1:
			set_page_control_bit(next_addr, PAGE_PTE, PT_PWT, 1, 0);
			set_page_control_bit(next_addr, PAGE_PTE, PT_PCD, 0, 0);
			set_page_control_bit(next_addr, PAGE_PTE, pat, 0, 0);
			break;
		case PT_MEMORY_TYPE_MASK2:
			set_page_control_bit(next_addr, PAGE_PTE, PT_PWT, 0, 0);
			set_page_control_bit(next_addr, PAGE_PTE, PT_PCD, 1, 0);
			set_page_control_bit(next_addr, PAGE_PTE, pat, 0, 0);
			break;
		case PT_MEMORY_TYPE_MASK3:
			set_page_control_bit(next_addr, PAGE_PTE, PT_PWT, 1, 0);
			set_page_control_bit(next_addr, PAGE_PTE, PT_PCD, 1, 0);
			set_page_control_bit(next_addr, PAGE_PTE, pat, 0, 0);
			break;
		case PT_MEMORY_TYPE_MASK4:
			set_page_control_bit(next_addr, PAGE_PTE, PT_PWT, 0, 0);
			set_page_control_bit(next_addr, PAGE_PTE, PT_PCD, 0, 0);
			set_page_control_bit(next_addr, PAGE_PTE, pat, 1, 0);
			break;
		case PT_MEMORY_TYPE_MASK5:
			set_page_control_bit(next_addr, PAGE_PTE, PT_PWT, 1, 0);
			set_page_control_bit(next_addr, PAGE_PTE, PT_PCD, 0, 0);
			set_page_control_bit(next_addr, PAGE_PTE, pat, 1, 0);
			break;
		case PT_MEMORY_TYPE_MASK6:
			set_page_control_bit(next_addr, PAGE_PTE, PT_PWT, 0, 0);
			set_page_control_bit(next_addr, PAGE_PTE, PT_PCD, 1, 0);
			set_page_control_bit(next_addr, PAGE_PTE, pat, 1, 0);
			break;
		case PT_MEMORY_TYPE_MASK7:
			set_page_control_bit(next_addr, PAGE_PTE, PT_PWT, 1, 0);
			set_page_control_bit(next_addr, PAGE_PTE, PT_PCD, 1, 0);
			set_page_control_bit(next_addr, PAGE_PTE, pat, 1, 0);
			break;
		default:
			debug_error("error type\n");
			break;
		}
	}
}

void flush_tlb()
{
	u32 cr3;
	cr3 = read_cr3();
	write_cr3(cr3);
}

void mem_cache_reflush_cache()
{
	u32 cr4;

	/*Disable interrupts;*/
	irq_disable();

	/*Save current value of CR4;*/
	cr4 = read_cr4();

	/*Disable and flush caches;*/
	write_cr0_bybit(CR0_BIT_CD, 1);
	write_cr0_bybit(CR0_BIT_NW, 0);
	asm_wbinvd();

	/*Flush TLBs;*/
	flush_tlb();

	/*Disable MTRRs;*/
	//disable_MTRR();

	/*Flush caches and TLBs;*/
	asm_wbinvd();
	flush_tlb();

	/*Enable MTRRs;*/
	//enable_MTRR();

	/*enable caches;*/
	write_cr0_bybit(CR0_BIT_CD, 0);
	write_cr0_bybit(CR0_BIT_NW, 0);

	/*Restore value of CR4;*/
	write_cr4(cr4);

	/*Enable interrupts;*/
	irq_enable();
}

void set_mem_cache_type(u64 cache_type)
{
#if 0
	u64 ia32_pat_test;

	ia32_pat_test = rdmsr(IA32_PAT_MSR);
	debug_print("ia32_pat_test 0x%lx \n", ia32_pat_test);

	//wrmsr(IA32_PAT_MSR,(ia32_pat_test&(~0xFF0000))|(cache_type<<16));
	wrmsr(IA32_PAT_MSR, cache_type);

	ia32_pat_test = rdmsr(IA32_PAT_MSR);
	debug_print("ia32_pat_test 0x%lx \n", ia32_pat_test);

	if (ia32_pat_test != cache_type) {
		debug_print("set pat type error set=0x%lx, get=0x%lx\n", cache_type, ia32_pat_test);
	} else {
		debug_print("set pat type sucess type=0x%lx get=0x%lx\n", cache_type, ia32_pat_test);
	}

	asm_mfence_wbinvd()
	mem_cache_reflush_cache();
#else

	set_memory_type_pt(cache_test_array, cache_type, cache_over_l3_size*8);
	//debug_print("cache_test_array=%p\n", cache_test_array);

	/* Flush caches and TLBs;*/
	asm_wbinvd();
	flush_tlb();
#endif
}

void set_mem_cache_type_all(u64 cache_type)
{
	u64 ia32_pat_test;

	wrmsr(IA32_PAT_MSR, cache_type);

	ia32_pat_test = rdmsr(IA32_PAT_MSR);

#ifdef __x86_64__
	debug_print("ia32_pat_test 0x%lx \n", ia32_pat_test);
	if (ia32_pat_test != cache_type) {
		debug_print("set pat type all error set=0x%lx, get=0x%lx\n", cache_type, ia32_pat_test);
	} else {
		debug_print("set pat type all sucess type=0x%lx\n", cache_type);
	}
#elif __i386__
	debug_print("ia32_pat_test 0x%llx \n", ia32_pat_test);
	if (ia32_pat_test != cache_type) {
		debug_print("set pat type all error set=0x%llx, get=0x%llx\n", cache_type, ia32_pat_test);
	} else {
		debug_print("set pat type all sucess type=0x%llx\n", cache_type);
	}
#endif
	asm_mfence_wbinvd();

	mem_cache_reflush_cache();
}


__attribute__((aligned(64))) u64 read_mem_cache_test(u64 size)
{
	u64 index;
	u64 t[2] = {0};

	cli();
	t[0] = asm_read_tsc();
	for (index = 0; index < size; index++) {
		asm_read_access_memory(&cache_test_array[index]);
	}
	t[1] = asm_read_tsc();
	sti();
#ifdef __x86_64__
	//printf("%ld\n", (t[1] - t[0]));
#elif __i386__
	//printf("%lld\n", (t[1] - t[0]));
#endif
	asm_mfence();
	return t[1] - t[0];
}

void read_mem_cache_test_time_invd(u64 size, int time)
{
	int t_time = time;
	/*debug_print("read cache cache_test_size 0x%lx %ld\n",size, size*8);*/
	while (t_time--) {
		read_mem_cache_test(size);
	}

	asm_mfence_wbinvd();
}

u64 cache_order_read(enum cache_size_type type, u64 size)
{
	int i;

	tsc_delay_delta_total = 0;
	/*Remove the first test data*/
	read_mem_cache_test(size);
	for (i = 0; i < CACHE_TEST_TIME_MAX; i++) {
		tsc_delay[i] = read_mem_cache_test(size);
		tsc_delay_delta_total += tsc_delay[i];
	}
	tsc_delay_delta_total /= CACHE_TEST_TIME_MAX;

	return tsc_delay_delta_total;
}

bool cache_check_memory_type(u64 average, u64 native_aver, u64 native_std, u64 size)
{
	bool ret = true;

	if ((average < ((native_aver*(100-ERROR_RANG))/100)) \
		|| (average > ((native_aver*(100+ERROR_RANG))/100))) {
		ret = false;
	}

#ifdef __x86_64__
	if (ret != true) {
		printf("read delta =%ld size=0x%lx [%ld, %ld]\n", tsc_delay_delta_total, size,
			(native_aver*(100-ERROR_RANG))/100, (native_aver*(100+ERROR_RANG))/100);
	}
#elif __i386__
	if (ret != true) {
		printf("read delta =%lld size=0x%llx [%lld, %lld]\n", tsc_delay_delta_total, size,
			(native_aver*(100-ERROR_RANG))/100, (native_aver*(100+ERROR_RANG))/100);
	}
#endif
	return ret;
}

bool cache_order_read_test(enum cache_size_type type, u64 size)
{
	bool ret = true;
	u64 ave;
	u64 std;

	ave = cache_bench[type].ave;
	std = cache_bench[type].std;

	asm_mfence_wbinvd();
	tsc_delay_delta_total = cache_order_read(type, size);

	ret = cache_check_memory_type(tsc_delay_delta_total, ave, std, size);

	asm_mfence_wbinvd();
	return ret;
}

int get_bit_range(u32 r, int start, int end)
{
	int mask = 0;
	int i = end-start+1;
	u32 t_r = r>>start;
	while (i--) {
		mask = mask<<1;
		mask += 1;
	}
	return t_r&mask;
}

void asm_clflush(long unsigned int addr)
{
	asm volatile("clflush (%0)" : : "b" (addr));
}

void cache_fun_exec(struct case_fun_index *case_fun, int size, long rqmid)
{
	int i;

	debug_print("***************start test case number = %d rqmid=%ld***************\n", size, rqmid);
	for (i = 0; i < size; i++) {
		if (rqmid == case_fun[i].rqmid) {
			case_fun[i].func();
			break;
		}

		if (rqmid == 0) {
			case_fun[i].func();
		}
	}
}

#ifdef __x86_64__
/*test case which should run under 64bit  */
#include "64/mem_cache_fn.c"
#elif __i386__
/*test case which should run  under 32bit  */
#include "32/mem_cache_fn.c"
#endif

#ifdef __x86_64__
extern void send_sipi();
int ap_start_count = 0;
volatile u64 init_pat = 0;
volatile u64 set_pat = 0;
void save_unchanged_reg()
{
	if (get_lapic_id() != (fwcfg_get_nb_cpus() - 1)) {
		return;
	}

	if (ap_start_count == 0) {
		/* save init value (defalut is 0007040600070406)*/
		init_pat = rdmsr(IA32_PAT_MSR);

		/* set new value to pat */
		wrmsr(IA32_PAT_MSR, 0x6);
		ap_start_count++;
	}

	set_pat = rdmsr(IA32_PAT_MSR);

	if (ap_start_count == 2) {
		/* resume environment */
		wrmsr(IA32_PAT_MSR, init_pat);
	}
}

void print_case_list_init_startup()
{
	printf("cache init statup feature case list:\n\r");
#ifdef IN_NON_SAFETY_VM
	printf("\t Case ID:%d case name:%s\n\r", 23239u, "IA32_PAT INIT value_unchange_001");
	printf("\t Case ID:%d case name:%s\n\r", 23241u, "CR0.CD INIT value_001");
#endif
	printf("\t Case ID:%d case name:%s\n\r", 23242u, "CR0.NW start-up value_001");
}

/**
 * @brief case name:IA32_PAT INIT value_unchange_001
 *
 * Summary: After AP receives??first INIT, set the PAT value??to 6H;
 * dump IA32_PAT register value, AP INIT again,??then dump IA32_PAT
 * register value again, two dumps value should be equal.
 */
void __unused cache_rqmid_23239_ia32_pat_init_unchange_01(void)
{
	volatile u64 ia32_pat1;
	volatile u64 ia32_pat2;

	/*get set_pat value */
	ia32_pat1 = set_pat;

	/*send sipi to ap*/
	send_sipi();

	/*get pat value again after ap reset*/
	ia32_pat2 = set_pat;

	/*compare init value with unchanged */
	report("%s ", ia32_pat1 == ia32_pat2, __FUNCTION__);
}

/*
 * @brief case name: IA32_PAT INIT value_unchange_002
 *
 * Summary: At BP executing 1st instruction and AP receives the first init,
 * save the PAT value, and the two PAT values should be equal.
 */
void __unused cache_rqmid_37108_ia32_pat_init_unchange_02(void)
{
	volatile u64 ia32_pat1;
	volatile u64 ia32_pat2;
	volatile u32 unchanged_ap_pat1 = 0;
	volatile u32 unchanged_ap_pat2 = 0;
	volatile u32 *ptr;

	/* startup pat value */
	ia32_pat1 = IA32_PAT_STARTUP_VALUE;

	/* init pat value */
	ptr = (volatile u32 *)(0x8000 + 0x8);
	unchanged_ap_pat1 = *ptr;
	unchanged_ap_pat2 = *(ptr + 1);
	ia32_pat2 = unchanged_ap_pat1 | ((u64)unchanged_ap_pat2 << 32);

	report("%s ", ia32_pat1 == ia32_pat2, __FUNCTION__);
}

/**
 * @brief case name:CR0.CD INIT value_001
 *
 * Summary: Get CR0.CD[bit 30] at AP init, the bit shall be 1 and same with SDM definition.
 */
void __unused cache_rqmid_23241_cr0_cd_init(void)
{
	volatile u32 ap_cr0 = 0;
	volatile u32 *ptr;

	ptr = (volatile u32 *)0x8000;
	ap_cr0 = *ptr;

	report("%s", (ap_cr0 & (1<<30)), __FUNCTION__);
}

/**
 * @brief case name:CR0.NW start-up value_001
 *
 * Summary: Get CR0.NW[bit 29] at BP start-up, the bit shall be 1 and same with SDM definition.
 */
void cache_rqmid_23242_cr0_nw_startup(void)
{
	volatile u32 *ptr;
	volatile u32 bp_cr0;

	ptr = (volatile u32 *)0x6000;
	bp_cr0 = *ptr;

	report("%s", (bp_cr0 & (1<<29)), __FUNCTION__);
}

/* 10 init startup case */
void cache_test_init_startup(long rqmid)
{
	print_case_list_init_startup();

	struct case_fun_index case_fun[] = {
	#ifdef IN_NON_SAFETY_VM
		/*Must be in front of 23239 */
		{33333, cache_rqmid_37108_ia32_pat_init_unchange_02},
		{23239, cache_rqmid_23239_ia32_pat_init_unchange_01},
		{23241, cache_rqmid_23241_cr0_cd_init},
	#endif
		{23242, cache_rqmid_23242_cr0_nw_startup},
	};

	cache_fun_exec(case_fun, sizeof(case_fun)/sizeof(case_fun[0]), rqmid);
}
#endif

int main(int ac, char **av)
{
	long rqmid = 0;

	if (ac >= 2) {
		rqmid = atol(av[1]);
	}

#ifdef __x86_64__
	cache_test_init_startup(rqmid);
#endif

#ifdef __x86_64__
	setup_idt();

	/*default PAT entry value 0007040600070406*/
	set_mem_cache_type_all(0x0000000001040506);
	setup_vm();

#elif defined(__i386__)
	setup_idt();
#endif

	cache_test_array = (u64 *)malloc(cache_malloc_size*8);
	if (cache_test_array == NULL) {
		debug_error("malloc error\n");
		return -1;
	}

	debug_print("cache_test_array=%p\n", cache_test_array);
	memset(cache_test_array, 0xFF, cache_malloc_size*8);
	debug_print("mem cache control memory malloc success addr=%lx\n", (u64)cache_test_array);
	/*test_cache_type();*/

	debug_print("rqmid = %ld\n", rqmid);

	//delay(10);
#ifdef __x86_64__
#ifndef CACHE_IN_NATIVE
	cache_test_64(rqmid);
#else
	/*cache_test_native(rqmid);*/
#endif
#elif defined(__i386__)
	/*cache_test_32(rqmid);*/
#endif

	free(cache_test_array);
	cache_test_array = NULL;
	return report_summary();
}

