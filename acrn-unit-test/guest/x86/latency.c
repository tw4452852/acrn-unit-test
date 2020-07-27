#include "libcflat.h"
#include "vm.h"
#include "vmalloc.h"
#include "apic.h"
#include "apic-defs.h"
#include "smp.h"
#include "desc.h"
#include "alloc.h"

#define IPI_VECTOR 0x22
#define LLC_MISS 0x43412e
#define IR 0x4300c0
#define URC 0x43003c
#define L2_MISS 0x433f24
#define L2_MISS_PF 0x433824
#define L2_MISS_DEMAND 0x432724
#define L2_MISS_FI 0x432424
#define L2_MISS_RFO 0x432224


struct recipe {
	const char *keyword;
	bool (*parse_args)(int, char**);
	bool (*is_expected)(uint64_t);
	void (*work)(void);
};

static bool accept_all(uint64_t vmexit_no) { return true; }
static void nop(void) {}

static bool (*is_expected_fn)(uint64_t vmexit_no) = accept_all;
static void (*work_fn)(void) = nop;

static void
ipi_work()
{
	apic_icr_write(APIC_INT_ASSERT | APIC_DEST_PHYSICAL | APIC_DM_FIXED | IPI_VECTOR, 1);
}
static bool
accept_0x20(uint64_t reason)
{
	return reason == 0x20;
}

struct recipe recipes[] = {
	{ .keyword = "ipi", .work = ipi_work, .is_expected = accept_0x20, },
};

struct vmswitch {
	uint64_t stop;
	uint64_t reason;
	uint64_t ts[3];
};

static u64 count;
static float freq;
static struct vmswitch vms;
static u64 pmc0_before, pmc0_after, pmc1_before, pmc1_after, pmc2_before, pmc2_after, pmc3_before, pmc3_after, pmc4_before, pmc4_after, pmc5_before, pmc5_after;

asm (
	"my_ipi_entry: \n"
#ifndef __x86_64__
	"   iret"
#else
	"   iretq"
#endif
	);

static int64_t acrn_vmswitch_toggle(uint64_t gva) {
	/* x86-64 System V ABI register usage */
	register signed long result __asm__ ("rax");
	register unsigned long r8 __asm__ ("r8") = 0x80000064;

	__asm__ __volatile__ (".byte 0x0F,0x01,0xC1\n"
			: "=r"(result)
			: "D" (gva), "r"(r8));

	return result;
}

#define add_one_interval(name)                                                               \
static u64 min_##name = -1, max_##name, sum_##name;                          				 \
static void _show_##name() { 																\
		printf(xstr(name)" %lu: min: %luns, max: %luns, avg: %luns, pmc0: %lu, pmc1: %lu, pmc2: %lu, pmc3: %lu, pmc4: %lu, pmc5: %lu\n", 			\
		count, min_##name, max_##name, (unsigned long)(sum_##name/count), pmc0_after-pmc0_before, pmc1_after-pmc1_before, pmc2_after-pmc2_before, pmc3_after-pmc3_before, pmc4_after-pmc4_before, pmc5_after-pmc5_before); 								\
}                                                                                            \
static void _record_##name(u64 interval) {                                                   \
	sum_##name += interval;                                                                  \
                                                                                             \
	if (interval < min_##name) {                                                             \
		min_##name = interval;                                                               \
	}                                                                                        \
                                                                                             \
	if (interval > max_##name) {                                                             \
		max_##name = interval;                                                               \
		printf(xstr(name)" max changed\n"); \
		_show_##name();						 \
	}                                                                                        \
} 

add_one_interval(vmexit);
add_one_interval(vmexit_handler);
add_one_interval(vmenter_pre);
add_one_interval(vmresume);
add_one_interval(total);

static void
_show() {
	printf("--------------------------------------\n");
	if (work_fn != nop) {
		_show_vmexit();
		_show_vmexit_handler();
		_show_vmenter_pre();
		_show_vmresume();
	}
	_show_total();
	printf("--------------------------------------\n");
}

static void
_one_loop()
{
	u32 aux;
	struct vmswitch vms_snap;	

    asm volatile("cli");
	pmc0_before = rdmsr(MSR_P6_PERFCTR0);
	pmc1_before = rdmsr(MSR_P6_PERFCTR1);
	pmc2_before = rdmsr(MSR_P6_PERFCTR0+2);
	pmc3_before = rdmsr(MSR_P6_PERFCTR0+3);
	pmc4_before = rdmsr(MSR_P6_PERFCTR0+4);
	pmc5_before = rdmsr(MSR_P6_PERFCTR0+5);
	

	mb();
	u64 start = rdtscp(&aux);
	work_fn();
	u64 end = rdtscp(&aux);
	mb();
		
	pmc0_after = rdmsr(MSR_P6_PERFCTR0);
	pmc1_after = rdmsr(MSR_P6_PERFCTR1);
	pmc2_after = rdmsr(MSR_P6_PERFCTR0+2);
	pmc3_after = rdmsr(MSR_P6_PERFCTR0+3);
	pmc4_after = rdmsr(MSR_P6_PERFCTR0+4);
	pmc5_after = rdmsr(MSR_P6_PERFCTR0+5);
    asm volatile("sti");
	vms_snap = vms;

	if (!is_expected_fn(vms.reason)) {
		printf("not expected vmexit reason[%#lx], skip\n", vms.reason);
		return;
	}

	count++;
	if (work_fn != nop) {
		_record_vmexit((unsigned long)((vms_snap.ts[0]-start)/freq));
		_record_vmexit_handler((unsigned long)((vms_snap.ts[1]-vms_snap.ts[0])/freq));
		_record_vmenter_pre((unsigned long)((vms_snap.ts[2]-vms_snap.ts[1])/freq));
		_record_vmresume((unsigned long)((end-vms_snap.ts[2])/freq));
	}
	_record_total((unsigned long)((end-start)/freq));
}

static void
shutdown()
{
	outw(0x2000|(5 << 10), 0x404);
}

static void
parse_args(int ac, char **av)
{
	int i;

	printf("ac: %d\n", ac);
	for (i = 0; i < ac; i++) {
		printf("%d: {%s}\n", i, av[i]);
	}

	if (ac == 0) {
		printf("no arguments found, use default(nop)\n");
		return;
	}

	for(i = 0; i < ARRAY_SIZE(recipes); i++) {
		if (strcmp(av[0], recipes[i].keyword) == 0) {
			printf("use %s\n", av[0]);
			if (recipes[i].parse_args) {
				recipes[i].parse_args(ac, av);
			}
			if (recipes[i].is_expected) {
				is_expected_fn = recipes[i].is_expected;
			}
			if (recipes[i].work) {
				work_fn = recipes[i].work;
			}
			return;
		}
	}

	printf("no recipe found, use default(nop)\n");
}

static void _init_pmc()
{
	wrmsr(MSR_P6_EVNTSEL0, LLC_MISS);
	wrmsr(MSR_P6_EVNTSEL0+1, L2_MISS);
	wrmsr(MSR_P6_EVNTSEL0+2, L2_MISS_DEMAND);
	wrmsr(MSR_P6_EVNTSEL0+3, L2_MISS_FI);
	wrmsr(MSR_P6_EVNTSEL0+4, L2_MISS_PF);
	wrmsr(MSR_P6_EVNTSEL0+5, L2_MISS_RFO);
}

int main(int ac, char **av)
{
	uint8_t c;
	void my_ipi_entry(void);

	setup_vm();
	parse_args(ac, av);

	struct cpuid r = cpuid(0x16);
	printf("tw; vmexit latency test\ncore_base_freq: %dMHz, core_max_freq: %dMHz, bus_freq: %dMHz\n",
		r.a, r.b, r.c);
	freq = r.a / 1000;

	set_idt_entry(IPI_VECTOR, my_ipi_entry, 0);

	_init_pmc();

	acrn_vmswitch_toggle((uint64_t)(&vms));
	while (!vms.stop) {
		_one_loop();	
	}
	
	acrn_vmswitch_toggle(0);
	printf("tw; done\n");

	while (1)
	{
		c = getc();
		if (c != 0xff) {
			if (c == 0x3) {
				break;
			}
			_show();
		}
	}	

	shutdown();
	return 0;
}
