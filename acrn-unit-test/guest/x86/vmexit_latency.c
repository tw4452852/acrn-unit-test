#include "libcflat.h"
#include "vm.h"
#include "vmalloc.h"
#include "apic.h"
#include "apic-defs.h"
#include "smp.h"
#include "desc.h"
#include "alloc.h"

static int loop_count = 1000;
static int skip_count = 10;
static int freq;

struct ctx {
	u64 begin_tsc;
	u64 end_tsc;
	bool end_in_exception;
};

struct case_result {
	bool valid;
	const char *name;
	u64 min;
	u64 max;
	u64 dev;
	u64 avg;
};

typedef int (*test_t)(struct ctx*);

struct test_case {
	const char *name;
	test_t fn;
	bool end_in_exception;
};

// helpers

static u64 exception_tsc(void)
{
	return *(volatile u64*)EXCEPTION_TSC_ADDR;
}

struct ex_record {
	unsigned long rip;
	unsigned long handler;
};
extern struct ex_record exception_table_start, exception_table_end;
static void record_exception_tsc(struct ex_regs *regs) {
	unsigned ex_val;
	struct ex_record *ex;
	u32 aux;
	volatile u64 *exception_tsc = (volatile u64 *)EXCEPTION_TSC_ADDR;

	ex_val = regs->vector | (regs->error_code << 16) |
		(((regs->rflags >> 16) & 1) << 8);
	asm("mov %0, %%gs:"xstr(EXCEPTION_ADDR)"" : : "r"(ex_val));
	*exception_tsc = rdtscp(&aux);

	for (ex = &exception_table_start; ex != &exception_table_end; ++ex) {
		if (ex->rip == regs->rip) {
			regs->rip = ex->handler;
			return;
		}
	}
	unhandled_exception(regs, false);
}

static int mark_begin(struct ctx *ctx)
{
	u32 aux;

	mb();
	ctx->begin_tsc = rdtscp(&aux);

	return 0;
}

static int mark_end(struct ctx *ctx)
{
	u32 aux;

	if (ctx->end_in_exception) {
		ctx->end_tsc = exception_tsc();
	} else {
		ctx->end_tsc = rdtscp(&aux);
	}
	mb();

	return 0;
}

static unsigned long get_latency_in_ns(struct ctx *ctx)
{
	if (!ctx->begin_tsc || !ctx->end_tsc || ctx->end_tsc <= ctx->begin_tsc) {
		printf("invalid tsc: begin[%lu], end[%lu]\n", ctx->begin_tsc, ctx->end_tsc);
		return 0;
	}
	//printf("%lx, %lx\n", ctx->begin_tsc, ctx->end_tsc);

	return (unsigned long)((ctx->end_tsc - ctx->begin_tsc)/freq);
}

static u64 delta(u64 a, u64 b)
{
	if (a > b) {
		return a - b;
	}
	return b - a;
}

static int my_atoi(char *str)
{
	int res = 0;

	for (int i = 0; str[i] != 0; i++) {
		res = res * 10 + str[i] - '0';
	}
	return res;
}


// test cases

static int sample_case_sst(struct ctx *ctx) {

	mark_begin(ctx);
	asm volatile(
		"pushf\n\t"
		"pushf\n\t"
		"pop %rax\n\t"
		"or $(1<<8), %rax\n\t"
		"push %rax\n\t"
		"popf\n\t"
		"popf\n\t"
		".pushsection .data.ex \n\t"
		".quad 1111f, 1111f\n\t"
		".popsection \n\t"
		"1111:"
		);
	mark_end(ctx);
	return 0;
}

static int sample_case_cpuid_1(struct ctx *ctx) {
	u64 misc = rdmsr(MSR_IA32_MISC_ENABLE);

	wrmsr(MSR_IA32_MISC_ENABLE, misc | (1 << 22));
	mark_begin(ctx);
	cpuid(0x1);
	mark_end(ctx);

	wrmsr(MSR_IA32_MISC_ENABLE, misc);
	return 0;
}

static int sample_case_cpuid_d(struct ctx *ctx) {
	u64 misc = rdmsr(MSR_IA32_MISC_ENABLE);

	wrmsr(MSR_IA32_MISC_ENABLE, misc | (1 << 22));
	mark_begin(ctx);
	cpuid(0xd);
	mark_end(ctx);

	wrmsr(MSR_IA32_MISC_ENABLE, misc);
	return 0;
}

static int sample_case_invd(struct ctx *ctx) {
	mark_begin(ctx);
	asm volatile(ASM_TRY("1f")"invd\n1:"::);
	mark_end(ctx);
	return 0;
}


static int sample_case_read_dr4(struct ctx *ctx) {
	u64 tmp;
	mark_begin(ctx);
	asm volatile("mov %%dr4, %0\n\t" :"=r"(tmp));
	mark_end(ctx);
	return 0;
}

static int sample_case_read_rtc(struct ctx *ctx) {
	outb(0, 0x70);
	mark_begin(ctx);
	inb(0x71);
	mark_end(ctx);
	return 0;
}

static int sample_case_rdmsr(struct ctx *ctx) {
	mark_begin(ctx);
	rdmsr(0x8b);
	mark_end(ctx);
	return 0;
}

static int sample_case_ept(struct ctx *ctx) {
	u64 tmp = 0;
	void *p = (void *)0x80000000;
	mark_begin(ctx);
	asm volatile(ASM_TRY("1f")"mov (%1), %0\n1:" ::"r"(tmp), "r"(p));
	mark_end(ctx);
	return 0;
}

static int sample_case_wbinvd(struct ctx *ctx) {
	mark_begin(ctx);
	asm volatile("wbinvd"::);
	mark_end(ctx);
	return 0;
}

static int xsave_setbv(u32 index, u64 value)
{
	u32 eax = value;
	u32 edx = value >> 32;

	asm volatile("xsetbv\n\t" /* xsetbv */
				 : : "a" (eax), "d" (edx), "c" (index));
	return 0;
}

static int sample_case_xsetbv(struct ctx *ctx) {
	u32 cr4 = read_cr4();

	/* enable cr4.OSFXSR[9] for SSE. */
	write_cr4(cr4 | (1<<18));

	mark_begin(ctx);
	xsave_setbv(0, 0x7);
	mark_end(ctx);

	write_cr4(cr4);
	return 0;
}

static int sample_case_rdpmc(struct ctx *ctx) {
	mark_begin(ctx);
	asm volatile(ASM_TRY("1f")"rdpmc\n1:"::);
	mark_end(ctx);
	return 0;
}

static int sample_case_wrmsr_efer(struct ctx *ctx) {
	u64 misc = rdmsr(MSR_IA32_MISC_ENABLE);
	u64 efer = rdmsr(MSR_EFER);

	// clear XD bit
	wrmsr(MSR_IA32_MISC_ENABLE, misc &~ MSR_IA32_MISC_ENABLE_XD_DISABLE);

	mark_begin(ctx);
	// set NXE and clear LMA
	wrmsr(MSR_EFER, (efer | EFER_NX ) &~ EFER_LMA);
	mark_end(ctx);

	wrmsr(MSR_IA32_MISC_ENABLE, misc);
	wrmsr(MSR_EFER, efer);
	return 0;
}

static int sample_case_wrmsr_misc(struct ctx *ctx) {
	u64 misc = rdmsr(MSR_IA32_MISC_ENABLE);
	u64 efer = rdmsr(MSR_EFER);

	// set NXE
	wrmsr(MSR_EFER, efer | EFER_NX);
	// set XD
	wrmsr(MSR_IA32_MISC_ENABLE, misc | MSR_IA32_MISC_ENABLE_XD_DISABLE);

	mark_begin(ctx);
	// clear XD
	wrmsr(MSR_IA32_MISC_ENABLE, misc &~ MSR_IA32_MISC_ENABLE_XD_DISABLE);
	mark_end(ctx);

	wrmsr(MSR_IA32_MISC_ENABLE, misc);
	wrmsr(MSR_EFER, efer);
	return 0;
}

static int sample_case_enable_msi(struct ctx *ctx) {
	u16 ctrl, data;
	// bus 0, dev 1, func 0
	u32 ctrl_addr = 0x80000000 | (1 << 11) | 0xd0;
	u32 data_addr = 0x80000000 | (1 << 11) | 0xdc;

	outl(ctrl_addr, 0xcf8);
	ctrl = inw(0xcfe);
	outl(data_addr, 0xcf8);
	data = inw(0xcfc);

	// set vector (0x40)
	outl(data_addr, 0xcf8);
	outw(data | 0x40, 0xcfc);

	// enable MSI
	outl(ctrl_addr, 0xcf8);
	mark_begin(ctx);
	outw(ctrl | 1, 0xcfe);
	mark_end(ctx);

	// restore
	outl(data_addr, 0xcf8);
	outw(data, 0xcfc);
	outl(ctrl_addr, 0xcf8);
	outw(ctrl, 0xcfe);
	return 0;
}

static int sample_case_enable_paging(struct ctx *ctx) {
	u64 *begin_tsc = &ctx->begin_tsc;
	u64 *end_tsc = &ctx->end_tsc;

	asm volatile(
		"ljmp *1f\n" /* switch to compatibility mode */
		"1:\n"
		".long 2f\n"
		".long " xstr(KERNEL_CS32) "\n"
		"2:\n"
		".code32\n"
		"movl %%cr0, %%ebx\n"
		"btcl $31, %%ebx\n" /* clear PG */
		"btsl $30, %%ebx\n" /* set CD */
		"movl %%ebx, %%cr0\n"

		"movl %%cr0, %%ebx\n"
		"btsl $31, %%ebx\n" /* set PG */
		"btcl $30, %%ebx\n" /* clear CD */

		"mfence\n"
		"rdtscp\n"
		"movl %%eax, (%%esi)\n"
		"movl %%edx, 4(%%esi)\n"
		"movl %%ebx, %%cr0\n" // enable paging
		"mfence\n"
		"rdtscp\n"
		"movl %%eax, (%%edi)\n"
		"movl %%edx, 4(%%edi)\n"

		"ljmpl %[cs64], $3f\n"    /* back to long mode */
		".code64\n"
		"3:\n"
		::[cs64] "i"(KERNEL_CS64), "S"(begin_tsc), "D"(end_tsc)
		:"rax", "rbx", "rdx", "memory");
	return 0;
}

extern u32 pt_root_32[];

static int sample_case_enable_pae(struct ctx *ctx) {
	u64 *begin_tsc = &ctx->begin_tsc;
	u64 *end_tsc = &ctx->end_tsc;

	asm volatile(
		"ljmp *1f\n" /* switch to compatibility mode */
		"1:\n"
		".long 2f\n"
		".long " xstr(KERNEL_CS32) "\n"
		"2:\n"
		".code32\n"
		"movl %%cr0, %%eax\n"
		"btcl $31, %%eax\n" /* clear PG */
		"movl %%eax, %%cr0\n"
		"movl %%cr4, %%eax\n"
		"btcl $5, %%eax\n" /* clear pae */
		"btsl $4, %%eax\n" // set PSE to enable 4M page in 32bits
		"movl %%eax, %%cr4\n"
		"movl %%cr3, %%eax\n"
		"pushl %%eax\n"
		"movl $pt_root_32, %%eax\n" /* set legacy page table */
		"movl %%eax, %%cr3\n"
		"movl $0xc0000080, %%ecx\n" /* EFER */
		"rdmsr\n"
		"btcl $8, %%eax\n" /* clear LME */
		"wrmsr\n"
		"movl %%cr0, %%eax\n"
		"btsl $31, %%eax\n" /* set PG */
		"movl %%eax, %%cr0\n"
		"ljmpl %[cs32], $1f\n"
		"1:\n"

		// set pae pgptes
		"movl $pt_root_pae, %%eax\n"
		"movl $pt_root_32, %%ebx\n"
		"movl (%%eax), %%edx\n"
		"movl %%edx, (%%ebx)\n"
		"movl 4(%%eax), %%edx\n"
		"movl %%edx, 4(%%ebx)\n"
		"movl 8(%%eax), %%edx\n"
		"movl %%edx, 8(%%ebx)\n"
		"movl 12(%%eax), %%edx\n"
		"movl %%edx, 12(%%ebx)\n"
		"movl 16(%%eax), %%edx\n"
		"movl %%edx, 16(%%ebx)\n"
		"movl 20(%%eax), %%edx\n"
		"movl %%edx, 20(%%ebx)\n"
		"movl 24(%%eax), %%edx\n"
		"movl %%edx, 24(%%ebx)\n"
		"movl 28(%%eax), %%edx\n"
		"movl %%edx, 28(%%ebx)\n"

		"movl %%cr4, %%ebx\n"
		"btsl $5, %%ebx\n" /* set pae */
		"btcl $4, %%ebx\n" /* clear pse */

		"mfence\n"
		"rdtscp\n"

		"movl %%ebx, %%cr4\n"

		"movl %%eax, %%ebx\n"
		"movl %%edx, %%ecx\n"
		"mfence\n"
		"rdtsc\n"
		"movl %%ebx, (%%esi)\n"
		"movl %%ecx, 4(%%esi)\n"
		"movl %%eax, (%%edi)\n"
		"movl %%edx, 4(%%edi)\n"

		// restore back to ia32-e mode
		"movl %%cr0, %%eax\n"
		"btcl $31, %%eax\n" /* clear PG */
		"movl %%eax, %%cr0\n"
		"movl $0xc0000080, %%ecx\n" /* EFER */
		"rdmsr\n"
		"btsl $8, %%eax\n" /* set LME */
		"wrmsr\n"
		"popl %%eax\n" /* 4-levels page table */
		"movl %%eax, %%cr3\n"
		"movl %%cr0, %%eax\n"
		"btsl $31, %%eax\n" /* set PG */
		"movl %%eax, %%cr0\n"

		"ljmpl %[cs64], $3f\n"    /* back to long mode */
		".code64\n"
		"3:\n"
		::[cs64] "i"(KERNEL_CS64), [cs32] "i"(KERNEL_CS32), "S"(begin_tsc), "D"(end_tsc)
		:"rax", "rbx", "rcx", "rdx", "memory");

	// restore pt_root_32's first 8 entries which are filled with pae's pgptes
	for (int i = 0; i < 8; i++) {
		pt_root_32[i] = 0x1e7 | (i << 22);
	}
	return 0;
}


static struct test_case all_cases[] = {
	{ .name = "single step trap", .fn = sample_case_sst, .end_in_exception = true },
	//{ .name = "jump task gate", .fn = sample_case_jmp_task_gate, .end_in_exception = true },
	{ .name = "cpuid 0x1", .fn = sample_case_cpuid_1 },
	{ .name = "cpuid 0xd", .fn = sample_case_cpuid_d },
	{ .name = "invd", .fn = sample_case_invd, .end_in_exception = true },
	{ .name = "enable paging", .fn = sample_case_enable_paging },
	{ .name = "enable pae", .fn = sample_case_enable_pae },
	{ .name = "read DR4", .fn = sample_case_read_dr4 },
	{ .name = "read rtc", .fn = sample_case_read_rtc },
	{ .name = "enable msi", .fn = sample_case_enable_msi },
	{ .name = "rdmsr", .fn = sample_case_rdmsr },
	{ .name = "wrmsr EFER", .fn = sample_case_wrmsr_efer },
	{ .name = "wrmsr MISC", .fn = sample_case_wrmsr_misc },
	{ .name = "ept violation", .fn = sample_case_ept, .end_in_exception = true },
	{ .name = "wbinvd", .fn = sample_case_wbinvd },
	{ .name = "xsetbv", .fn = sample_case_xsetbv },
	{ .name = "rdpmc", .fn = sample_case_rdpmc, .end_in_exception = true },
};

// implementations

static struct case_result *results[ARRAY_SIZE(all_cases)] = {0};
static u64 *samples = NULL;

static void do_test()
{
	int i, c, ret;
	struct case_result *cr;
	u64 min, max, dur, sum;
	struct ctx ctx;
	struct test_case *p;
	handler old_gp;
	handler old_ud;
	handler old_pf;

	for (i = 0; i < ARRAY_SIZE(all_cases); i++) {
		min = -1;
		sum = max = 0;
		memset(samples, 0, loop_count * sizeof(*samples));
		p = &all_cases[i];
		cr = results[i];

		if (p->end_in_exception) {
			old_gp = handle_exception(GP_VECTOR, record_exception_tsc);
			old_ud = handle_exception(UD_VECTOR, record_exception_tsc);
			old_pf = handle_exception(PF_VECTOR, record_exception_tsc);
		}

		printf("start test %s...", p->name);
		for (c = 0; c < loop_count + skip_count; c++) {
			memset(&ctx, 0, sizeof(ctx));
			ctx.end_in_exception = p->end_in_exception;

			ret = all_cases[i].fn(&ctx);
			if (ret) {
				printf("case %s: failed at count %d, ret %d\n", p->name, c, ret);
				break;
			}

			dur = get_latency_in_ns(&ctx);
			if (dur == 0) {
				printf("case %s: get zero latency at count %d, skip\n", p->name, c);
				break;
			}

			if (c < skip_count) {
				continue;
			}

			sum += dur;
			samples[c - skip_count] = dur;
			if (dur > max) {
				max = dur;
			}
			if (dur < min) {
				min = dur;
			}
		}
		printf("done\n");

		if (p->end_in_exception) {
			handle_exception(GP_VECTOR, old_gp);
			handle_exception(UD_VECTOR, old_ud);
			handle_exception(PF_VECTOR, old_pf);
		}

		if (c != loop_count + skip_count) {
			cr->valid = false;
			continue;
		}


		cr->valid = true;
		cr->name = p->name;
		cr->min = min;
		cr->max = max;
		cr->avg = sum/loop_count;

		// computer average of deviations
		sum = 0;
		for (c = 0; c < loop_count; c++) {
			sum += delta(samples[c], cr->avg) * delta(samples[c], cr->avg);
		}
		cr->dev = sum/loop_count;
	}
}

static void alloc_results()
{
	for (int i = 0; i < ARRAY_SIZE(all_cases); i++) {
		results[i] = malloc(sizeof(*results[i]));
	}
	samples = calloc(loop_count, sizeof(*samples));
}

static void show_results()
{
	int i;
	struct case_result *p;

	printf("Results:\n");
	for (i = 0; i < ARRAY_SIZE(all_cases); i++) {
		p = results[i];
		if (p && p->valid) {
			printf("%d: %s: min[%luns], max[%luns], avg[%luns], dev2[%luns]\n",
				i, p->name, p->min, p->max, p->avg, p->dev);
		}
	}
	printf("[ctrl-c]: to exit, [ctrl-r]: to rerun test, any other keys to re-show current results\n");
}

static void free_results()
{
	for (int i = 0; i < ARRAY_SIZE(all_cases); i++) {
		if (results[i]) {
			free(results[i]);
			results[i] = NULL;
		}
	}
	if (samples) {
		free(samples);
		samples = NULL;
	}
}

static void shutdown()
{
	outw(0x2000|(5 << 10), 0x404);
}

static void parse_args(int ac, char **av)
{
	int i;

	printf("ac: %d\n", ac);
	if (ac == 0) {
		return;
	}

	for (i = 0; i < ac; i++) {
		printf("%d: {%s}\n", i, av[i]);
		if (av[i][0] != '-' || strlen(av[i]) == 1) {
			printf("unknown parameter, skip\n");
			continue;
		}
		switch (av[i][1]) {
			case 'c':
				loop_count = my_atoi(&av[i][1]);
				printf("loop count change to %d\n", loop_count);
				break;
			case 's':
				skip_count = my_atoi(&av[i][1]);
				printf("skip count change to %d\n", skip_count);
				break;
			default:
				printf("unknown parameter\n");
				break;
		}
	}
}

static void print_usage()
{
	printf("Usage:\nvmexit_latency -c[loop_count] -s[warmup_count]\n"
		"\t-c[loop_count]: totol loop count, default is %d\n"
		"\t-s[warmup_count]: warmup run before loop, default is %d\n",
			loop_count, skip_count);
}

int main(int ac, char **av)
{
	uint8_t c;

	setup_idt();
	setup_vm();
	print_usage();
	parse_args(ac, av);

	alloc_results();
	struct cpuid r = cpuid(0x16);
	freq = r.a / 1000;
	printf("vmexit latency test\ncore_base_freq: %dMHz, core_max_freq: %dMHz, bus_freq: %dMHz, freq: %d\n",
		r.a, r.b, r.c, freq);

test:
	// do test
	asm volatile("cli");
	do_test();
	asm volatile("sti");


	show_results();

	while (1)
	{
		c = getc();
		if (c != 0xff) {
			//printf("get %x\n", c);
			if (c == 0x3) {
				// ctrl-c
				break;
			}
			if (c == 0x12) {
				// ctrl-r
				goto test;
			}
			show_results();
		}
	}

	printf("exit...\n");
	free_results();
	shutdown();
	return 0;
}
