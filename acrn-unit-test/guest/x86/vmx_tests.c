/*
 * All test cases of nested virtualization should be in this file
 *
 * Author : Arthur Chunqi Li <yzt356@gmail.com>
 */
#include "vmx.h"
#include "msr.h"
#include "processor.h"
#include "vm.h"
#include "pci.h"
#include "fwcfg.h"
#include "isr.h"
#include "desc.h"
#include "apic.h"
#include "types.h"
#include "vmalloc.h"
#include "alloc_page.h"
#include "smp.h"
#include "delay.h"

#define NONCANONICAL            0xaaaaaaaaaaaaaaaaull

#define VPID_CAP_INVVPID_TYPES_SHIFT 40

u64 ia32_pat;
u64 ia32_efer;
void *io_bitmap_a, *io_bitmap_b;
u16 ioport;

unsigned long *pml4;
u64 eptp;
void *data_page1, *data_page2;

phys_addr_t pci_physaddr;

void *pml_log;
#define PML_INDEX 512

static inline unsigned ffs(unsigned x)
{
	int pos = -1;

	__asm__ __volatile__("bsf %1, %%eax; cmovnz %%eax, %0"
			     : "+r"(pos) : "rm"(x) : "eax");
	return pos + 1;
}

static inline void vmcall(void)
{
	asm volatile("vmcall");
}

static void basic_guest_main(void)
{
	report("Basic VMX test", 1);
}

static int basic_exit_handler(void)
{
	report("Basic VMX test", 0);
	print_vmexit_info();
	return VMX_TEST_EXIT;
}

static void vmenter_main(void)
{
	u64 rax;
	u64 rsp, resume_rsp;

	report("test vmlaunch", 1);

	asm volatile(
		"mov %%rsp, %0\n\t"
		"mov %3, %%rax\n\t"
		"vmcall\n\t"
		"mov %%rax, %1\n\t"
		"mov %%rsp, %2\n\t"
		: "=r"(rsp), "=r"(rax), "=r"(resume_rsp)
		: "g"(0xABCD));
	report("test vmresume", (rax == 0xFFFF) && (rsp == resume_rsp));
}

static int vmenter_exit_handler(void)
{
	u64 guest_rip;
	ulong reason;

	guest_rip = vmcs_read(GUEST_RIP);
	reason = vmcs_read(EXI_REASON) & 0xff;
	switch (reason) {
	case VMX_VMCALL:
		if (regs.rax != 0xABCD) {
			report("test vmresume", 0);
			return VMX_TEST_VMEXIT;
		}
		regs.rax = 0xFFFF;
		vmcs_write(GUEST_RIP, guest_rip + 3);
		return VMX_TEST_RESUME;
	default:
		report("test vmresume", 0);
		print_vmexit_info();
	}
	return VMX_TEST_VMEXIT;
}

u32 preempt_scale;
volatile unsigned long long tsc_val;
volatile u32 preempt_val;
u64 saved_rip;

static int preemption_timer_init(struct vmcs *vmcs)
{
	if (!(ctrl_pin_rev.clr & PIN_PREEMPT)) {
		printf("\tPreemption timer is not supported\n");
		return VMX_TEST_EXIT;
	}
	vmcs_write(PIN_CONTROLS, vmcs_read(PIN_CONTROLS) | PIN_PREEMPT);
	preempt_val = 10000000;
	vmcs_write(PREEMPT_TIMER_VALUE, preempt_val);
	preempt_scale = rdmsr(MSR_IA32_VMX_MISC) & 0x1F;

	if (!(ctrl_exit_rev.clr & EXI_SAVE_PREEMPT))
		printf("\tSave preemption value is not supported\n");

	return VMX_TEST_START;
}

static void preemption_timer_main(void)
{
	tsc_val = rdtsc();
	if (ctrl_exit_rev.clr & EXI_SAVE_PREEMPT) {
		vmx_set_test_stage(0);
		vmcall();
		if (vmx_get_test_stage() == 1)
			vmcall();
	}
	vmx_set_test_stage(1);
	while (vmx_get_test_stage() == 1) {
		if (((rdtsc() - tsc_val) >> preempt_scale)
				> 10 * preempt_val) {
			vmx_set_test_stage(2);
			vmcall();
		}
	}
	tsc_val = rdtsc();
	asm volatile ("hlt");
	vmcall();
	vmx_set_test_stage(5);
	vmcall();
}

static int preemption_timer_exit_handler(void)
{
	bool guest_halted;
	u64 guest_rip;
	ulong reason;
	u32 insn_len;
	u32 ctrl_exit;

	guest_rip = vmcs_read(GUEST_RIP);
	reason = vmcs_read(EXI_REASON) & 0xff;
	insn_len = vmcs_read(EXI_INST_LEN);
	switch (reason) {
	case VMX_PREEMPT:
		switch (vmx_get_test_stage()) {
		case 1:
		case 2:
			report("busy-wait for preemption timer",
			       ((rdtsc() - tsc_val) >> preempt_scale) >=
			       preempt_val);
			vmx_set_test_stage(3);
			vmcs_write(PREEMPT_TIMER_VALUE, preempt_val);
			return VMX_TEST_RESUME;
		case 3:
			guest_halted =
				(vmcs_read(GUEST_ACTV_STATE) == ACTV_HLT);
			report("preemption timer during hlt",
			       ((rdtsc() - tsc_val) >> preempt_scale) >=
			       preempt_val && guest_halted);
			vmx_set_test_stage(4);
			vmcs_write(PIN_CONTROLS,
				   vmcs_read(PIN_CONTROLS) & ~PIN_PREEMPT);
			vmcs_write(GUEST_ACTV_STATE, ACTV_ACTIVE);
			return VMX_TEST_RESUME;
		case 4:
			report("preemption timer with 0 value",
			       saved_rip == guest_rip);
			break;
		default:
			report("Invalid stage.", false);
			print_vmexit_info();
			break;
		}
		break;
	case VMX_VMCALL:
		vmcs_write(GUEST_RIP, guest_rip + insn_len);
		switch (vmx_get_test_stage()) {
		case 0:
			report("Keep preemption value",
			       vmcs_read(PREEMPT_TIMER_VALUE) == preempt_val);
			vmx_set_test_stage(1);
			vmcs_write(PREEMPT_TIMER_VALUE, preempt_val);
			ctrl_exit = (vmcs_read(EXI_CONTROLS) |
				EXI_SAVE_PREEMPT) & ctrl_exit_rev.clr;
			vmcs_write(EXI_CONTROLS, ctrl_exit);
			return VMX_TEST_RESUME;
		case 1:
			report("Save preemption value",
			       vmcs_read(PREEMPT_TIMER_VALUE) < preempt_val);
			return VMX_TEST_RESUME;
		case 2:
			report("busy-wait for preemption timer", 0);
			vmx_set_test_stage(3);
			vmcs_write(PREEMPT_TIMER_VALUE, preempt_val);
			return VMX_TEST_RESUME;
		case 3:
			report("preemption timer during hlt", 0);
			vmx_set_test_stage(4);
			/* fall through */
		case 4:
			vmcs_write(PIN_CONTROLS,
				   vmcs_read(PIN_CONTROLS) | PIN_PREEMPT);
			vmcs_write(PREEMPT_TIMER_VALUE, 0);
			saved_rip = guest_rip + insn_len;
			return VMX_TEST_RESUME;
		case 5:
			report("preemption timer with 0 value (vmcall stage 5)", 0);
			break;
		default:
			// Should not reach here
			report("unexpected stage, %d", false,
			       vmx_get_test_stage());
			print_vmexit_info();
			return VMX_TEST_VMEXIT;
		}
		break;
	default:
		report("Unknown exit reason, %ld", false, reason);
		print_vmexit_info();
	}
	vmcs_write(PIN_CONTROLS, vmcs_read(PIN_CONTROLS) & ~PIN_PREEMPT);
	return VMX_TEST_VMEXIT;
}

static void msr_bmp_init(void)
{
	void *msr_bitmap;
	u32 ctrl_cpu0;

	msr_bitmap = alloc_page();
	memset(msr_bitmap, 0x0, PAGE_SIZE);
	ctrl_cpu0 = vmcs_read(CPU_EXEC_CTRL0);
	ctrl_cpu0 |= CPU_MSR_BITMAP;
	vmcs_write(CPU_EXEC_CTRL0, ctrl_cpu0);
	vmcs_write(MSR_BITMAP, (u64)msr_bitmap);
}

static int test_ctrl_pat_init(struct vmcs *vmcs)
{
	u64 ctrl_ent;
	u64 ctrl_exi;

	msr_bmp_init();
	if (!(ctrl_exit_rev.clr & EXI_SAVE_PAT) &&
	    !(ctrl_exit_rev.clr & EXI_LOAD_PAT) &&
	    !(ctrl_enter_rev.clr & ENT_LOAD_PAT)) {
		printf("\tSave/load PAT is not supported\n");
		return 1;
	}

	ctrl_ent = vmcs_read(ENT_CONTROLS);
	ctrl_exi = vmcs_read(EXI_CONTROLS);
	ctrl_ent |= ctrl_enter_rev.clr & ENT_LOAD_PAT;
	ctrl_exi |= ctrl_exit_rev.clr & (EXI_SAVE_PAT | EXI_LOAD_PAT);
	vmcs_write(ENT_CONTROLS, ctrl_ent);
	vmcs_write(EXI_CONTROLS, ctrl_exi);
	ia32_pat = rdmsr(MSR_IA32_CR_PAT);
	vmcs_write(GUEST_PAT, 0x0);
	vmcs_write(HOST_PAT, ia32_pat);
	return VMX_TEST_START;
}

static void test_ctrl_pat_main(void)
{
	u64 guest_ia32_pat;

	guest_ia32_pat = rdmsr(MSR_IA32_CR_PAT);
	if (!(ctrl_enter_rev.clr & ENT_LOAD_PAT))
		printf("\tENT_LOAD_PAT is not supported.\n");
	else {
		if (guest_ia32_pat != 0) {
			report("Entry load PAT", 0);
			return;
		}
	}
	wrmsr(MSR_IA32_CR_PAT, 0x6);
	vmcall();
	guest_ia32_pat = rdmsr(MSR_IA32_CR_PAT);
	if (ctrl_enter_rev.clr & ENT_LOAD_PAT)
		report("Entry load PAT", guest_ia32_pat == ia32_pat);
}

static int test_ctrl_pat_exit_handler(void)
{
	u64 guest_rip;
	ulong reason;
	u64 guest_pat;

	guest_rip = vmcs_read(GUEST_RIP);
	reason = vmcs_read(EXI_REASON) & 0xff;
	switch (reason) {
	case VMX_VMCALL:
		guest_pat = vmcs_read(GUEST_PAT);
		if (!(ctrl_exit_rev.clr & EXI_SAVE_PAT)) {
			printf("\tEXI_SAVE_PAT is not supported\n");
			vmcs_write(GUEST_PAT, 0x6);
		} else {
			report("Exit save PAT", guest_pat == 0x6);
		}
		if (!(ctrl_exit_rev.clr & EXI_LOAD_PAT))
			printf("\tEXI_LOAD_PAT is not supported\n");
		else
			report("Exit load PAT", rdmsr(MSR_IA32_CR_PAT) == ia32_pat);
		vmcs_write(GUEST_PAT, ia32_pat);
		vmcs_write(GUEST_RIP, guest_rip + 3);
		return VMX_TEST_RESUME;
	default:
		printf("ERROR : Undefined exit reason, reason = %ld.\n", reason);
		break;
	}
	return VMX_TEST_VMEXIT;
}

static int test_ctrl_efer_init(struct vmcs *vmcs)
{
	u64 ctrl_ent;
	u64 ctrl_exi;

	msr_bmp_init();
	ctrl_ent = vmcs_read(ENT_CONTROLS) | ENT_LOAD_EFER;
	ctrl_exi = vmcs_read(EXI_CONTROLS) | EXI_SAVE_EFER | EXI_LOAD_EFER;
	vmcs_write(ENT_CONTROLS, ctrl_ent & ctrl_enter_rev.clr);
	vmcs_write(EXI_CONTROLS, ctrl_exi & ctrl_exit_rev.clr);
	ia32_efer = rdmsr(MSR_EFER);
	vmcs_write(GUEST_EFER, ia32_efer ^ EFER_NX);
	vmcs_write(HOST_EFER, ia32_efer ^ EFER_NX);
	return VMX_TEST_START;
}

static void test_ctrl_efer_main(void)
{
	u64 guest_ia32_efer;

	guest_ia32_efer = rdmsr(MSR_EFER);
	if (!(ctrl_enter_rev.clr & ENT_LOAD_EFER))
		printf("\tENT_LOAD_EFER is not supported.\n");
	else {
		if (guest_ia32_efer != (ia32_efer ^ EFER_NX)) {
			report("Entry load EFER", 0);
			return;
		}
	}
	wrmsr(MSR_EFER, ia32_efer);
	vmcall();
	guest_ia32_efer = rdmsr(MSR_EFER);
	if (ctrl_enter_rev.clr & ENT_LOAD_EFER)
		report("Entry load EFER", guest_ia32_efer == ia32_efer);
}

static int test_ctrl_efer_exit_handler(void)
{
	u64 guest_rip;
	ulong reason;
	u64 guest_efer;

	guest_rip = vmcs_read(GUEST_RIP);
	reason = vmcs_read(EXI_REASON) & 0xff;
	switch (reason) {
	case VMX_VMCALL:
		guest_efer = vmcs_read(GUEST_EFER);
		if (!(ctrl_exit_rev.clr & EXI_SAVE_EFER)) {
			printf("\tEXI_SAVE_EFER is not supported\n");
			vmcs_write(GUEST_EFER, ia32_efer);
		} else {
			report("Exit save EFER", guest_efer == ia32_efer);
		}
		if (!(ctrl_exit_rev.clr & EXI_LOAD_EFER)) {
			printf("\tEXI_LOAD_EFER is not supported\n");
			wrmsr(MSR_EFER, ia32_efer ^ EFER_NX);
		} else {
			report("Exit load EFER", rdmsr(MSR_EFER) == (ia32_efer ^ EFER_NX));
		}
		vmcs_write(GUEST_PAT, ia32_efer);
		vmcs_write(GUEST_RIP, guest_rip + 3);
		return VMX_TEST_RESUME;
	default:
		printf("ERROR : Undefined exit reason, reason = %ld.\n", reason);
		break;
	}
	return VMX_TEST_VMEXIT;
}

u32 guest_cr0, guest_cr4;

static void cr_shadowing_main(void)
{
	u32 cr0, cr4, tmp;

	// Test read through
	vmx_set_test_stage(0);
	guest_cr0 = read_cr0();
	if (vmx_get_test_stage() == 1)
		report("Read through CR0", 0);
	else
		vmcall();
	vmx_set_test_stage(1);
	guest_cr4 = read_cr4();
	if (vmx_get_test_stage() == 2)
		report("Read through CR4", 0);
	else
		vmcall();
	// Test write through
	guest_cr0 = guest_cr0 ^ (X86_CR0_TS | X86_CR0_MP);
	guest_cr4 = guest_cr4 ^ (X86_CR4_TSD | X86_CR4_DE);
	vmx_set_test_stage(2);
	write_cr0(guest_cr0);
	if (vmx_get_test_stage() == 3)
		report("Write throuth CR0", 0);
	else
		vmcall();
	vmx_set_test_stage(3);
	write_cr4(guest_cr4);
	if (vmx_get_test_stage() == 4)
		report("Write through CR4", 0);
	else
		vmcall();
	// Test read shadow
	vmx_set_test_stage(4);
	vmcall();
	cr0 = read_cr0();
	if (vmx_get_test_stage() != 5)
		report("Read shadowing CR0", cr0 == guest_cr0);
	vmx_set_test_stage(5);
	cr4 = read_cr4();
	if (vmx_get_test_stage() != 6)
		report("Read shadowing CR4", cr4 == guest_cr4);
	// Test write shadow (same value with shadow)
	vmx_set_test_stage(6);
	write_cr0(guest_cr0);
	if (vmx_get_test_stage() == 7)
		report("Write shadowing CR0 (same value with shadow)", 0);
	else
		vmcall();
	vmx_set_test_stage(7);
	write_cr4(guest_cr4);
	if (vmx_get_test_stage() == 8)
		report("Write shadowing CR4 (same value with shadow)", 0);
	else
		vmcall();
	// Test write shadow (different value)
	vmx_set_test_stage(8);
	tmp = guest_cr0 ^ X86_CR0_TS;
	asm volatile("mov %0, %%rsi\n\t"
		"mov %%rsi, %%cr0\n\t"
		::"m"(tmp)
		:"rsi", "memory", "cc");
	report("Write shadowing different X86_CR0_TS", vmx_get_test_stage() == 9);
	vmx_set_test_stage(9);
	tmp = guest_cr0 ^ X86_CR0_MP;
	asm volatile("mov %0, %%rsi\n\t"
		"mov %%rsi, %%cr0\n\t"
		::"m"(tmp)
		:"rsi", "memory", "cc");
	report("Write shadowing different X86_CR0_MP", vmx_get_test_stage() == 10);
	vmx_set_test_stage(10);
	tmp = guest_cr4 ^ X86_CR4_TSD;
	asm volatile("mov %0, %%rsi\n\t"
		"mov %%rsi, %%cr4\n\t"
		::"m"(tmp)
		:"rsi", "memory", "cc");
	report("Write shadowing different X86_CR4_TSD", vmx_get_test_stage() == 11);
	vmx_set_test_stage(11);
	tmp = guest_cr4 ^ X86_CR4_DE;
	asm volatile("mov %0, %%rsi\n\t"
		"mov %%rsi, %%cr4\n\t"
		::"m"(tmp)
		:"rsi", "memory", "cc");
	report("Write shadowing different X86_CR4_DE", vmx_get_test_stage() == 12);
}

static int cr_shadowing_exit_handler(void)
{
	u64 guest_rip;
	ulong reason;
	u32 insn_len;
	u32 exit_qual;

	guest_rip = vmcs_read(GUEST_RIP);
	reason = vmcs_read(EXI_REASON) & 0xff;
	insn_len = vmcs_read(EXI_INST_LEN);
	exit_qual = vmcs_read(EXI_QUALIFICATION);
	switch (reason) {
	case VMX_VMCALL:
		switch (vmx_get_test_stage()) {
		case 0:
			report("Read through CR0", guest_cr0 == vmcs_read(GUEST_CR0));
			break;
		case 1:
			report("Read through CR4", guest_cr4 == vmcs_read(GUEST_CR4));
			break;
		case 2:
			report("Write through CR0", guest_cr0 == vmcs_read(GUEST_CR0));
			break;
		case 3:
			report("Write through CR4", guest_cr4 == vmcs_read(GUEST_CR4));
			break;
		case 4:
			guest_cr0 = vmcs_read(GUEST_CR0) ^ (X86_CR0_TS | X86_CR0_MP);
			guest_cr4 = vmcs_read(GUEST_CR4) ^ (X86_CR4_TSD | X86_CR4_DE);
			vmcs_write(CR0_MASK, X86_CR0_TS | X86_CR0_MP);
			vmcs_write(CR0_READ_SHADOW, guest_cr0 & (X86_CR0_TS | X86_CR0_MP));
			vmcs_write(CR4_MASK, X86_CR4_TSD | X86_CR4_DE);
			vmcs_write(CR4_READ_SHADOW, guest_cr4 & (X86_CR4_TSD | X86_CR4_DE));
			break;
		case 6:
			report("Write shadowing CR0 (same value)",
					guest_cr0 == (vmcs_read(GUEST_CR0) ^ (X86_CR0_TS | X86_CR0_MP)));
			break;
		case 7:
			report("Write shadowing CR4 (same value)",
					guest_cr4 == (vmcs_read(GUEST_CR4) ^ (X86_CR4_TSD | X86_CR4_DE)));
			break;
		default:
			// Should not reach here
			report("unexpected stage, %d", false,
			       vmx_get_test_stage());
			print_vmexit_info();
			return VMX_TEST_VMEXIT;
		}
		vmcs_write(GUEST_RIP, guest_rip + insn_len);
		return VMX_TEST_RESUME;
	case VMX_CR:
		switch (vmx_get_test_stage()) {
		case 4:
			report("Read shadowing CR0", 0);
			vmx_inc_test_stage();
			break;
		case 5:
			report("Read shadowing CR4", 0);
			vmx_inc_test_stage();
			break;
		case 6:
			report("Write shadowing CR0 (same value)", 0);
			vmx_inc_test_stage();
			break;
		case 7:
			report("Write shadowing CR4 (same value)", 0);
			vmx_inc_test_stage();
			break;
		case 8:
		case 9:
			// 0x600 encodes "mov %esi, %cr0"
			if (exit_qual == 0x600)
				vmx_inc_test_stage();
			break;
		case 10:
		case 11:
			// 0x604 encodes "mov %esi, %cr4"
			if (exit_qual == 0x604)
				vmx_inc_test_stage();
			break;
		default:
			// Should not reach here
			report("unexpected stage, %d", false,
			       vmx_get_test_stage());
			print_vmexit_info();
			return VMX_TEST_VMEXIT;
		}
		vmcs_write(GUEST_RIP, guest_rip + insn_len);
		return VMX_TEST_RESUME;
	default:
		report("Unknown exit reason, %ld", false, reason);
		print_vmexit_info();
	}
	return VMX_TEST_VMEXIT;
}

static int iobmp_init(struct vmcs *vmcs)
{
	u32 ctrl_cpu0;

	io_bitmap_a = alloc_page();
	io_bitmap_b = alloc_page();
	memset(io_bitmap_a, 0x0, PAGE_SIZE);
	memset(io_bitmap_b, 0x0, PAGE_SIZE);
	ctrl_cpu0 = vmcs_read(CPU_EXEC_CTRL0);
	ctrl_cpu0 |= CPU_IO_BITMAP;
	ctrl_cpu0 &= (~CPU_IO);
	vmcs_write(CPU_EXEC_CTRL0, ctrl_cpu0);
	vmcs_write(IO_BITMAP_A, (u64)io_bitmap_a);
	vmcs_write(IO_BITMAP_B, (u64)io_bitmap_b);
	return VMX_TEST_START;
}

static void iobmp_main(void)
{
	// stage 0, test IO pass
	vmx_set_test_stage(0);
	inb(0x5000);
	outb(0x0, 0x5000);
	report("I/O bitmap - I/O pass", vmx_get_test_stage() == 0);
	// test IO width, in/out
	((u8 *)io_bitmap_a)[0] = 0xFF;
	vmx_set_test_stage(2);
	inb(0x0);
	report("I/O bitmap - trap in", vmx_get_test_stage() == 3);
	vmx_set_test_stage(3);
	outw(0x0, 0x0);
	report("I/O bitmap - trap out", vmx_get_test_stage() == 4);
	vmx_set_test_stage(4);
	inl(0x0);
	report("I/O bitmap - I/O width, long", vmx_get_test_stage() == 5);
	// test low/high IO port
	vmx_set_test_stage(5);
	((u8 *)io_bitmap_a)[0x5000 / 8] = (1 << (0x5000 % 8));
	inb(0x5000);
	report("I/O bitmap - I/O port, low part", vmx_get_test_stage() == 6);
	vmx_set_test_stage(6);
	((u8 *)io_bitmap_b)[0x1000 / 8] = (1 << (0x1000 % 8));
	inb(0x9000);
	report("I/O bitmap - I/O port, high part", vmx_get_test_stage() == 7);
	// test partial pass
	vmx_set_test_stage(7);
	inl(0x4FFF);
	report("I/O bitmap - partial pass", vmx_get_test_stage() == 8);
	// test overrun
	vmx_set_test_stage(8);
	memset(io_bitmap_a, 0x0, PAGE_SIZE);
	memset(io_bitmap_b, 0x0, PAGE_SIZE);
	inl(0xFFFF);
	report("I/O bitmap - overrun", vmx_get_test_stage() == 9);
	vmx_set_test_stage(9);
	vmcall();
	outb(0x0, 0x0);
	report("I/O bitmap - ignore unconditional exiting",
	       vmx_get_test_stage() == 9);
	vmx_set_test_stage(10);
	vmcall();
	outb(0x0, 0x0);
	report("I/O bitmap - unconditional exiting",
	       vmx_get_test_stage() == 11);
}

static int iobmp_exit_handler(void)
{
	u64 guest_rip;
	ulong reason, exit_qual;
	u32 insn_len, ctrl_cpu0;

	guest_rip = vmcs_read(GUEST_RIP);
	reason = vmcs_read(EXI_REASON) & 0xff;
	exit_qual = vmcs_read(EXI_QUALIFICATION);
	insn_len = vmcs_read(EXI_INST_LEN);
	switch (reason) {
	case VMX_IO:
		switch (vmx_get_test_stage()) {
		case 0:
		case 1:
			vmx_inc_test_stage();
			break;
		case 2:
			report("I/O bitmap - I/O width, byte",
					(exit_qual & VMX_IO_SIZE_MASK) == _VMX_IO_BYTE);
			report("I/O bitmap - I/O direction, in", exit_qual & VMX_IO_IN);
			vmx_inc_test_stage();
			break;
		case 3:
			report("I/O bitmap - I/O width, word",
					(exit_qual & VMX_IO_SIZE_MASK) == _VMX_IO_WORD);
			report("I/O bitmap - I/O direction, out",
					!(exit_qual & VMX_IO_IN));
			vmx_inc_test_stage();
			break;
		case 4:
			report("I/O bitmap - I/O width, long",
					(exit_qual & VMX_IO_SIZE_MASK) == _VMX_IO_LONG);
			vmx_inc_test_stage();
			break;
		case 5:
			if (((exit_qual & VMX_IO_PORT_MASK) >> VMX_IO_PORT_SHIFT) == 0x5000)
				vmx_inc_test_stage();
			break;
		case 6:
			if (((exit_qual & VMX_IO_PORT_MASK) >> VMX_IO_PORT_SHIFT) == 0x9000)
				vmx_inc_test_stage();
			break;
		case 7:
			if (((exit_qual & VMX_IO_PORT_MASK) >> VMX_IO_PORT_SHIFT) == 0x4FFF)
				vmx_inc_test_stage();
			break;
		case 8:
			if (((exit_qual & VMX_IO_PORT_MASK) >> VMX_IO_PORT_SHIFT) == 0xFFFF)
				vmx_inc_test_stage();
			break;
		case 9:
		case 10:
			ctrl_cpu0 = vmcs_read(CPU_EXEC_CTRL0);
			vmcs_write(CPU_EXEC_CTRL0, ctrl_cpu0 & ~CPU_IO);
			vmx_inc_test_stage();
			break;
		default:
			// Should not reach here
			report("unexpected stage, %d", false,
			       vmx_get_test_stage());
			print_vmexit_info();
			return VMX_TEST_VMEXIT;
		}
		vmcs_write(GUEST_RIP, guest_rip + insn_len);
		return VMX_TEST_RESUME;
	case VMX_VMCALL:
		switch (vmx_get_test_stage()) {
		case 9:
			ctrl_cpu0 = vmcs_read(CPU_EXEC_CTRL0);
			ctrl_cpu0 |= CPU_IO | CPU_IO_BITMAP;
			vmcs_write(CPU_EXEC_CTRL0, ctrl_cpu0);
			break;
		case 10:
			ctrl_cpu0 = vmcs_read(CPU_EXEC_CTRL0);
			ctrl_cpu0 = (ctrl_cpu0 & ~CPU_IO_BITMAP) | CPU_IO;
			vmcs_write(CPU_EXEC_CTRL0, ctrl_cpu0);
			break;
		default:
			// Should not reach here
			report("unexpected stage, %d", false,
			       vmx_get_test_stage());
			print_vmexit_info();
			return VMX_TEST_VMEXIT;
		}
		vmcs_write(GUEST_RIP, guest_rip + insn_len);
		return VMX_TEST_RESUME;
	default:
		printf("guest_rip = %#lx\n", guest_rip);
		printf("\tERROR : Undefined exit reason, reason = %ld.\n", reason);
		break;
	}
	return VMX_TEST_VMEXIT;
}

#define INSN_CPU0		0
#define INSN_CPU1		1
#define INSN_ALWAYS_TRAP	2

#define FIELD_EXIT_QUAL		(1 << 0)
#define FIELD_INSN_INFO		(1 << 1)

asm(
	"insn_hlt: hlt;ret\n\t"
	"insn_invlpg: invlpg 0x12345678;ret\n\t"
	"insn_mwait: xor %eax, %eax; xor %ecx, %ecx; mwait;ret\n\t"
	"insn_rdpmc: xor %ecx, %ecx; rdpmc;ret\n\t"
	"insn_rdtsc: rdtsc;ret\n\t"
	"insn_cr3_load: mov cr3,%rax; mov %rax,%cr3;ret\n\t"
	"insn_cr3_store: mov %cr3,%rax;ret\n\t"
#ifdef __x86_64__
	"insn_cr8_load: xor %eax, %eax; mov %rax,%cr8;ret\n\t"
	"insn_cr8_store: mov %cr8,%rax;ret\n\t"
#endif
	"insn_monitor: xor %eax, %eax; xor %ecx, %ecx; xor %edx, %edx; monitor;ret\n\t"
	"insn_pause: pause;ret\n\t"
	"insn_wbinvd: wbinvd;ret\n\t"
	"insn_cpuid: mov $10, %eax; cpuid;ret\n\t"
	"insn_invd: invd;ret\n\t"
	"insn_sgdt: sgdt gdt64_desc;ret\n\t"
	"insn_lgdt: lgdt gdt64_desc;ret\n\t"
	"insn_sidt: sidt idt_descr;ret\n\t"
	"insn_lidt: lidt idt_descr;ret\n\t"
	"insn_sldt: sldt %ax;ret\n\t"
	"insn_lldt: xor %eax, %eax; lldt %ax;ret\n\t"
	"insn_str: str %ax;ret\n\t"
	"insn_rdrand: rdrand %rax;ret\n\t"
	"insn_rdseed: rdseed %rax;ret\n\t"
);
extern void insn_hlt(void);
extern void insn_invlpg(void);
extern void insn_mwait(void);
extern void insn_rdpmc(void);
extern void insn_rdtsc(void);
extern void insn_cr3_load(void);
extern void insn_cr3_store(void);
#ifdef __x86_64__
extern void insn_cr8_load(void);
extern void insn_cr8_store(void);
#endif
extern void insn_monitor(void);
extern void insn_pause(void);
extern void insn_wbinvd(void);
extern void insn_sgdt(void);
extern void insn_lgdt(void);
extern void insn_sidt(void);
extern void insn_lidt(void);
extern void insn_sldt(void);
extern void insn_lldt(void);
extern void insn_str(void);
extern void insn_cpuid(void);
extern void insn_invd(void);
extern void insn_rdrand(void);
extern void insn_rdseed(void);

u32 cur_insn;
u64 cr3;

struct insn_table {
	const char *name;
	u32 flag;
	void (*insn_func)(void);
	u32 type;
	u32 reason;
	ulong exit_qual;
	u32 insn_info;
	// Use FIELD_EXIT_QUAL and FIELD_INSN_INFO to define
	// which field need to be tested, reason is always tested
	u32 test_field;
};

/*
 * Add more test cases of instruction intercept here. Elements in this
 * table is:
 *	name/control flag/insn function/type/exit reason/exit qulification/
 *	instruction info/field to test
 * The last field defines which fields (exit_qual and insn_info) need to be
 * tested in exit handler. If set to 0, only "reason" is checked.
 */
static struct insn_table insn_table[] = {
	// Flags for Primary Processor-Based VM-Execution Controls
	{"HLT",  CPU_HLT, insn_hlt, INSN_CPU0, 12, 0, 0, 0},
	{"INVLPG", CPU_INVLPG, insn_invlpg, INSN_CPU0, 14,
		0x12345678, 0, FIELD_EXIT_QUAL},
	{"MWAIT", CPU_MWAIT, insn_mwait, INSN_CPU0, 36, 0, 0, 0},
	{"RDPMC", CPU_RDPMC, insn_rdpmc, INSN_CPU0, 15, 0, 0, 0},
	{"RDTSC", CPU_RDTSC, insn_rdtsc, INSN_CPU0, 16, 0, 0, 0},
	{"CR3 load", CPU_CR3_LOAD, insn_cr3_load, INSN_CPU0, 28, 0x3, 0,
		FIELD_EXIT_QUAL},
	{"CR3 store", CPU_CR3_STORE, insn_cr3_store, INSN_CPU0, 28, 0x13, 0,
		FIELD_EXIT_QUAL},
#ifdef __x86_64__
	{"CR8 load", CPU_CR8_LOAD, insn_cr8_load, INSN_CPU0, 28, 0x8, 0,
		FIELD_EXIT_QUAL},
	{"CR8 store", CPU_CR8_STORE, insn_cr8_store, INSN_CPU0, 28, 0x18, 0,
		FIELD_EXIT_QUAL},
#endif
	{"MONITOR", CPU_MONITOR, insn_monitor, INSN_CPU0, 39, 0, 0, 0},
	{"PAUSE", CPU_PAUSE, insn_pause, INSN_CPU0, 40, 0, 0, 0},
	// Flags for Secondary Processor-Based VM-Execution Controls
	{"WBINVD", CPU_WBINVD, insn_wbinvd, INSN_CPU1, 54, 0, 0, 0},
	{"DESC_TABLE (SGDT)", CPU_DESC_TABLE, insn_sgdt, INSN_CPU1, 46, 0, 0, 0},
	{"DESC_TABLE (LGDT)", CPU_DESC_TABLE, insn_lgdt, INSN_CPU1, 46, 0, 0, 0},
	{"DESC_TABLE (SIDT)", CPU_DESC_TABLE, insn_sidt, INSN_CPU1, 46, 0, 0, 0},
	{"DESC_TABLE (LIDT)", CPU_DESC_TABLE, insn_lidt, INSN_CPU1, 46, 0, 0, 0},
	{"DESC_TABLE (SLDT)", CPU_DESC_TABLE, insn_sldt, INSN_CPU1, 47, 0, 0, 0},
	{"DESC_TABLE (LLDT)", CPU_DESC_TABLE, insn_lldt, INSN_CPU1, 47, 0, 0, 0},
	{"DESC_TABLE (STR)", CPU_DESC_TABLE, insn_str, INSN_CPU1, 47, 0, 0, 0},
	/* LTR causes a #GP if done with a busy selector, so it is not tested.  */
	{"RDRAND", CPU_RDRAND, insn_rdrand, INSN_CPU1, VMX_RDRAND, 0, 0, 0},
	{"RDSEED", CPU_RDSEED, insn_rdseed, INSN_CPU1, VMX_RDSEED, 0, 0, 0},
	// Instructions always trap
	{"CPUID", 0, insn_cpuid, INSN_ALWAYS_TRAP, 10, 0, 0, 0},
	{"INVD", 0, insn_invd, INSN_ALWAYS_TRAP, 13, 0, 0, 0},
	// Instructions never trap
	{NULL},
};

static int insn_intercept_init(struct vmcs *vmcs)
{
	u32 ctrl_cpu;

	ctrl_cpu = ctrl_cpu_rev[0].set | CPU_SECONDARY;
	ctrl_cpu &= ctrl_cpu_rev[0].clr;
	vmcs_write(CPU_EXEC_CTRL0, ctrl_cpu);
	vmcs_write(CPU_EXEC_CTRL1, ctrl_cpu_rev[1].set);
	cr3 = read_cr3();
	return VMX_TEST_START;
}

static void insn_intercept_main(void)
{
	for (cur_insn = 0; insn_table[cur_insn].name != NULL; cur_insn++) {
		vmx_set_test_stage(cur_insn * 2);
		if ((insn_table[cur_insn].type == INSN_CPU0 &&
		     !(ctrl_cpu_rev[0].clr & insn_table[cur_insn].flag)) ||
		    (insn_table[cur_insn].type == INSN_CPU1 &&
		     !(ctrl_cpu_rev[1].clr & insn_table[cur_insn].flag))) {
			printf("\tCPU_CTRL%d.CPU_%s is not supported.\n",
			       insn_table[cur_insn].type - INSN_CPU0,
			       insn_table[cur_insn].name);
			continue;
		}

		if ((insn_table[cur_insn].type == INSN_CPU0 &&
		     !(ctrl_cpu_rev[0].set & insn_table[cur_insn].flag)) ||
		    (insn_table[cur_insn].type == INSN_CPU1 &&
		     !(ctrl_cpu_rev[1].set & insn_table[cur_insn].flag))) {
			/* skip hlt, it stalls the guest and is tested below */
			if (insn_table[cur_insn].insn_func != insn_hlt)
				insn_table[cur_insn].insn_func();
			report("execute %s", vmx_get_test_stage() == cur_insn * 2,
					insn_table[cur_insn].name);
		} else if (insn_table[cur_insn].type != INSN_ALWAYS_TRAP)
			printf("\tCPU_CTRL%d.CPU_%s always traps.\n",
			       insn_table[cur_insn].type - INSN_CPU0,
			       insn_table[cur_insn].name);

		vmcall();

		insn_table[cur_insn].insn_func();
		report("intercept %s", vmx_get_test_stage() == cur_insn * 2 + 1,
				insn_table[cur_insn].name);

		vmx_set_test_stage(cur_insn * 2 + 1);
		vmcall();
	}
}

static int insn_intercept_exit_handler(void)
{
	u64 guest_rip;
	u32 reason;
	ulong exit_qual;
	u32 insn_len;
	u32 insn_info;
	bool pass;

	guest_rip = vmcs_read(GUEST_RIP);
	reason = vmcs_read(EXI_REASON) & 0xff;
	exit_qual = vmcs_read(EXI_QUALIFICATION);
	insn_len = vmcs_read(EXI_INST_LEN);
	insn_info = vmcs_read(EXI_INST_INFO);

	if (reason == VMX_VMCALL) {
		u32 val = 0;

		if (insn_table[cur_insn].type == INSN_CPU0)
			val = vmcs_read(CPU_EXEC_CTRL0);
		else if (insn_table[cur_insn].type == INSN_CPU1)
			val = vmcs_read(CPU_EXEC_CTRL1);

		if (vmx_get_test_stage() & 1)
			val &= ~insn_table[cur_insn].flag;
		else
			val |= insn_table[cur_insn].flag;

		if (insn_table[cur_insn].type == INSN_CPU0)
			vmcs_write(CPU_EXEC_CTRL0, val | ctrl_cpu_rev[0].set);
		else if (insn_table[cur_insn].type == INSN_CPU1)
			vmcs_write(CPU_EXEC_CTRL1, val | ctrl_cpu_rev[1].set);
	} else {
		pass = (cur_insn * 2 == vmx_get_test_stage()) &&
			insn_table[cur_insn].reason == reason;
		if (insn_table[cur_insn].test_field & FIELD_EXIT_QUAL &&
		    insn_table[cur_insn].exit_qual != exit_qual)
			pass = false;
		if (insn_table[cur_insn].test_field & FIELD_INSN_INFO &&
		    insn_table[cur_insn].insn_info != insn_info)
			pass = false;
		if (pass)
			vmx_inc_test_stage();
	}
	vmcs_write(GUEST_RIP, guest_rip + insn_len);
	return VMX_TEST_RESUME;
}


/* Enables EPT and sets up the identity map. */
static int setup_ept(bool enable_ad)
{
	unsigned long end_of_memory;
	u32 ctrl_cpu[2];

	if (!(ctrl_cpu_rev[0].clr & CPU_SECONDARY) ||
	    !(ctrl_cpu_rev[1].clr & CPU_EPT)) {
		printf("\tEPT is not supported");
		return 1;
	}


	if (!(ept_vpid.val & EPT_CAP_UC) &&
			!(ept_vpid.val & EPT_CAP_WB)) {
		printf("\tEPT paging-structure memory type "
				"UC&WB are not supported\n");
		return 1;
	}
	if (ept_vpid.val & EPT_CAP_UC)
		eptp = EPT_MEM_TYPE_UC;
	else
		eptp = EPT_MEM_TYPE_WB;
	if (!(ept_vpid.val & EPT_CAP_PWL4)) {
		printf("\tPWL4 is not supported\n");
		return 1;
	}
	ctrl_cpu[0] = vmcs_read(CPU_EXEC_CTRL0);
	ctrl_cpu[1] = vmcs_read(CPU_EXEC_CTRL1);
	ctrl_cpu[0] = (ctrl_cpu[0] | CPU_SECONDARY)
		& ctrl_cpu_rev[0].clr;
	ctrl_cpu[1] = (ctrl_cpu[1] | CPU_EPT)
		& ctrl_cpu_rev[1].clr;
	vmcs_write(CPU_EXEC_CTRL0, ctrl_cpu[0]);
	vmcs_write(CPU_EXEC_CTRL1, ctrl_cpu[1]);
	eptp |= (3 << EPTP_PG_WALK_LEN_SHIFT);
	pml4 = alloc_page();
	memset(pml4, 0, PAGE_SIZE);
	eptp |= virt_to_phys(pml4);
	if (enable_ad)
		eptp |= EPTP_AD_FLAG;
	vmcs_write(EPTP, eptp);
	end_of_memory = fwcfg_get_u64(FW_CFG_RAM_SIZE);
	if (end_of_memory < (1ul << 32))
		end_of_memory = (1ul << 32);
	/* Cannot use large EPT pages if we need to track EPT
	 * accessed/dirty bits at 4K granularity.
	 */
	setup_ept_range(pml4, 0, end_of_memory, 0,
			!enable_ad && ept_2m_supported(),
			EPT_WA | EPT_RA | EPT_EA);
	return 0;
}

static void ept_enable_ad_bits(void)
{
	eptp |= EPTP_AD_FLAG;
	vmcs_write(EPTP, eptp);
}

static void ept_disable_ad_bits(void)
{
	eptp &= ~EPTP_AD_FLAG;
	vmcs_write(EPTP, eptp);
}

static void ept_enable_ad_bits_or_skip_test(void)
{
	if (!ept_ad_bits_supported())
		test_skip("EPT AD bits not supported.");
	ept_enable_ad_bits();
}

static int apic_version;

static int ept_init_common(bool have_ad)
{
	int ret;
	struct pci_dev pcidev;

	if (setup_ept(have_ad))
		return VMX_TEST_EXIT;
	data_page1 = alloc_page();
	data_page2 = alloc_page();
	memset(data_page1, 0x0, PAGE_SIZE);
	memset(data_page2, 0x0, PAGE_SIZE);
	*((u32 *)data_page1) = MAGIC_VAL_1;
	*((u32 *)data_page2) = MAGIC_VAL_2;
	install_ept(pml4, (unsigned long)data_page1, (unsigned long)data_page2,
			EPT_RA | EPT_WA | EPT_EA);

	apic_version = apic_read(APIC_LVR);

	ret = pci_find_dev(PCI_VENDOR_ID_REDHAT, PCI_DEVICE_ID_REDHAT_TEST);
	if (ret != PCIDEVADDR_INVALID) {
		pci_dev_init(&pcidev, ret);
		pci_physaddr = pcidev.resource[PCI_TESTDEV_BAR_MEM];
	}

	return VMX_TEST_START;
}

static int ept_init(struct vmcs *vmcs)
{
	return ept_init_common(false);
}

static void ept_common(void)
{
	vmx_set_test_stage(0);
	if (*((u32 *)data_page2) != MAGIC_VAL_1 ||
			*((u32 *)data_page1) != MAGIC_VAL_1)
		report("EPT basic framework - read", 0);
	else {
		*((u32 *)data_page2) = MAGIC_VAL_3;
		vmcall();
		if (vmx_get_test_stage() == 1) {
			if (*((u32 *)data_page1) == MAGIC_VAL_3 &&
					*((u32 *)data_page2) == MAGIC_VAL_2)
				report("EPT basic framework", 1);
			else
				report("EPT basic framework - remap", 1);
		}
	}
	// Test EPT Misconfigurations
	vmx_set_test_stage(1);
	vmcall();
	*((u32 *)data_page1) = MAGIC_VAL_1;
	if (vmx_get_test_stage() != 2) {
		report("EPT misconfigurations", 0);
		goto t1;
	}
	vmx_set_test_stage(2);
	vmcall();
	*((u32 *)data_page1) = MAGIC_VAL_1;
	report("EPT misconfigurations", vmx_get_test_stage() == 3);
t1:
	// Test EPT violation
	vmx_set_test_stage(3);
	vmcall();
	*((u32 *)data_page1) = MAGIC_VAL_1;
	report("EPT violation - page permission", vmx_get_test_stage() == 4);
	// Violation caused by EPT paging structure
	vmx_set_test_stage(4);
	vmcall();
	*((u32 *)data_page1) = MAGIC_VAL_2;
	report("EPT violation - paging structure", vmx_get_test_stage() == 5);

	// MMIO Read/Write
	vmx_set_test_stage(5);
	vmcall();

	*(u32 volatile *)pci_physaddr;
	report("MMIO EPT violation - read", vmx_get_test_stage() == 6);

	*(u32 volatile *)pci_physaddr = MAGIC_VAL_1;
	report("MMIO EPT violation - write", vmx_get_test_stage() == 7);
}

static void ept_main(void)
{
	ept_common();

	// Test EPT access to L1 MMIO
	vmx_set_test_stage(7);
	report("EPT - MMIO access", *((u32 *)0xfee00030UL) == apic_version);

	// Test invalid operand for INVEPT
	vmcall();
	report("EPT - unsupported INVEPT", vmx_get_test_stage() == 8);
}

static bool invept_test(int type, u64 eptp)
{
	bool ret, supported;

	supported = ept_vpid.val & (EPT_CAP_INVEPT_SINGLE >> INVEPT_SINGLE << type);
	ret = invept(type, eptp);

	if (ret == !supported)
		return false;

	if (!supported)
		printf("WARNING: unsupported invept passed!\n");
	else
		printf("WARNING: invept failed!\n");

	return true;
}

static int pml_exit_handler(void)
{
	u16 index, count;
	ulong reason = vmcs_read(EXI_REASON) & 0xff;
	u64 *pmlbuf = pml_log;
	u64 guest_rip = vmcs_read(GUEST_RIP);;
	u64 guest_cr3 = vmcs_read(GUEST_CR3);
	u32 insn_len = vmcs_read(EXI_INST_LEN);

	switch (reason) {
	case VMX_VMCALL:
		switch (vmx_get_test_stage()) {
		case 0:
			index = vmcs_read(GUEST_PML_INDEX);
			for (count = index + 1; count < PML_INDEX; count++) {
				if (pmlbuf[count] == (u64)data_page2) {
					vmx_inc_test_stage();
					clear_ept_ad(pml4, guest_cr3, (unsigned long)data_page2);
					break;
				}
			}
			break;
		case 1:
			index = vmcs_read(GUEST_PML_INDEX);
			/* Keep clearing the dirty bit till a overflow */
			clear_ept_ad(pml4, guest_cr3, (unsigned long)data_page2);
			break;
		default:
			report("unexpected stage, %d.", false,
			       vmx_get_test_stage());
			print_vmexit_info();
			return VMX_TEST_VMEXIT;
		}
		vmcs_write(GUEST_RIP, guest_rip + insn_len);
		return VMX_TEST_RESUME;
	case VMX_PML_FULL:
		vmx_inc_test_stage();
		vmcs_write(GUEST_PML_INDEX, PML_INDEX - 1);
		return VMX_TEST_RESUME;
	default:
		report("Unknown exit reason, %ld", false, reason);
		print_vmexit_info();
	}
	return VMX_TEST_VMEXIT;
}

static int ept_exit_handler_common(bool have_ad)
{
	u64 guest_rip;
	u64 guest_cr3;
	ulong reason;
	u32 insn_len;
	u32 exit_qual;
	static unsigned long data_page1_pte, data_page1_pte_pte, memaddr_pte;

	guest_rip = vmcs_read(GUEST_RIP);
	guest_cr3 = vmcs_read(GUEST_CR3);
	reason = vmcs_read(EXI_REASON) & 0xff;
	insn_len = vmcs_read(EXI_INST_LEN);
	exit_qual = vmcs_read(EXI_QUALIFICATION);
	switch (reason) {
	case VMX_VMCALL:
		switch (vmx_get_test_stage()) {
		case 0:
			check_ept_ad(pml4, guest_cr3,
				     (unsigned long)data_page1,
				     have_ad ? EPT_ACCESS_FLAG : 0,
				     have_ad ? EPT_ACCESS_FLAG | EPT_DIRTY_FLAG : 0);
			check_ept_ad(pml4, guest_cr3,
				     (unsigned long)data_page2,
				     have_ad ? EPT_ACCESS_FLAG | EPT_DIRTY_FLAG : 0,
				     have_ad ? EPT_ACCESS_FLAG | EPT_DIRTY_FLAG : 0);
			clear_ept_ad(pml4, guest_cr3, (unsigned long)data_page1);
			clear_ept_ad(pml4, guest_cr3, (unsigned long)data_page2);
			if (have_ad)
				ept_sync(INVEPT_SINGLE, eptp);;
			if (*((u32 *)data_page1) == MAGIC_VAL_3 &&
					*((u32 *)data_page2) == MAGIC_VAL_2) {
				vmx_inc_test_stage();
				install_ept(pml4, (unsigned long)data_page2,
						(unsigned long)data_page2,
						EPT_RA | EPT_WA | EPT_EA);
			} else
				report("EPT basic framework - write", 0);
			break;
		case 1:
			install_ept(pml4, (unsigned long)data_page1,
 				(unsigned long)data_page1, EPT_WA);
			ept_sync(INVEPT_SINGLE, eptp);
			break;
		case 2:
			install_ept(pml4, (unsigned long)data_page1,
 				(unsigned long)data_page1,
 				EPT_RA | EPT_WA | EPT_EA |
 				(2 << EPT_MEM_TYPE_SHIFT));
			ept_sync(INVEPT_SINGLE, eptp);
			break;
		case 3:
			clear_ept_ad(pml4, guest_cr3, (unsigned long)data_page1);
			TEST_ASSERT(get_ept_pte(pml4, (unsigned long)data_page1,
						1, &data_page1_pte));
			set_ept_pte(pml4, (unsigned long)data_page1, 
				1, data_page1_pte & ~EPT_PRESENT);
			ept_sync(INVEPT_SINGLE, eptp);
			break;
		case 4:
			TEST_ASSERT(get_ept_pte(pml4, (unsigned long)data_page1,
						2, &data_page1_pte));
			data_page1_pte &= PAGE_MASK;
			TEST_ASSERT(get_ept_pte(pml4, data_page1_pte,
						2, &data_page1_pte_pte));
			set_ept_pte(pml4, data_page1_pte, 2,
				data_page1_pte_pte & ~EPT_PRESENT);
			ept_sync(INVEPT_SINGLE, eptp);
			break;
		case 5:
			install_ept(pml4, (unsigned long)pci_physaddr,
				(unsigned long)pci_physaddr, 0);
			ept_sync(INVEPT_SINGLE, eptp);
			break;
		case 7:
			if (!invept_test(0, eptp))
				vmx_inc_test_stage();
			break;
		// Should not reach here
		default:
			report("ERROR - unexpected stage, %d.", false,
			       vmx_get_test_stage());
			print_vmexit_info();
			return VMX_TEST_VMEXIT;
		}
		vmcs_write(GUEST_RIP, guest_rip + insn_len);
		return VMX_TEST_RESUME;
	case VMX_EPT_MISCONFIG:
		switch (vmx_get_test_stage()) {
		case 1:
		case 2:
			vmx_inc_test_stage();
			install_ept(pml4, (unsigned long)data_page1,
 				(unsigned long)data_page1,
 				EPT_RA | EPT_WA | EPT_EA);
			ept_sync(INVEPT_SINGLE, eptp);
			break;
		// Should not reach here
		default:
			report("ERROR - unexpected stage, %d.", false,
			       vmx_get_test_stage());
			print_vmexit_info();
			return VMX_TEST_VMEXIT;
		}
		return VMX_TEST_RESUME;
	case VMX_EPT_VIOLATION:
		switch(vmx_get_test_stage()) {
		case 3:
			check_ept_ad(pml4, guest_cr3, (unsigned long)data_page1, 0,
				     have_ad ? EPT_ACCESS_FLAG | EPT_DIRTY_FLAG : 0);
			clear_ept_ad(pml4, guest_cr3, (unsigned long)data_page1);
			if (exit_qual == (EPT_VLT_WR | EPT_VLT_LADDR_VLD |
					EPT_VLT_PADDR))
				vmx_inc_test_stage();
			set_ept_pte(pml4, (unsigned long)data_page1,
				1, data_page1_pte | (EPT_PRESENT));
			ept_sync(INVEPT_SINGLE, eptp);
			break;
		case 4:
			check_ept_ad(pml4, guest_cr3, (unsigned long)data_page1, 0,
				     have_ad ? EPT_ACCESS_FLAG | EPT_DIRTY_FLAG : 0);
			clear_ept_ad(pml4, guest_cr3, (unsigned long)data_page1);
			if (exit_qual == (EPT_VLT_RD |
					  (have_ad ? EPT_VLT_WR : 0) |
					  EPT_VLT_LADDR_VLD))
				vmx_inc_test_stage();
			set_ept_pte(pml4, data_page1_pte, 2,
				data_page1_pte_pte | (EPT_PRESENT));
			ept_sync(INVEPT_SINGLE, eptp);
			break;
		case 5:
			if (exit_qual & EPT_VLT_RD)
				vmx_inc_test_stage();
			TEST_ASSERT(get_ept_pte(pml4, (unsigned long)pci_physaddr,
						1, &memaddr_pte));
			set_ept_pte(pml4, memaddr_pte, 1, memaddr_pte | EPT_RA);
			ept_sync(INVEPT_SINGLE, eptp);
			break;
		case 6:
			if (exit_qual & EPT_VLT_WR)
				vmx_inc_test_stage();
			TEST_ASSERT(get_ept_pte(pml4, (unsigned long)pci_physaddr,
						1, &memaddr_pte));
			set_ept_pte(pml4, memaddr_pte, 1, memaddr_pte | EPT_RA | EPT_WA);
			ept_sync(INVEPT_SINGLE, eptp);
			break;
		default:
			// Should not reach here
			report("ERROR : unexpected stage, %d", false,
			       vmx_get_test_stage());
			print_vmexit_info();
			return VMX_TEST_VMEXIT;
		}
		return VMX_TEST_RESUME;
	default:
		report("Unknown exit reason, %ld", false, reason);
		print_vmexit_info();
	}
	return VMX_TEST_VMEXIT;
}

static int ept_exit_handler(void)
{
	return ept_exit_handler_common(false);
}

static int eptad_init(struct vmcs *vmcs)
{
	int r = ept_init_common(true);

	if (r == VMX_TEST_EXIT)
		return r;

	if ((rdmsr(MSR_IA32_VMX_EPT_VPID_CAP) & EPT_CAP_AD_FLAG) == 0) {
		printf("\tEPT A/D bits are not supported");
		return VMX_TEST_EXIT;
	}

	return r;
}

static int pml_init(struct vmcs *vmcs)
{
	u32 ctrl_cpu;
	int r = eptad_init(vmcs);

	if (r == VMX_TEST_EXIT)
		return r;

	if (!(ctrl_cpu_rev[0].clr & CPU_SECONDARY) ||
		!(ctrl_cpu_rev[1].clr & CPU_PML)) {
		printf("\tPML is not supported");
		return VMX_TEST_EXIT;
	}

	pml_log = alloc_page();
	memset(pml_log, 0x0, PAGE_SIZE);
	vmcs_write(PMLADDR, (u64)pml_log);
	vmcs_write(GUEST_PML_INDEX, PML_INDEX - 1);

	ctrl_cpu = vmcs_read(CPU_EXEC_CTRL1) | CPU_PML;
	vmcs_write(CPU_EXEC_CTRL1, ctrl_cpu);

	return VMX_TEST_START;
}

static void pml_main(void)
{
	int count = 0;

	vmx_set_test_stage(0);
	*((u32 *)data_page2) = 0x1;
	vmcall();
	report("PML - Dirty GPA Logging", vmx_get_test_stage() == 1);

	while (vmx_get_test_stage() == 1) {
		vmcall();
		*((u32 *)data_page2) = 0x1;
		if (count++ > PML_INDEX)
			break;
	}
	report("PML Full Event", vmx_get_test_stage() == 2);
}

static void eptad_main(void)
{
	ept_common();
}

static int eptad_exit_handler(void)
{
	return ept_exit_handler_common(true);
}

static bool invvpid_test(int type, u16 vpid)
{
	bool ret, supported;

	supported = ept_vpid.val &
		(VPID_CAP_INVVPID_ADDR >> INVVPID_ADDR << type);
	ret = invvpid(type, vpid, 0);

	if (ret == !supported)
		return false;

	if (!supported)
		printf("WARNING: unsupported invvpid passed!\n");
	else
		printf("WARNING: invvpid failed!\n");

	return true;
}

static int vpid_init(struct vmcs *vmcs)
{
	u32 ctrl_cpu1;

	if (!(ctrl_cpu_rev[0].clr & CPU_SECONDARY) ||
		!(ctrl_cpu_rev[1].clr & CPU_VPID)) {
		printf("\tVPID is not supported");
		return VMX_TEST_EXIT;
	}

	ctrl_cpu1 = vmcs_read(CPU_EXEC_CTRL1);
	ctrl_cpu1 |= CPU_VPID;
	vmcs_write(CPU_EXEC_CTRL1, ctrl_cpu1);
	return VMX_TEST_START;
}

static void vpid_main(void)
{
	vmx_set_test_stage(0);
	vmcall();
	report("INVVPID SINGLE ADDRESS", vmx_get_test_stage() == 1);
	vmx_set_test_stage(2);
	vmcall();
	report("INVVPID SINGLE", vmx_get_test_stage() == 3);
	vmx_set_test_stage(4);
	vmcall();
	report("INVVPID ALL", vmx_get_test_stage() == 5);
}

static int vpid_exit_handler(void)
{
	u64 guest_rip;
	ulong reason;
	u32 insn_len;

	guest_rip = vmcs_read(GUEST_RIP);
	reason = vmcs_read(EXI_REASON) & 0xff;
	insn_len = vmcs_read(EXI_INST_LEN);

	switch (reason) {
	case VMX_VMCALL:
		switch(vmx_get_test_stage()) {
		case 0:
			if (!invvpid_test(INVVPID_ADDR, 1))
				vmx_inc_test_stage();
			break;
		case 2:
			if (!invvpid_test(INVVPID_CONTEXT_GLOBAL, 1))
				vmx_inc_test_stage();
			break;
		case 4:
			if (!invvpid_test(INVVPID_ALL, 1))
				vmx_inc_test_stage();
			break;
		default:
			report("ERROR: unexpected stage, %d", false,
					vmx_get_test_stage());
			print_vmexit_info();
			return VMX_TEST_VMEXIT;
		}
		vmcs_write(GUEST_RIP, guest_rip + insn_len);
		return VMX_TEST_RESUME;
	default:
		report("Unknown exit reason, %ld", false, reason);
		print_vmexit_info();
	}
	return VMX_TEST_VMEXIT;
}

#define TIMER_VECTOR	222

static volatile bool timer_fired;

static void timer_isr(isr_regs_t *regs)
{
	timer_fired = true;
	apic_write(APIC_EOI, 0);
}

static int interrupt_init(struct vmcs *vmcs)
{
	msr_bmp_init();
	vmcs_write(PIN_CONTROLS, vmcs_read(PIN_CONTROLS) & ~PIN_EXTINT);
	handle_irq(TIMER_VECTOR, timer_isr);
	return VMX_TEST_START;
}

static void interrupt_main(void)
{
	long long start, loops;

	vmx_set_test_stage(0);

	apic_write(APIC_LVTT, TIMER_VECTOR);
	irq_enable();

	apic_write(APIC_TMICT, 1);
	for (loops = 0; loops < 10000000 && !timer_fired; loops++)
		asm volatile ("nop");
	report("direct interrupt while running guest", timer_fired);

	apic_write(APIC_TMICT, 0);
	irq_disable();
	vmcall();
	timer_fired = false;
	apic_write(APIC_TMICT, 1);
	for (loops = 0; loops < 10000000 && !timer_fired; loops++)
		asm volatile ("nop");
	report("intercepted interrupt while running guest", timer_fired);

	irq_enable();
	apic_write(APIC_TMICT, 0);
	irq_disable();
	vmcall();
	timer_fired = false;
	start = rdtsc();
	apic_write(APIC_TMICT, 1000000);

	asm volatile ("sti; hlt");

	report("direct interrupt + hlt",
	       rdtsc() - start > 1000000 && timer_fired);

	apic_write(APIC_TMICT, 0);
	irq_disable();
	vmcall();
	timer_fired = false;
	start = rdtsc();
	apic_write(APIC_TMICT, 1000000);

	asm volatile ("sti; hlt");

	report("intercepted interrupt + hlt",
	       rdtsc() - start > 10000 && timer_fired);

	apic_write(APIC_TMICT, 0);
	irq_disable();
	vmcall();
	timer_fired = false;
	start = rdtsc();
	apic_write(APIC_TMICT, 1000000);

	irq_enable();
	asm volatile ("nop");
	vmcall();

	report("direct interrupt + activity state hlt",
	       rdtsc() - start > 10000 && timer_fired);

	apic_write(APIC_TMICT, 0);
	irq_disable();
	vmcall();
	timer_fired = false;
	start = rdtsc();
	apic_write(APIC_TMICT, 1000000);

	irq_enable();
	asm volatile ("nop");
	vmcall();

	report("intercepted interrupt + activity state hlt",
	       rdtsc() - start > 10000 && timer_fired);

	apic_write(APIC_TMICT, 0);
	irq_disable();
	vmx_set_test_stage(7);
	vmcall();
	timer_fired = false;
	apic_write(APIC_TMICT, 1);
	for (loops = 0; loops < 10000000 && !timer_fired; loops++)
		asm volatile ("nop");
	report("running a guest with interrupt acknowledgement set", timer_fired);

	apic_write(APIC_TMICT, 0);
	irq_enable();
	timer_fired = false;
	vmcall();
	report("Inject an event to a halted guest", timer_fired);
}

static int interrupt_exit_handler(void)
{
	u64 guest_rip = vmcs_read(GUEST_RIP);
	ulong reason = vmcs_read(EXI_REASON) & 0xff;
	u32 insn_len = vmcs_read(EXI_INST_LEN);

	switch (reason) {
	case VMX_VMCALL:
		switch (vmx_get_test_stage()) {
		case 0:
		case 2:
		case 5:
			vmcs_write(PIN_CONTROLS,
				   vmcs_read(PIN_CONTROLS) | PIN_EXTINT);
			break;
		case 7:
			vmcs_write(EXI_CONTROLS, vmcs_read(EXI_CONTROLS) | EXI_INTA);
			vmcs_write(PIN_CONTROLS,
				   vmcs_read(PIN_CONTROLS) | PIN_EXTINT);
			break;
		case 1:
		case 3:
			vmcs_write(PIN_CONTROLS,
				   vmcs_read(PIN_CONTROLS) & ~PIN_EXTINT);
			break;
		case 4:
		case 6:
			vmcs_write(GUEST_ACTV_STATE, ACTV_HLT);
			break;

		case 8:
			vmcs_write(GUEST_ACTV_STATE, ACTV_HLT);
			vmcs_write(ENT_INTR_INFO,
				   TIMER_VECTOR |
				   (VMX_INTR_TYPE_EXT_INTR << INTR_INFO_INTR_TYPE_SHIFT) |
				   INTR_INFO_VALID_MASK);
			break;
		}
		vmx_inc_test_stage();
		vmcs_write(GUEST_RIP, guest_rip + insn_len);
		return VMX_TEST_RESUME;
	case VMX_EXTINT:
		if (vmcs_read(EXI_CONTROLS) & EXI_INTA) {
			int vector = vmcs_read(EXI_INTR_INFO) & 0xff;
			handle_external_interrupt(vector);
		} else {
			irq_enable();
			asm volatile ("nop");
			irq_disable();
		}
		if (vmx_get_test_stage() >= 2)
			vmcs_write(GUEST_ACTV_STATE, ACTV_ACTIVE);
		return VMX_TEST_RESUME;
	default:
		report("Unknown exit reason, %ld", false, reason);
		print_vmexit_info();
	}

	return VMX_TEST_VMEXIT;
}

static int dbgctls_init(struct vmcs *vmcs)
{
	u64 dr7 = 0x402;
	u64 zero = 0;

	msr_bmp_init();
	asm volatile(
		"mov %0,%%dr0\n\t"
		"mov %0,%%dr1\n\t"
		"mov %0,%%dr2\n\t"
		"mov %1,%%dr7\n\t"
		: : "r" (zero), "r" (dr7));
	wrmsr(MSR_IA32_DEBUGCTLMSR, 0x1);
	vmcs_write(GUEST_DR7, 0x404);
	vmcs_write(GUEST_DEBUGCTL, 0x2);

	vmcs_write(ENT_CONTROLS, vmcs_read(ENT_CONTROLS) | ENT_LOAD_DBGCTLS);
	vmcs_write(EXI_CONTROLS, vmcs_read(EXI_CONTROLS) | EXI_SAVE_DBGCTLS);

	return VMX_TEST_START;
}

static void dbgctls_main(void)
{
	u64 dr7, debugctl;

	asm volatile("mov %%dr7,%0" : "=r" (dr7));
	debugctl = rdmsr(MSR_IA32_DEBUGCTLMSR);
	/* Commented out: KVM does not support DEBUGCTL so far */
	(void)debugctl;
	report("Load debug controls", dr7 == 0x404 /* && debugctl == 0x2 */);

	dr7 = 0x408;
	asm volatile("mov %0,%%dr7" : : "r" (dr7));
	wrmsr(MSR_IA32_DEBUGCTLMSR, 0x3);

	vmx_set_test_stage(0);
	vmcall();
	report("Save debug controls", vmx_get_test_stage() == 1);

	if (ctrl_enter_rev.set & ENT_LOAD_DBGCTLS ||
	    ctrl_exit_rev.set & EXI_SAVE_DBGCTLS) {
		printf("\tDebug controls are always loaded/saved\n");
		return;
	}
	vmx_set_test_stage(2);
	vmcall();

	asm volatile("mov %%dr7,%0" : "=r" (dr7));
	debugctl = rdmsr(MSR_IA32_DEBUGCTLMSR);
	/* Commented out: KVM does not support DEBUGCTL so far */
	(void)debugctl;
	report("Guest=host debug controls", dr7 == 0x402 /* && debugctl == 0x1 */);

	dr7 = 0x408;
	asm volatile("mov %0,%%dr7" : : "r" (dr7));
	wrmsr(MSR_IA32_DEBUGCTLMSR, 0x3);

	vmx_set_test_stage(3);
	vmcall();
	report("Don't save debug controls", vmx_get_test_stage() == 4);
}

static int dbgctls_exit_handler(void)
{
	unsigned int reason = vmcs_read(EXI_REASON) & 0xff;
	u32 insn_len = vmcs_read(EXI_INST_LEN);
	u64 guest_rip = vmcs_read(GUEST_RIP);
	u64 dr7, debugctl;

	asm volatile("mov %%dr7,%0" : "=r" (dr7));
	debugctl = rdmsr(MSR_IA32_DEBUGCTLMSR);

	switch (reason) {
	case VMX_VMCALL:
		switch (vmx_get_test_stage()) {
		case 0:
			if (dr7 == 0x400 && debugctl == 0 &&
			    vmcs_read(GUEST_DR7) == 0x408 /* &&
			    Commented out: KVM does not support DEBUGCTL so far
			    vmcs_read(GUEST_DEBUGCTL) == 0x3 */)
				vmx_inc_test_stage();
			break;
		case 2:
			dr7 = 0x402;
			asm volatile("mov %0,%%dr7" : : "r" (dr7));
			wrmsr(MSR_IA32_DEBUGCTLMSR, 0x1);
			vmcs_write(GUEST_DR7, 0x404);
			vmcs_write(GUEST_DEBUGCTL, 0x2);

			vmcs_write(ENT_CONTROLS,
				vmcs_read(ENT_CONTROLS) & ~ENT_LOAD_DBGCTLS);
			vmcs_write(EXI_CONTROLS,
				vmcs_read(EXI_CONTROLS) & ~EXI_SAVE_DBGCTLS);
			break;
		case 3:
			if (dr7 == 0x400 && debugctl == 0 &&
			    vmcs_read(GUEST_DR7) == 0x404 /* &&
			    Commented out: KVM does not support DEBUGCTL so far
			    vmcs_read(GUEST_DEBUGCTL) == 0x2 */)
				vmx_inc_test_stage();
			break;
		}
		vmcs_write(GUEST_RIP, guest_rip + insn_len);
		return VMX_TEST_RESUME;
	default:
		report("Unknown exit reason, %d", false, reason);
		print_vmexit_info();
	}
	return VMX_TEST_VMEXIT;
}

struct vmx_msr_entry {
	u32 index;
	u32 reserved;
	u64 value;
} __attribute__((packed));

#define MSR_MAGIC 0x31415926
struct vmx_msr_entry *exit_msr_store, *entry_msr_load, *exit_msr_load;

static int msr_switch_init(struct vmcs *vmcs)
{
	msr_bmp_init();
	exit_msr_store = alloc_page();
	exit_msr_load = alloc_page();
	entry_msr_load = alloc_page();
	memset(exit_msr_store, 0, PAGE_SIZE);
	memset(exit_msr_load, 0, PAGE_SIZE);
	memset(entry_msr_load, 0, PAGE_SIZE);
	entry_msr_load[0].index = MSR_KERNEL_GS_BASE;
	entry_msr_load[0].value = MSR_MAGIC;

	vmx_set_test_stage(1);
	vmcs_write(ENT_MSR_LD_CNT, 1);
	vmcs_write(ENTER_MSR_LD_ADDR, (u64)entry_msr_load);
	vmcs_write(EXI_MSR_ST_CNT, 1);
	vmcs_write(EXIT_MSR_ST_ADDR, (u64)exit_msr_store);
	vmcs_write(EXI_MSR_LD_CNT, 1);
	vmcs_write(EXIT_MSR_LD_ADDR, (u64)exit_msr_load);
	return VMX_TEST_START;
}

static void msr_switch_main(void)
{
	if (vmx_get_test_stage() == 1) {
		report("VM entry MSR load",
			rdmsr(MSR_KERNEL_GS_BASE) == MSR_MAGIC);
		vmx_set_test_stage(2);
		wrmsr(MSR_KERNEL_GS_BASE, MSR_MAGIC + 1);
		exit_msr_store[0].index = MSR_KERNEL_GS_BASE;
		exit_msr_load[0].index = MSR_KERNEL_GS_BASE;
		exit_msr_load[0].value = MSR_MAGIC + 2;
	}
	vmcall();
}

static int msr_switch_exit_handler(void)
{
	ulong reason;

	reason = vmcs_read(EXI_REASON);
	if (reason == VMX_VMCALL && vmx_get_test_stage() == 2) {
		report("VM exit MSR store",
			exit_msr_store[0].value == MSR_MAGIC + 1);
		report("VM exit MSR load",
			rdmsr(MSR_KERNEL_GS_BASE) == MSR_MAGIC + 2);
		vmx_set_test_stage(3);
		entry_msr_load[0].index = MSR_FS_BASE;
		return VMX_TEST_RESUME;
	}
	printf("ERROR %s: unexpected stage=%u or reason=%lu\n",
		__func__, vmx_get_test_stage(), reason);
	return VMX_TEST_EXIT;
}

static int msr_switch_entry_failure(struct vmentry_failure *failure)
{
	ulong reason;

	if (failure->early) {
		printf("ERROR %s: early exit\n", __func__);
		return VMX_TEST_EXIT;
	}

	reason = vmcs_read(EXI_REASON);
	if (reason == (VMX_ENTRY_FAILURE | VMX_FAIL_MSR) &&
	    vmx_get_test_stage() == 3) {
		report("VM entry MSR load: try to load FS_BASE",
			vmcs_read(EXI_QUALIFICATION) == 1);
		return VMX_TEST_VMEXIT;
	}
	printf("ERROR %s: unexpected stage=%u or reason=%lu\n",
		__func__, vmx_get_test_stage(), reason);
	return VMX_TEST_EXIT;
}

static int vmmcall_init(struct vmcs *vmcs)
{
	vmcs_write(EXC_BITMAP, 1 << UD_VECTOR);
	return VMX_TEST_START;
}

static void vmmcall_main(void)
{
	asm volatile(
		"mov $0xABCD, %%rax\n\t"
		"vmmcall\n\t"
		::: "rax");

	report("VMMCALL", 0);
}

static int vmmcall_exit_handler(void)
{
	ulong reason;

	reason = vmcs_read(EXI_REASON);
	switch (reason) {
	case VMX_VMCALL:
		printf("here\n");
		report("VMMCALL triggers #UD", 0);
		break;
	case VMX_EXC_NMI:
		report("VMMCALL triggers #UD",
		       (vmcs_read(EXI_INTR_INFO) & 0xff) == UD_VECTOR);
		break;
	default:
		report("Unknown exit reason, %ld", false, reason);
		print_vmexit_info();
	}

	return VMX_TEST_VMEXIT;
}

static int disable_rdtscp_init(struct vmcs *vmcs)
{
	u32 ctrl_cpu1;

	if (ctrl_cpu_rev[0].clr & CPU_SECONDARY) {
		ctrl_cpu1 = vmcs_read(CPU_EXEC_CTRL1);
		ctrl_cpu1 &= ~CPU_RDTSCP;
		vmcs_write(CPU_EXEC_CTRL1, ctrl_cpu1);
	}

	return VMX_TEST_START;
}

static void disable_rdtscp_ud_handler(struct ex_regs *regs)
{
	switch (vmx_get_test_stage()) {
	case 0:
		report("RDTSCP triggers #UD", true);
		vmx_inc_test_stage();
		regs->rip += 3;
		break;
	case 2:
		report("RDPID triggers #UD", true);
		vmx_inc_test_stage();
		regs->rip += 4;
		break;
	}
	return;

}

static void disable_rdtscp_main(void)
{
	/* Test that #UD is properly injected in L2.  */
	handle_exception(UD_VECTOR, disable_rdtscp_ud_handler);

	vmx_set_test_stage(0);
	asm volatile("rdtscp" : : : "eax", "ecx", "edx");
	vmcall();
	asm volatile(".byte 0xf3, 0x0f, 0xc7, 0xf8" : : : "eax");

	handle_exception(UD_VECTOR, 0);
	vmcall();
}

static int disable_rdtscp_exit_handler(void)
{
	unsigned int reason = vmcs_read(EXI_REASON) & 0xff;

	switch (reason) {
	case VMX_VMCALL:
		switch (vmx_get_test_stage()) {
		case 0:
			report("RDTSCP triggers #UD", false);
			vmx_inc_test_stage();
			/* fallthrough */
		case 1:
			vmx_inc_test_stage();
			vmcs_write(GUEST_RIP, vmcs_read(GUEST_RIP) + 3);
			return VMX_TEST_RESUME;
		case 2:
			report("RDPID triggers #UD", false);
			break;
		}
		break;

	default:
		report("Unknown exit reason, %d", false, reason);
		print_vmexit_info();
	}
	return VMX_TEST_VMEXIT;
}

static int int3_init(struct vmcs *vmcs)
{
	vmcs_write(EXC_BITMAP, ~0u);
	return VMX_TEST_START;
}

static void int3_guest_main(void)
{
	asm volatile ("int3");
}

static int int3_exit_handler(void)
{
	u32 reason = vmcs_read(EXI_REASON);
	u32 intr_info = vmcs_read(EXI_INTR_INFO);

	report("L1 intercepts #BP", reason == VMX_EXC_NMI &&
	       (intr_info & INTR_INFO_VALID_MASK) &&
	       (intr_info & INTR_INFO_VECTOR_MASK) == BP_VECTOR &&
	       ((intr_info & INTR_INFO_INTR_TYPE_MASK) >>
		INTR_INFO_INTR_TYPE_SHIFT) == VMX_INTR_TYPE_SOFT_EXCEPTION);

	return VMX_TEST_VMEXIT;
}

static int into_init(struct vmcs *vmcs)
{
	vmcs_write(EXC_BITMAP, ~0u);
	return VMX_TEST_START;
}

static void into_guest_main(void)
{
	struct far_pointer32 fp = {
		.offset = (uintptr_t)&&into,
		.selector = KERNEL_CS32,
	};
	register uintptr_t rsp asm("rsp");

	if (fp.offset != (uintptr_t)&&into) {
		printf("Code address too high.\n");
		return;
	}
	if ((u32)rsp != rsp) {
		printf("Stack address too high.\n");
		return;
	}

	asm goto ("lcall *%0" : : "m" (fp) : "rax" : into);
	return;
into:
	asm volatile (".code32;"
		      "movl $0x7fffffff, %eax;"
		      "addl %eax, %eax;"
		      "into;"
		      "lret;"
		      ".code64");
	__builtin_unreachable();
}

static int into_exit_handler(void)
{
	u32 reason = vmcs_read(EXI_REASON);
	u32 intr_info = vmcs_read(EXI_INTR_INFO);

	report("L1 intercepts #OF", reason == VMX_EXC_NMI &&
	       (intr_info & INTR_INFO_VALID_MASK) &&
	       (intr_info & INTR_INFO_VECTOR_MASK) == OF_VECTOR &&
	       ((intr_info & INTR_INFO_INTR_TYPE_MASK) >>
		INTR_INFO_INTR_TYPE_SHIFT) == VMX_INTR_TYPE_SOFT_EXCEPTION);

	return VMX_TEST_VMEXIT;
}

static void exit_monitor_from_l2_main(void)
{
	printf("Calling exit(0) from l2...\n");
	exit(0);
}

static int exit_monitor_from_l2_handler(void)
{
	report("The guest should have killed the VMM", false);
	return VMX_TEST_EXIT;
}

static void assert_exit_reason(u64 expected)
{
	u64 actual = vmcs_read(EXI_REASON);

	TEST_ASSERT_EQ_MSG(expected, actual, "Expected %s, got %s.",
			   exit_reason_description(expected),
			   exit_reason_description(actual));
}

static void skip_exit_insn(void)
{
	u64 guest_rip = vmcs_read(GUEST_RIP);
	u32 insn_len = vmcs_read(EXI_INST_LEN);
	vmcs_write(GUEST_RIP, guest_rip + insn_len);
}

static void skip_exit_vmcall(void)
{
	assert_exit_reason(VMX_VMCALL);
	skip_exit_insn();
}

static void v2_null_test_guest(void)
{
}

static void v2_null_test(void)
{
	test_set_guest(v2_null_test_guest);
	enter_guest();
	report(__func__, 1);
}

static void v2_multiple_entries_test_guest(void)
{
	vmx_set_test_stage(1);
	vmcall();
	vmx_set_test_stage(2);
}

static void v2_multiple_entries_test(void)
{
	test_set_guest(v2_multiple_entries_test_guest);
	enter_guest();
	TEST_ASSERT_EQ(vmx_get_test_stage(), 1);
	skip_exit_vmcall();
	enter_guest();
	TEST_ASSERT_EQ(vmx_get_test_stage(), 2);
	report(__func__, 1);
}

static int fixture_test_data = 1;

static void fixture_test_teardown(void *data)
{
	*((int *) data) = 1;
}

static void fixture_test_guest(void)
{
	fixture_test_data++;
}


static void fixture_test_setup(void)
{
	TEST_ASSERT_EQ_MSG(1, fixture_test_data,
			   "fixture_test_teardown didn't run?!");
	fixture_test_data = 2;
	test_add_teardown(fixture_test_teardown, &fixture_test_data);
	test_set_guest(fixture_test_guest);
}

static void fixture_test_case1(void)
{
	fixture_test_setup();
	TEST_ASSERT_EQ(2, fixture_test_data);
	enter_guest();
	TEST_ASSERT_EQ(3, fixture_test_data);
	report(__func__, 1);
}

static void fixture_test_case2(void)
{
	fixture_test_setup();
	TEST_ASSERT_EQ(2, fixture_test_data);
	enter_guest();
	TEST_ASSERT_EQ(3, fixture_test_data);
	report(__func__, 1);
}

enum ept_access_op {
	OP_READ,
	OP_WRITE,
	OP_EXEC,
	OP_FLUSH_TLB,
	OP_EXIT,
};

static struct ept_access_test_data {
	unsigned long gpa;
	unsigned long *gva;
	unsigned long hpa;
	unsigned long *hva;
	enum ept_access_op op;
} ept_access_test_data;

extern unsigned char ret42_start;
extern unsigned char ret42_end;

/* Returns 42. */
asm(
	".align 64\n"
	"ret42_start:\n"
	"mov $42, %eax\n"
	"ret\n"
	"ret42_end:\n"
);

static void
diagnose_ept_violation_qual(u64 expected, u64 actual)
{

#define DIAGNOSE(flag)							\
do {									\
	if ((expected & flag) != (actual & flag))			\
		printf(#flag " %sexpected\n",				\
		       (expected & flag) ? "" : "un");			\
} while (0)

	DIAGNOSE(EPT_VLT_RD);
	DIAGNOSE(EPT_VLT_WR);
	DIAGNOSE(EPT_VLT_FETCH);
	DIAGNOSE(EPT_VLT_PERM_RD);
	DIAGNOSE(EPT_VLT_PERM_WR);
	DIAGNOSE(EPT_VLT_PERM_EX);
	DIAGNOSE(EPT_VLT_LADDR_VLD);
	DIAGNOSE(EPT_VLT_PADDR);

#undef DIAGNOSE
}

static void do_ept_access_op(enum ept_access_op op)
{
	ept_access_test_data.op = op;
	enter_guest();
}

/*
 * Force the guest to flush its TLB (i.e., flush gva -> gpa mappings). Only
 * needed by tests that modify guest PTEs.
 */
static void ept_access_test_guest_flush_tlb(void)
{
	do_ept_access_op(OP_FLUSH_TLB);
	skip_exit_vmcall();
}

/*
 * Modifies the EPT entry at @level in the mapping of @gpa. First clears the
 * bits in @clear then sets the bits in @set. @mkhuge transforms the entry into
 * a huge page.
 */
static unsigned long ept_twiddle(unsigned long gpa, bool mkhuge, int level,
				 unsigned long clear, unsigned long set)
{
	struct ept_access_test_data *data = &ept_access_test_data;
	unsigned long orig_pte;
	unsigned long pte;

	/* Screw with the mapping at the requested level. */
	TEST_ASSERT(get_ept_pte(pml4, gpa, level, &orig_pte));
	pte = orig_pte;
	if (mkhuge)
		pte = (orig_pte & ~EPT_ADDR_MASK) | data->hpa | EPT_LARGE_PAGE;
	else
		pte = orig_pte;
	pte = (pte & ~clear) | set;
	set_ept_pte(pml4, gpa, level, pte);
	ept_sync(INVEPT_SINGLE, eptp);

	return orig_pte;
}

static void ept_untwiddle(unsigned long gpa, int level, unsigned long orig_pte)
{
	set_ept_pte(pml4, gpa, level, orig_pte);
}

static void do_ept_violation(bool leaf, enum ept_access_op op,
			     u64 expected_qual, u64 expected_paddr)
{
	u64 qual;

	/* Try the access and observe the violation. */
	do_ept_access_op(op);

	assert_exit_reason(VMX_EPT_VIOLATION);

	qual = vmcs_read(EXI_QUALIFICATION);

	diagnose_ept_violation_qual(expected_qual, qual);
	TEST_EXPECT_EQ(expected_qual, qual);

	#if 0
	/* Disable for now otherwise every test will fail */
	TEST_EXPECT_EQ(vmcs_read(GUEST_LINEAR_ADDRESS),
		       (unsigned long) (
			       op == OP_EXEC ? data->gva + 1 : data->gva));
	#endif
	/*
	 * TODO: tests that probe expected_paddr in pages other than the one at
	 * the beginning of the 1g region.
	 */
	TEST_EXPECT_EQ(vmcs_read(INFO_PHYS_ADDR), expected_paddr);
}

static void
ept_violation_at_level_mkhuge(bool mkhuge, int level, unsigned long clear,
			      unsigned long set, enum ept_access_op op,
			      u64 expected_qual)
{
	struct ept_access_test_data *data = &ept_access_test_data;
	unsigned long orig_pte;

	orig_pte = ept_twiddle(data->gpa, mkhuge, level, clear, set);

	do_ept_violation(level == 1 || mkhuge, op, expected_qual,
			 op == OP_EXEC ? data->gpa + sizeof(unsigned long) :
					 data->gpa);

	/* Fix the violation and resume the op loop. */
	ept_untwiddle(data->gpa, level, orig_pte);
	enter_guest();
	skip_exit_vmcall();
}

static void
ept_violation_at_level(int level, unsigned long clear, unsigned long set,
		       enum ept_access_op op, u64 expected_qual)
{
	ept_violation_at_level_mkhuge(false, level, clear, set, op,
				      expected_qual);
	if (ept_huge_pages_supported(level))
		ept_violation_at_level_mkhuge(true, level, clear, set, op,
					      expected_qual);
}

static void ept_violation(unsigned long clear, unsigned long set,
			  enum ept_access_op op, u64 expected_qual)
{
	ept_violation_at_level(1, clear, set, op, expected_qual);
	ept_violation_at_level(2, clear, set, op, expected_qual);
	ept_violation_at_level(3, clear, set, op, expected_qual);
	ept_violation_at_level(4, clear, set, op, expected_qual);
}

static void ept_access_violation(unsigned long access, enum ept_access_op op,
				       u64 expected_qual)
{
	ept_violation(EPT_PRESENT, access, op,
		      expected_qual | EPT_VLT_LADDR_VLD | EPT_VLT_PADDR);
}

/*
 * For translations that don't involve a GVA, that is physical address (paddr)
 * accesses, EPT violations don't set the flag EPT_VLT_PADDR.  For a typical
 * guest memory access, the hardware does GVA -> GPA -> HPA.  However, certain
 * translations don't involve GVAs, such as when the hardware does the guest
 * page table walk. For example, in translating GVA_1 -> GPA_1, the guest MMU
 * might try to set an A bit on a guest PTE. If the GPA_2 that the PTE resides
 * on isn't present in the EPT, then the EPT violation will be for GPA_2 and
 * the EPT_VLT_PADDR bit will be clear in the exit qualification.
 *
 * Note that paddr violations can also be triggered by loading PAE page tables
 * with wonky addresses. We don't test that yet.
 *
 * This function modifies the EPT entry that maps the GPA that the guest page
 * table entry mapping ept_access_data.gva resides on.
 *
 *	@ept_access	EPT permissions to set. Other permissions are cleared.
 *
 *	@pte_ad		Set the A/D bits on the guest PTE accordingly.
 *
 *	@op		Guest operation to perform with ept_access_data.gva.
 *
 *	@expect_violation
 *			Is a violation expected during the paddr access?
 *
 *	@expected_qual	Expected qualification for the EPT violation.
 *			EPT_VLT_PADDR should be clear.
 */
static void ept_access_paddr(unsigned long ept_access, unsigned long pte_ad,
			     enum ept_access_op op, bool expect_violation,
			     u64 expected_qual)
{
	struct ept_access_test_data *data = &ept_access_test_data;
	unsigned long *ptep;
	unsigned long gpa;
	unsigned long orig_epte;

	/* Modify the guest PTE mapping data->gva according to @pte_ad.  */
	ptep = get_pte_level(current_page_table(), data->gva, /*level=*/1);
	TEST_ASSERT(ptep);
	TEST_ASSERT_EQ(*ptep & PT_ADDR_MASK, data->gpa);
	*ptep = (*ptep & ~PT_AD_MASK) | pte_ad;
	ept_access_test_guest_flush_tlb();

	/*
	 * Now modify the access bits on the EPT entry for the GPA that the
	 * guest PTE resides on. Note that by modifying a single EPT entry,
	 * we're potentially affecting 512 guest PTEs. However, we've carefully
	 * constructed our test such that those other 511 PTEs aren't used by
	 * the guest: data->gva is at the beginning of a 1G huge page, thus the
	 * PTE we're modifying is at the beginning of a 4K page and the
	 * following 511 entires are also under our control (and not touched by
	 * the guest).
	 */
	gpa = virt_to_phys(ptep);
	TEST_ASSERT_EQ(gpa & ~PAGE_MASK, 0);
	/*
	 * Make sure the guest page table page is mapped with a 4K EPT entry,
	 * otherwise our level=1 twiddling below will fail. We use the
	 * identity map (gpa = gpa) since page tables are shared with the host.
	 */
	install_ept(pml4, gpa, gpa, EPT_PRESENT);
	orig_epte = ept_twiddle(gpa, /*mkhuge=*/0, /*level=*/1,
				/*clear=*/EPT_PRESENT, /*set=*/ept_access);

	if (expect_violation) {
		do_ept_violation(/*leaf=*/true, op,
				 expected_qual | EPT_VLT_LADDR_VLD, gpa);
		ept_untwiddle(gpa, /*level=*/1, orig_epte);
		do_ept_access_op(op);
	} else {
		do_ept_access_op(op);
		ept_untwiddle(gpa, /*level=*/1, orig_epte);
	}

	TEST_ASSERT(*ptep & PT_ACCESSED_MASK);
	if ((pte_ad & PT_DIRTY_MASK) || op == OP_WRITE)
		TEST_ASSERT(*ptep & PT_DIRTY_MASK);

	skip_exit_vmcall();
}

static void ept_access_allowed_paddr(unsigned long ept_access,
				     unsigned long pte_ad,
				     enum ept_access_op op)
{
	ept_access_paddr(ept_access, pte_ad, op, /*expect_violation=*/false,
			 /*expected_qual=*/-1);
}

static void ept_access_violation_paddr(unsigned long ept_access,
				       unsigned long pte_ad,
				       enum ept_access_op op,
				       u64 expected_qual)
{
	ept_access_paddr(ept_access, pte_ad, op, /*expect_violation=*/true,
			 expected_qual);
}


static void ept_allowed_at_level_mkhuge(bool mkhuge, int level,
					unsigned long clear,
					unsigned long set,
					enum ept_access_op op)
{
	struct ept_access_test_data *data = &ept_access_test_data;
	unsigned long orig_pte;

	orig_pte = ept_twiddle(data->gpa, mkhuge, level, clear, set);

	/* No violation. Should proceed to vmcall. */
	do_ept_access_op(op);
	skip_exit_vmcall();

	ept_untwiddle(data->gpa, level, orig_pte);
}

static void ept_allowed_at_level(int level, unsigned long clear,
				 unsigned long set, enum ept_access_op op)
{
	ept_allowed_at_level_mkhuge(false, level, clear, set, op);
	if (ept_huge_pages_supported(level))
		ept_allowed_at_level_mkhuge(true, level, clear, set, op);
}

static void ept_allowed(unsigned long clear, unsigned long set,
			enum ept_access_op op)
{
	ept_allowed_at_level(1, clear, set, op);
	ept_allowed_at_level(2, clear, set, op);
	ept_allowed_at_level(3, clear, set, op);
	ept_allowed_at_level(4, clear, set, op);
}

static void ept_ignored_bit(int bit)
{
	/* Set the bit. */
	ept_allowed(0, 1ul << bit, OP_READ);
	ept_allowed(0, 1ul << bit, OP_WRITE);
	ept_allowed(0, 1ul << bit, OP_EXEC);

	/* Clear the bit. */
	ept_allowed(1ul << bit, 0, OP_READ);
	ept_allowed(1ul << bit, 0, OP_WRITE);
	ept_allowed(1ul << bit, 0, OP_EXEC);
}

static void ept_access_allowed(unsigned long access, enum ept_access_op op)
{
	ept_allowed(EPT_PRESENT, access, op);
}


static void ept_misconfig_at_level_mkhuge_op(bool mkhuge, int level,
					     unsigned long clear,
					     unsigned long set,
					     enum ept_access_op op)
{
	struct ept_access_test_data *data = &ept_access_test_data;
	unsigned long orig_pte;

	orig_pte = ept_twiddle(data->gpa, mkhuge, level, clear, set);

	do_ept_access_op(op);
	assert_exit_reason(VMX_EPT_MISCONFIG);

	/* Intel 27.2.1, "For all other VM exits, this field is cleared." */
	#if 0
	/* broken: */
	TEST_EXPECT_EQ_MSG(vmcs_read(EXI_QUALIFICATION), 0);
	#endif
	#if 0
	/*
	 * broken:
	 * According to description of exit qual for EPT violation,
	 * EPT_VLT_LADDR_VLD indicates if GUEST_LINEAR_ADDRESS is valid.
	 * However, I can't find anything that says GUEST_LINEAR_ADDRESS ought
	 * to be set for msiconfig.
	 */
	TEST_EXPECT_EQ(vmcs_read(GUEST_LINEAR_ADDRESS),
		       (unsigned long) (
			       op == OP_EXEC ? data->gva + 1 : data->gva));
	#endif

	/* Fix the violation and resume the op loop. */
	ept_untwiddle(data->gpa, level, orig_pte);
	enter_guest();
	skip_exit_vmcall();
}

static void ept_misconfig_at_level_mkhuge(bool mkhuge, int level,
					  unsigned long clear,
					  unsigned long set)
{
	/* The op shouldn't matter (read, write, exec), so try them all! */
	ept_misconfig_at_level_mkhuge_op(mkhuge, level, clear, set, OP_READ);
	ept_misconfig_at_level_mkhuge_op(mkhuge, level, clear, set, OP_WRITE);
	ept_misconfig_at_level_mkhuge_op(mkhuge, level, clear, set, OP_EXEC);
}

static void ept_misconfig_at_level(int level, unsigned long clear,
				   unsigned long set)
{
	ept_misconfig_at_level_mkhuge(false, level, clear, set);
	if (ept_huge_pages_supported(level))
		ept_misconfig_at_level_mkhuge(true, level, clear, set);
}

static void ept_misconfig(unsigned long clear, unsigned long set)
{
	ept_misconfig_at_level(1, clear, set);
	ept_misconfig_at_level(2, clear, set);
	ept_misconfig_at_level(3, clear, set);
	ept_misconfig_at_level(4, clear, set);
}

static void ept_access_misconfig(unsigned long access)
{
	ept_misconfig(EPT_PRESENT, access);
}

static void ept_reserved_bit_at_level_nohuge(int level, int bit)
{
	/* Setting the bit causes a misconfig. */
	ept_misconfig_at_level_mkhuge(false, level, 0, 1ul << bit);

	/* Making the entry non-present turns reserved bits into ignored. */
	ept_violation_at_level(level, EPT_PRESENT, 1ul << bit, OP_READ,
			       EPT_VLT_RD | EPT_VLT_LADDR_VLD | EPT_VLT_PADDR);
}

static void ept_reserved_bit_at_level_huge(int level, int bit)
{
	/* Setting the bit causes a misconfig. */
	ept_misconfig_at_level_mkhuge(true, level, 0, 1ul << bit);

	/* Making the entry non-present turns reserved bits into ignored. */
	ept_violation_at_level(level, EPT_PRESENT, 1ul << bit, OP_READ,
			       EPT_VLT_RD | EPT_VLT_LADDR_VLD | EPT_VLT_PADDR);
}

static void ept_reserved_bit_at_level(int level, int bit)
{
	/* Setting the bit causes a misconfig. */
	ept_misconfig_at_level(level, 0, 1ul << bit);

	/* Making the entry non-present turns reserved bits into ignored. */
	ept_violation_at_level(level, EPT_PRESENT, 1ul << bit, OP_READ,
			       EPT_VLT_RD | EPT_VLT_LADDR_VLD | EPT_VLT_PADDR);
}

static void ept_reserved_bit(int bit)
{
	ept_reserved_bit_at_level(1, bit);
	ept_reserved_bit_at_level(2, bit);
	ept_reserved_bit_at_level(3, bit);
	ept_reserved_bit_at_level(4, bit);
}

#define PAGE_2M_ORDER 9
#define PAGE_1G_ORDER 18

static void *get_1g_page(void)
{
	static void *alloc;

	if (!alloc)
		alloc = alloc_pages(PAGE_1G_ORDER);
	return alloc;
}

static void ept_access_test_teardown(void *unused)
{
	/* Exit the guest cleanly. */
	do_ept_access_op(OP_EXIT);
}

static void ept_access_test_guest(void)
{
	struct ept_access_test_data *data = &ept_access_test_data;
	int (*code)(void) = (int (*)(void)) &data->gva[1];

	while (true) {
		switch (data->op) {
		case OP_READ:
			TEST_ASSERT_EQ(*data->gva, MAGIC_VAL_1);
			break;
		case OP_WRITE:
			*data->gva = MAGIC_VAL_2;
			TEST_ASSERT_EQ(*data->gva, MAGIC_VAL_2);
			*data->gva = MAGIC_VAL_1;
			break;
		case OP_EXEC:
			TEST_ASSERT_EQ(42, code());
			break;
		case OP_FLUSH_TLB:
			write_cr3(read_cr3());
			break;
		case OP_EXIT:
			return;
		default:
			TEST_ASSERT_MSG(false, "Unknown op %d", data->op);
		}
		vmcall();
	}
}

static void ept_access_test_setup(void)
{
	struct ept_access_test_data *data = &ept_access_test_data;
	unsigned long npages = 1ul << PAGE_1G_ORDER;
	unsigned long size = npages * PAGE_SIZE;
	unsigned long *page_table = current_page_table();
	unsigned long pte;

	if (setup_ept(false))
		test_skip("EPT not supported");

	/* We use data->gpa = 1 << 39 so that test data has a separate pml4 entry */
	if (cpuid_maxphyaddr() < 40)
		test_skip("Test needs MAXPHYADDR >= 40");

	test_set_guest(ept_access_test_guest);
	test_add_teardown(ept_access_test_teardown, NULL);

	data->hva = get_1g_page();
	TEST_ASSERT(data->hva);
	data->hpa = virt_to_phys(data->hva);

	data->gpa = 1ul << 39;
	data->gva = (void *) ALIGN((unsigned long) alloc_vpages(npages * 2),
				   size);
	TEST_ASSERT(!any_present_pages(page_table, data->gva, size));
	install_pages(page_table, data->gpa, size, data->gva);

	/*
	 * Make sure nothing's mapped here so the tests that screw with the
	 * pml4 entry don't inadvertently break something.
	 */
	TEST_ASSERT(get_ept_pte(pml4, data->gpa, 4, &pte) && pte == 0);
	TEST_ASSERT(get_ept_pte(pml4, data->gpa + size - 1, 4, &pte) && pte == 0);
	install_ept(pml4, data->hpa, data->gpa, EPT_PRESENT);

	data->hva[0] = MAGIC_VAL_1;
	memcpy(&data->hva[1], &ret42_start, &ret42_end - &ret42_start);
}

static void ept_access_test_not_present(void)
{
	ept_access_test_setup();
	/* --- */
	ept_access_violation(0, OP_READ, EPT_VLT_RD);
	ept_access_violation(0, OP_WRITE, EPT_VLT_WR);
	ept_access_violation(0, OP_EXEC, EPT_VLT_FETCH);
}

static void ept_access_test_read_only(void)
{
	ept_access_test_setup();

	/* r-- */
	ept_access_allowed(EPT_RA, OP_READ);
	ept_access_violation(EPT_RA, OP_WRITE, EPT_VLT_WR | EPT_VLT_PERM_RD);
	ept_access_violation(EPT_RA, OP_EXEC, EPT_VLT_FETCH | EPT_VLT_PERM_RD);
}

static void ept_access_test_write_only(void)
{
	ept_access_test_setup();
	/* -w- */
	ept_access_misconfig(EPT_WA);
}

static void ept_access_test_read_write(void)
{
	ept_access_test_setup();
	/* rw- */
	ept_access_allowed(EPT_RA | EPT_WA, OP_READ);
	ept_access_allowed(EPT_RA | EPT_WA, OP_WRITE);
	ept_access_violation(EPT_RA | EPT_WA, OP_EXEC,
			   EPT_VLT_FETCH | EPT_VLT_PERM_RD | EPT_VLT_PERM_WR);
}


static void ept_access_test_execute_only(void)
{
	ept_access_test_setup();
	/* --x */
	if (ept_execute_only_supported()) {
		ept_access_violation(EPT_EA, OP_READ,
				     EPT_VLT_RD | EPT_VLT_PERM_EX);
		ept_access_violation(EPT_EA, OP_WRITE,
				     EPT_VLT_WR | EPT_VLT_PERM_EX);
		ept_access_allowed(EPT_EA, OP_EXEC);
	} else {
		ept_access_misconfig(EPT_EA);
	}
}

static void ept_access_test_read_execute(void)
{
	ept_access_test_setup();
	/* r-x */
	ept_access_allowed(EPT_RA | EPT_EA, OP_READ);
	ept_access_violation(EPT_RA | EPT_EA, OP_WRITE,
			   EPT_VLT_WR | EPT_VLT_PERM_RD | EPT_VLT_PERM_EX);
	ept_access_allowed(EPT_RA | EPT_EA, OP_EXEC);
}

static void ept_access_test_write_execute(void)
{
	ept_access_test_setup();
	/* -wx */
	ept_access_misconfig(EPT_WA | EPT_EA);
}

static void ept_access_test_read_write_execute(void)
{
	ept_access_test_setup();
	/* rwx */
	ept_access_allowed(EPT_RA | EPT_WA | EPT_EA, OP_READ);
	ept_access_allowed(EPT_RA | EPT_WA | EPT_EA, OP_WRITE);
	ept_access_allowed(EPT_RA | EPT_WA | EPT_EA, OP_EXEC);
}

static void ept_access_test_reserved_bits(void)
{
	int i;
	int maxphyaddr;

	ept_access_test_setup();

	/* Reserved bits above maxphyaddr. */
	maxphyaddr = cpuid_maxphyaddr();
	for (i = maxphyaddr; i <= 51; i++) {
		report_prefix_pushf("reserved_bit=%d", i);
		ept_reserved_bit(i);
		report_prefix_pop();
	}

	/* Level-specific reserved bits. */
	ept_reserved_bit_at_level_nohuge(2, 3);
	ept_reserved_bit_at_level_nohuge(2, 4);
	ept_reserved_bit_at_level_nohuge(2, 5);
	ept_reserved_bit_at_level_nohuge(2, 6);
	/* 2M alignment. */
	for (i = 12; i < 20; i++) {
		report_prefix_pushf("reserved_bit=%d", i);
		ept_reserved_bit_at_level_huge(2, i);
		report_prefix_pop();
	}
	ept_reserved_bit_at_level_nohuge(3, 3);
	ept_reserved_bit_at_level_nohuge(3, 4);
	ept_reserved_bit_at_level_nohuge(3, 5);
	ept_reserved_bit_at_level_nohuge(3, 6);
	/* 1G alignment. */
	for (i = 12; i < 29; i++) {
		report_prefix_pushf("reserved_bit=%d", i);
		ept_reserved_bit_at_level_huge(3, i);
		report_prefix_pop();
	}
	ept_reserved_bit_at_level(4, 3);
	ept_reserved_bit_at_level(4, 4);
	ept_reserved_bit_at_level(4, 5);
	ept_reserved_bit_at_level(4, 6);
	ept_reserved_bit_at_level(4, 7);
}

static void ept_access_test_ignored_bits(void)
{
	ept_access_test_setup();
	/*
	 * Bits ignored at every level. Bits 8 and 9 (A and D) are ignored as
	 * far as translation is concerned even if AD bits are enabled in the
	 * EPTP. Bit 63 is ignored because "EPT-violation #VE" VM-execution
	 * control is 0.
	 */
	ept_ignored_bit(8);
	ept_ignored_bit(9);
	ept_ignored_bit(10);
	ept_ignored_bit(11);
	ept_ignored_bit(52);
	ept_ignored_bit(53);
	ept_ignored_bit(54);
	ept_ignored_bit(55);
	ept_ignored_bit(56);
	ept_ignored_bit(57);
	ept_ignored_bit(58);
	ept_ignored_bit(59);
	ept_ignored_bit(60);
	ept_ignored_bit(61);
	ept_ignored_bit(62);
	ept_ignored_bit(63);
}

static void ept_access_test_paddr_not_present_ad_disabled(void)
{
	ept_access_test_setup();
	ept_disable_ad_bits();

	ept_access_violation_paddr(0, PT_AD_MASK, OP_READ, EPT_VLT_RD);
	ept_access_violation_paddr(0, PT_AD_MASK, OP_WRITE, EPT_VLT_RD);
	ept_access_violation_paddr(0, PT_AD_MASK, OP_EXEC, EPT_VLT_RD);
}

static void ept_access_test_paddr_not_present_ad_enabled(void)
{
	u64 qual = EPT_VLT_RD | EPT_VLT_WR;

	ept_access_test_setup();
	ept_enable_ad_bits_or_skip_test();

	ept_access_violation_paddr(0, PT_AD_MASK, OP_READ, qual);
	ept_access_violation_paddr(0, PT_AD_MASK, OP_WRITE, qual);
	ept_access_violation_paddr(0, PT_AD_MASK, OP_EXEC, qual);
}

static void ept_access_test_paddr_read_only_ad_disabled(void)
{
	/*
	 * When EPT AD bits are disabled, all accesses to guest paging
	 * structures are reported separately as a read and (after
	 * translation of the GPA to host physical address) a read+write
	 * if the A/D bits have to be set.
	 */
	u64 qual = EPT_VLT_WR | EPT_VLT_RD | EPT_VLT_PERM_RD;

	ept_access_test_setup();
	ept_disable_ad_bits();

	/* Can't update A bit, so all accesses fail. */
	ept_access_violation_paddr(EPT_RA, 0, OP_READ, qual);
	ept_access_violation_paddr(EPT_RA, 0, OP_WRITE, qual);
	ept_access_violation_paddr(EPT_RA, 0, OP_EXEC, qual);
	/* AD bits disabled, so only writes try to update the D bit. */
	ept_access_allowed_paddr(EPT_RA, PT_ACCESSED_MASK, OP_READ);
	ept_access_violation_paddr(EPT_RA, PT_ACCESSED_MASK, OP_WRITE, qual);
	ept_access_allowed_paddr(EPT_RA, PT_ACCESSED_MASK, OP_EXEC);
	/* Both A and D already set, so read-only is OK. */
	ept_access_allowed_paddr(EPT_RA, PT_AD_MASK, OP_READ);
	ept_access_allowed_paddr(EPT_RA, PT_AD_MASK, OP_WRITE);
	ept_access_allowed_paddr(EPT_RA, PT_AD_MASK, OP_EXEC);
}

static void ept_access_test_paddr_read_only_ad_enabled(void)
{
	/*
	 * When EPT AD bits are enabled, all accesses to guest paging
	 * structures are considered writes as far as EPT translation
	 * is concerned.
	 */
	u64 qual = EPT_VLT_WR | EPT_VLT_RD | EPT_VLT_PERM_RD;

	ept_access_test_setup();
	ept_enable_ad_bits_or_skip_test();

	ept_access_violation_paddr(EPT_RA, 0, OP_READ, qual);
	ept_access_violation_paddr(EPT_RA, 0, OP_WRITE, qual);
	ept_access_violation_paddr(EPT_RA, 0, OP_EXEC, qual);
	ept_access_violation_paddr(EPT_RA, PT_ACCESSED_MASK, OP_READ, qual);
	ept_access_violation_paddr(EPT_RA, PT_ACCESSED_MASK, OP_WRITE, qual);
	ept_access_violation_paddr(EPT_RA, PT_ACCESSED_MASK, OP_EXEC, qual);
	ept_access_violation_paddr(EPT_RA, PT_AD_MASK, OP_READ, qual);
	ept_access_violation_paddr(EPT_RA, PT_AD_MASK, OP_WRITE, qual);
	ept_access_violation_paddr(EPT_RA, PT_AD_MASK, OP_EXEC, qual);
}

static void ept_access_test_paddr_read_write(void)
{
	ept_access_test_setup();
	/* Read-write access to paging structure. */
	ept_access_allowed_paddr(EPT_RA | EPT_WA, 0, OP_READ);
	ept_access_allowed_paddr(EPT_RA | EPT_WA, 0, OP_WRITE);
	ept_access_allowed_paddr(EPT_RA | EPT_WA, 0, OP_EXEC);
}

static void ept_access_test_paddr_read_write_execute(void)
{
	ept_access_test_setup();
	/* RWX access to paging structure. */
	ept_access_allowed_paddr(EPT_PRESENT, 0, OP_READ);
	ept_access_allowed_paddr(EPT_PRESENT, 0, OP_WRITE);
	ept_access_allowed_paddr(EPT_PRESENT, 0, OP_EXEC);
}

static void ept_access_test_paddr_read_execute_ad_disabled(void)
{
  	/*
	 * When EPT AD bits are disabled, all accesses to guest paging
	 * structures are reported separately as a read and (after
	 * translation of the GPA to host physical address) a read+write
	 * if the A/D bits have to be set.
	 */
	u64 qual = EPT_VLT_WR | EPT_VLT_RD | EPT_VLT_PERM_RD | EPT_VLT_PERM_EX;

	ept_access_test_setup();
	ept_disable_ad_bits();

	/* Can't update A bit, so all accesses fail. */
	ept_access_violation_paddr(EPT_RA | EPT_EA, 0, OP_READ, qual);
	ept_access_violation_paddr(EPT_RA | EPT_EA, 0, OP_WRITE, qual);
	ept_access_violation_paddr(EPT_RA | EPT_EA, 0, OP_EXEC, qual);
	/* AD bits disabled, so only writes try to update the D bit. */
	ept_access_allowed_paddr(EPT_RA | EPT_EA, PT_ACCESSED_MASK, OP_READ);
	ept_access_violation_paddr(EPT_RA | EPT_EA, PT_ACCESSED_MASK, OP_WRITE, qual);
	ept_access_allowed_paddr(EPT_RA | EPT_EA, PT_ACCESSED_MASK, OP_EXEC);
	/* Both A and D already set, so read-only is OK. */
	ept_access_allowed_paddr(EPT_RA | EPT_EA, PT_AD_MASK, OP_READ);
	ept_access_allowed_paddr(EPT_RA | EPT_EA, PT_AD_MASK, OP_WRITE);
	ept_access_allowed_paddr(EPT_RA | EPT_EA, PT_AD_MASK, OP_EXEC);
}

static void ept_access_test_paddr_read_execute_ad_enabled(void)
{
	/*
	 * When EPT AD bits are enabled, all accesses to guest paging
	 * structures are considered writes as far as EPT translation
	 * is concerned.
	 */
	u64 qual = EPT_VLT_WR | EPT_VLT_RD | EPT_VLT_PERM_RD | EPT_VLT_PERM_EX;

	ept_access_test_setup();
	ept_enable_ad_bits_or_skip_test();

	ept_access_violation_paddr(EPT_RA | EPT_EA, 0, OP_READ, qual);
	ept_access_violation_paddr(EPT_RA | EPT_EA, 0, OP_WRITE, qual);
	ept_access_violation_paddr(EPT_RA | EPT_EA, 0, OP_EXEC, qual);
	ept_access_violation_paddr(EPT_RA | EPT_EA, PT_ACCESSED_MASK, OP_READ, qual);
	ept_access_violation_paddr(EPT_RA | EPT_EA, PT_ACCESSED_MASK, OP_WRITE, qual);
	ept_access_violation_paddr(EPT_RA | EPT_EA, PT_ACCESSED_MASK, OP_EXEC, qual);
	ept_access_violation_paddr(EPT_RA | EPT_EA, PT_AD_MASK, OP_READ, qual);
	ept_access_violation_paddr(EPT_RA | EPT_EA, PT_AD_MASK, OP_WRITE, qual);
	ept_access_violation_paddr(EPT_RA | EPT_EA, PT_AD_MASK, OP_EXEC, qual);
}

static void ept_access_test_paddr_not_present_page_fault(void)
{
	ept_access_test_setup();
	/*
	 * TODO: test no EPT violation as long as guest PF occurs. e.g., GPA is
	 * page is read-only in EPT but GVA is also mapped read only in PT.
	 * Thus guest page fault before host takes EPT violation for trying to
	 * update A bit.
	 */
}

static void ept_access_test_force_2m_page(void)
{
	ept_access_test_setup();

	TEST_ASSERT_EQ(ept_2m_supported(), true);
	ept_allowed_at_level_mkhuge(true, 2, 0, 0, OP_READ);
	ept_violation_at_level_mkhuge(true, 2, EPT_PRESENT, EPT_RA, OP_WRITE,
				      EPT_VLT_WR | EPT_VLT_PERM_RD |
				      EPT_VLT_LADDR_VLD | EPT_VLT_PADDR);
	ept_misconfig_at_level_mkhuge(true, 2, EPT_PRESENT, EPT_WA);
}

static bool invvpid_valid(u64 type, u64 vpid, u64 gla)
{
	u64 msr = rdmsr(MSR_IA32_VMX_EPT_VPID_CAP);

	TEST_ASSERT(msr & VPID_CAP_INVVPID);

	if (type < INVVPID_ADDR || type > INVVPID_CONTEXT_LOCAL)
		return false;

	if (!(msr & (1ull << (type + VPID_CAP_INVVPID_TYPES_SHIFT))))
		return false;

	if (vpid >> 16)
		return false;

	if (type != INVVPID_ALL && !vpid)
		return false;

	if (type == INVVPID_ADDR && !is_canonical(gla))
		return false;

	return true;
}

static void try_invvpid(u64 type, u64 vpid, u64 gla)
{
	int rc;
	bool valid = invvpid_valid(type, vpid, gla);
	u64 expected = valid ? VMXERR_UNSUPPORTED_VMCS_COMPONENT
		: VMXERR_INVALID_OPERAND_TO_INVEPT_INVVPID;
	/*
	 * Set VMX_INST_ERROR to VMXERR_UNVALID_VMCS_COMPONENT, so
	 * that we can tell if it is updated by INVVPID.
	 */
	vmcs_read(~0);
	rc = invvpid(type, vpid, gla);
	report("INVVPID type %ld VPID %lx GLA %lx %s",
	       !rc == valid, type, vpid, gla,
	       valid ? "passes" : "fails");
	report("After %s INVVPID, VMX_INST_ERR is %ld (actual %ld)",
	       vmcs_read(VMX_INST_ERROR) == expected,
	       rc ? "failed" : "successful",
	       expected, vmcs_read(VMX_INST_ERROR));
}

static void ds_invvpid(void *data)
{
	u64 msr = rdmsr(MSR_IA32_VMX_EPT_VPID_CAP);
	u64 type = ffs(msr >> VPID_CAP_INVVPID_TYPES_SHIFT) - 1;

	TEST_ASSERT(type >= INVVPID_ADDR && type <= INVVPID_CONTEXT_LOCAL);
	asm volatile("invvpid %0, %1"
		     :
		     : "m"(*(struct invvpid_operand *)data),
		       "r"(type));
}

/*
 * The SS override is ignored in 64-bit mode, so we use an addressing
 * mode with %rsp as the base register to generate an implicit SS
 * reference.
 */
static void ss_invvpid(void *data)
{
	u64 msr = rdmsr(MSR_IA32_VMX_EPT_VPID_CAP);
	u64 type = ffs(msr >> VPID_CAP_INVVPID_TYPES_SHIFT) - 1;

	TEST_ASSERT(type >= INVVPID_ADDR && type <= INVVPID_CONTEXT_LOCAL);
	asm volatile("sub %%rsp,%0; invvpid (%%rsp,%0,1), %1"
		     : "+r"(data)
		     : "r"(type));
}

static void invvpid_test_gp(void)
{
	bool fault;

	fault = test_for_exception(GP_VECTOR, &ds_invvpid,
				   (void *)NONCANONICAL);
	report("INVVPID with non-canonical DS operand raises #GP", fault);
}

static void invvpid_test_ss(void)
{
	bool fault;

	fault = test_for_exception(SS_VECTOR, &ss_invvpid,
				   (void *)NONCANONICAL);
	report("INVVPID with non-canonical SS operand raises #SS", fault);
}

static void invvpid_test_pf(void)
{
	void *vpage = alloc_vpage();
	bool fault;

	fault = test_for_exception(PF_VECTOR, &ds_invvpid, vpage);
	report("INVVPID with unmapped operand raises #PF", fault);
}

static void try_compat_invvpid(void *unused)
{
	struct far_pointer32 fp = {
		.offset = (uintptr_t)&&invvpid,
		.selector = KERNEL_CS32,
	};
	register uintptr_t rsp asm("rsp");

	TEST_ASSERT_MSG(fp.offset == (uintptr_t)&&invvpid,
			"Code address too high.");
	TEST_ASSERT_MSG(rsp == (u32)rsp, "Stack address too high.");

	asm goto ("lcall *%0" : : "m" (fp) : "rax" : invvpid);
	return;
invvpid:
	asm volatile (".code32;"
		      "invvpid (%eax), %eax;"
		      "lret;"
		      ".code64");
	__builtin_unreachable();
}

static void invvpid_test_compatibility_mode(void)
{
	bool fault;

	fault = test_for_exception(UD_VECTOR, &try_compat_invvpid, NULL);
	report("Compatibility mode INVVPID raises #UD", fault);
}

static void invvpid_test_not_in_vmx_operation(void)
{
	bool fault;

	TEST_ASSERT(!vmx_off());
	fault = test_for_exception(UD_VECTOR, &ds_invvpid, NULL);
	report("INVVPID outside of VMX operation raises #UD", fault);
	TEST_ASSERT(!vmx_on());
}

/*
 * This does not test real-address mode, virtual-8086 mode, protected mode,
 * or CPL > 0.
 */
static void invvpid_test_v2(void)
{
	u64 msr;
	int i;
	unsigned types = 0;
	unsigned type;

	if (!(ctrl_cpu_rev[0].clr & CPU_SECONDARY) ||
	    !(ctrl_cpu_rev[1].clr & CPU_VPID))
		test_skip("VPID not supported");

	msr = rdmsr(MSR_IA32_VMX_EPT_VPID_CAP);

	if (!(msr & VPID_CAP_INVVPID))
		test_skip("INVVPID not supported.\n");

	if (msr & VPID_CAP_INVVPID_ADDR)
		types |= 1u << INVVPID_ADDR;
	if (msr & VPID_CAP_INVVPID_CXTGLB)
		types |= 1u << INVVPID_CONTEXT_GLOBAL;
	if (msr & VPID_CAP_INVVPID_ALL)
		types |= 1u << INVVPID_ALL;
	if (msr & VPID_CAP_INVVPID_CXTLOC)
		types |= 1u << INVVPID_CONTEXT_LOCAL;

	if (!types)
		test_skip("No INVVPID types supported.\n");

	for (i = -127; i < 128; i++)
		try_invvpid(i, 0xffff, 0);

	/*
	 * VPID must not be more than 16 bits.
	 */
	for (i = 0; i < 64; i++)
		for (type = 0; type < 4; type++)
			if (types & (1u << type))
				try_invvpid(type, 1ul << i, 0);

	/*
	 * VPID must not be zero, except for "all contexts."
	 */
	for (type = 0; type < 4; type++)
		if (types & (1u << type))
			try_invvpid(type, 0, 0);

	/*
	 * The gla operand is only validated for single-address INVVPID.
	 */
	if (types & (1u << INVVPID_ADDR))
		try_invvpid(INVVPID_ADDR, 0xffff, NONCANONICAL);

	invvpid_test_gp();
	invvpid_test_ss();
	invvpid_test_pf();
	invvpid_test_compatibility_mode();
	invvpid_test_not_in_vmx_operation();
}

/*
 * Test for early VMLAUNCH failure. Returns true if VMLAUNCH makes it
 * at least as far as the guest-state checks. Returns false if the
 * VMLAUNCH fails early and execution falls through to the next
 * instruction.
 */
static bool vmlaunch_succeeds(void)
{
	/*
	 * Indirectly set VMX_INST_ERR to 12 ("VMREAD/VMWRITE from/to
	 * unsupported VMCS component"). The caller can then check
	 * to see if a failed VM-entry sets VMX_INST_ERR as expected.
	 */
	vmcs_write(~0u, 0);

	vmcs_write(HOST_RIP, (uintptr_t)&&success);
	__asm__ __volatile__ goto ("vmwrite %%rsp, %0; vmlaunch"
				   :
				   : "r" ((u64)HOST_RSP)
				   : "cc", "memory"
				   : success);
	return false;
success:
	TEST_ASSERT(vmcs_read(EXI_REASON) ==
		    (VMX_FAIL_STATE | VMX_ENTRY_FAILURE));
	return true;
}

/*
 * Try to launch the current VMCS.
 */
static void test_vmx_controls(bool controls_valid, bool xfail)
{
	bool success = vmlaunch_succeeds();
	u32 vmx_inst_err;

	report_xfail("vmlaunch %s", xfail, success == controls_valid,
		     controls_valid ? "succeeds" : "fails");
	if (!success) {
		vmx_inst_err = vmcs_read(VMX_INST_ERROR);
		report("VMX inst error is %d (actual %d)",
		       vmx_inst_err == VMXERR_ENTRY_INVALID_CONTROL_FIELD,
		       VMXERR_ENTRY_INVALID_CONTROL_FIELD, vmx_inst_err);
	}
}

/*
 * Test a particular value of a VM-execution control bit, if the value
 * is required or if the value is zero.
 */
static void test_rsvd_ctl_bit_value(const char *name, union vmx_ctrl_msr msr,
				    enum Encoding encoding, unsigned bit,
				    unsigned val)
{
	u32 mask = 1u << bit;
	bool expected;
	u32 controls;

	if (msr.set & mask)
		TEST_ASSERT(msr.clr & mask);

	/*
	 * We can't arbitrarily turn on a control bit, because it may
	 * introduce dependencies on other VMCS fields. So, we only
	 * test turning on bits that have a required setting.
	 */
	if (val && (msr.clr & mask) && !(msr.set & mask))
		return;

	report_prefix_pushf("%s %s bit %d",
			    val ? "Set" : "Clear", name, bit);

	controls = vmcs_read(encoding);
	if (val) {
		vmcs_write(encoding, msr.set | mask);
		expected = (msr.clr & mask);
	} else {
		vmcs_write(encoding, msr.set & ~mask);
		expected = !(msr.set & mask);
	}
	test_vmx_controls(expected, false);
	vmcs_write(encoding, controls);
	report_prefix_pop();
}

/*
 * Test reserved values of a VM-execution control bit, based on the
 * allowed bit settings from the corresponding VMX capability MSR.
 */
static void test_rsvd_ctl_bit(const char *name, union vmx_ctrl_msr msr,
			      enum Encoding encoding, unsigned bit)
{
	test_rsvd_ctl_bit_value(name, msr, encoding, bit, 0);
	test_rsvd_ctl_bit_value(name, msr, encoding, bit, 1);
}

/*
 * Reserved bits in the pin-based VM-execution controls must be set
 * properly. Software may consult the VMX capability MSRs to determine
 * the proper settings.
 * [Intel SDM]
 */
static void test_pin_based_ctls(void)
{
	unsigned bit;

	printf("%s: %lx\n", basic.ctrl ? "MSR_IA32_VMX_TRUE_PIN" :
	       "MSR_IA32_VMX_PINBASED_CTLS", ctrl_pin_rev.val);
	for (bit = 0; bit < 32; bit++)
		test_rsvd_ctl_bit("pin-based controls",
				  ctrl_pin_rev, PIN_CONTROLS, bit);
}

/*
 * Reserved bits in the primary processor-based VM-execution controls
 * must be set properly. Software may consult the VMX capability MSRs
 * to determine the proper settings.
 * [Intel SDM]
 */
static void test_primary_processor_based_ctls(void)
{
	unsigned bit;

	printf("\n%s: %lx\n", basic.ctrl ? "MSR_IA32_VMX_TRUE_PROC" :
	       "MSR_IA32_VMX_PROCBASED_CTLS", ctrl_cpu_rev[0].val);
	for (bit = 0; bit < 32; bit++)
		test_rsvd_ctl_bit("primary processor-based controls",
				  ctrl_cpu_rev[0], CPU_EXEC_CTRL0, bit);
}

/*
 * If the "activate secondary controls" primary processor-based
 * VM-execution control is 1, reserved bits in the secondary
 * processor-based VM-execution controls must be cleared. Software may
 * consult the VMX capability MSRs to determine which bits are
 * reserved.
 * If the "activate secondary controls" primary processor-based
 * VM-execution control is 0 (or if the processor does not support the
 * 1-setting of that control), no checks are performed on the
 * secondary processor-based VM-execution controls.
 * [Intel SDM]
 */
static void test_secondary_processor_based_ctls(void)
{
	u32 primary;
	u32 secondary;
	unsigned bit;

	if (!(ctrl_cpu_rev[0].clr & CPU_SECONDARY))
		return;

	primary = vmcs_read(CPU_EXEC_CTRL0);
	secondary = vmcs_read(CPU_EXEC_CTRL1);

	vmcs_write(CPU_EXEC_CTRL0, primary | CPU_SECONDARY);
	printf("\nMSR_IA32_VMX_PROCBASED_CTLS2: %lx\n", ctrl_cpu_rev[1].val);
	for (bit = 0; bit < 32; bit++)
		test_rsvd_ctl_bit("secondary processor-based controls",
				  ctrl_cpu_rev[1], CPU_EXEC_CTRL1, bit);

	/*
	 * When the "activate secondary controls" VM-execution control
	 * is clear, there are no checks on the secondary controls.
	 */
	vmcs_write(CPU_EXEC_CTRL0, primary & ~CPU_SECONDARY);
	vmcs_write(CPU_EXEC_CTRL1, ~0);
	report("Secondary processor-based controls ignored",
	       vmlaunch_succeeds());
	vmcs_write(CPU_EXEC_CTRL1, secondary);
	vmcs_write(CPU_EXEC_CTRL0, primary);
}

static void try_cr3_target_count(unsigned i, unsigned max)
{
	report_prefix_pushf("CR3 target count 0x%x", i);
	vmcs_write(CR3_TARGET_COUNT, i);
	test_vmx_controls(i <= max, false);
	report_prefix_pop();
}

/*
 * The CR3-target count must not be greater than 4. Future processors
 * may support a different number of CR3-target values. Software
 * should read the VMX capability MSR IA32_VMX_MISC to determine the
 * number of values supported.
 * [Intel SDM]
 */
static void test_cr3_targets(void)
{
	unsigned supported_targets = (rdmsr(MSR_IA32_VMX_MISC) >> 16) & 0x1ff;
	u32 cr3_targets = vmcs_read(CR3_TARGET_COUNT);
	unsigned i;

	printf("\nSupported CR3 targets: %d\n", supported_targets);
	TEST_ASSERT(supported_targets <= 256);

	try_cr3_target_count(-1u, supported_targets);
	try_cr3_target_count(0x80000000, supported_targets);
	try_cr3_target_count(0x7fffffff, supported_targets);
	for (i = 0; i <= supported_targets + 1; i++)
		try_cr3_target_count(i, supported_targets);
	vmcs_write(CR3_TARGET_COUNT, cr3_targets);
}

/*
 * Test a particular address setting for a physical page reference in
 * the VMCS.
 */
static void test_vmcs_page_addr(const char *name,
				enum Encoding encoding,
				bool ignored,
				bool xfail_beyond_mapped_ram,
				u64 addr)
{
	bool xfail =
		(xfail_beyond_mapped_ram &&
		 addr > fwcfg_get_u64(FW_CFG_RAM_SIZE) - PAGE_SIZE &&
		 addr < (1ul << cpuid_maxphyaddr()));

	report_prefix_pushf("%s = %lx", name, addr);
	vmcs_write(encoding, addr);
	test_vmx_controls(ignored || (IS_ALIGNED(addr, PAGE_SIZE) &&
				  addr < (1ul << cpuid_maxphyaddr())),
			  xfail);
	report_prefix_pop();
	xfail = false;
}

/*
 * Test interesting values for a physical page reference in the VMCS.
 */
static void test_vmcs_page_values(const char *name,
				  enum Encoding encoding,
				  bool ignored,
				  bool xfail_beyond_mapped_ram)
{
	unsigned i;
	u64 orig_val = vmcs_read(encoding);

	for (i = 0; i < 64; i++)
		test_vmcs_page_addr(name, encoding, ignored,
				    xfail_beyond_mapped_ram, 1ul << i);

	test_vmcs_page_addr(name, encoding, ignored,
			    xfail_beyond_mapped_ram, PAGE_SIZE - 1);
	test_vmcs_page_addr(name, encoding, ignored,
			    xfail_beyond_mapped_ram, PAGE_SIZE);
	test_vmcs_page_addr(name, encoding, ignored,
			    xfail_beyond_mapped_ram,
			    (1ul << cpuid_maxphyaddr()) - PAGE_SIZE);
	test_vmcs_page_addr(name, encoding, ignored,
			    xfail_beyond_mapped_ram,
			    -1ul);

	vmcs_write(encoding, orig_val);
}

/*
 * Test a physical page reference in the VMCS, when the corresponding
 * feature is enabled and when the corresponding feature is disabled.
 */
static void test_vmcs_page_reference(u32 control_bit, enum Encoding field,
				     const char *field_name,
				     const char *control_name,
				     bool xfail_beyond_mapped_ram,
				     bool control_primary)
{
	u32 primary = vmcs_read(CPU_EXEC_CTRL0);
	u32 secondary = vmcs_read(CPU_EXEC_CTRL1);
	u64 page_addr;

	if (control_primary) {
		if (!(ctrl_cpu_rev[0].clr & control_bit))
			return;
	} else {
		if (!(ctrl_cpu_rev[1].clr & control_bit))
			return;
	}

	page_addr = vmcs_read(field);

	report_prefix_pushf("%s enabled", control_name);
	if (control_primary) {
		vmcs_write(CPU_EXEC_CTRL0, primary | control_bit);
	} else {
		vmcs_write(CPU_EXEC_CTRL0, primary | CPU_SECONDARY);
		vmcs_write(CPU_EXEC_CTRL1, secondary | control_bit);
	}
	test_vmcs_page_values(field_name, field, false, xfail_beyond_mapped_ram);
	report_prefix_pop();

	report_prefix_pushf("%s disabled", control_name);
	if (control_primary) {
		vmcs_write(CPU_EXEC_CTRL0, primary & ~control_bit);
	} else {
		vmcs_write(CPU_EXEC_CTRL0, primary & ~CPU_SECONDARY);
		vmcs_write(CPU_EXEC_CTRL1, secondary & ~control_bit);
	}
	test_vmcs_page_values(field_name, field, true, false);
	report_prefix_pop();

	vmcs_write(field, page_addr);
	vmcs_write(CPU_EXEC_CTRL0, primary);
}

/*
 * If the "use I/O bitmaps" VM-execution control is 1, bits 11:0 of
 * each I/O-bitmap address must be 0. Neither address should set any
 * bits beyond the processor's physical-address width.
 * [Intel SDM]
 */
static void test_io_bitmaps(void)
{
	test_vmcs_page_reference(CPU_IO_BITMAP, IO_BITMAP_A,
				 "I/O bitmap A", "Use I/O bitmaps", false,
				 true);
	test_vmcs_page_reference(CPU_IO_BITMAP, IO_BITMAP_B,
				 "I/O bitmap B", "Use I/O bitmaps", false,
				 true);
}

/*
 * If the "use MSR bitmaps" VM-execution control is 1, bits 11:0 of
 * the MSR-bitmap address must be 0. The address should not set any
 * bits beyond the processor's physical-address width.
 * [Intel SDM]
 */
static void test_msr_bitmap(void)
{
	test_vmcs_page_reference(CPU_MSR_BITMAP, MSR_BITMAP,
				 "MSR bitmap", "Use MSR bitmaps", false,
				 true);
}

/*
 * If the "use TPR shadow" VM-execution control is 1, the virtual-APIC
 * address must satisfy the following checks:
 * - Bits 11:0 of the address must be 0.
 * - The address should not set any bits beyond the processor's
 *   physical-address width.
 * [Intel SDM]
 */
static void test_apic_virt_addr(void)
{
	test_vmcs_page_reference(CPU_TPR_SHADOW, APIC_VIRT_ADDR,
				 "virtual-APIC address", "Use TPR shadow",
				 true, true);
}

/*
 * If the "virtualize APIC-accesses" VM-execution control is 1, the
 * APIC-access address must satisfy the following checks:
 *  - Bits 11:0 of the address must be 0.
 *  - The address should not set any bits beyond the processor's
 *    physical-address width.
 * [Intel SDM]
 */
static void test_apic_access_addr(void)
{
	void *apic_access_page = alloc_page();

	vmcs_write(APIC_ACCS_ADDR, virt_to_phys(apic_access_page));

	test_vmcs_page_reference(CPU_VIRT_APIC_ACCESSES, APIC_ACCS_ADDR,
				 "APIC-access address",
				 "virtualize APIC-accesses", false, false);
}

static bool set_bit_pattern(u8 mask, u32 *secondary)
{
	u8 i;
	bool flag = false;
	u32 test_bits[3] = {
		CPU_VIRT_X2APIC,
		CPU_APIC_REG_VIRT,
		CPU_VINTD
	};

        for (i = 0; i < ARRAY_SIZE(test_bits); i++) {
		if ((mask & (1u << i)) &&
		    (ctrl_cpu_rev[1].clr & test_bits[i])) {
			*secondary |= test_bits[i];
			flag = true;
		}
	}

	return (flag);
}

/*
 * If the "use TPR shadow" VM-execution control is 0, the following
 * VM-execution controls must also be 0:
 * 	- virtualize x2APIC mode
 *	- APIC-register virtualization
 *	- virtual-interrupt delivery
 *    [Intel SDM]
 *
 * 2. If the "virtualize x2APIC mode" VM-execution control is 1, the
 *    "virtualize APIC accesses" VM-execution control must be 0.
 *    [Intel SDM]
 */
static void test_apic_virtual_ctls(void)
{
	u32 saved_primary = vmcs_read(CPU_EXEC_CTRL0);
	u32 saved_secondary = vmcs_read(CPU_EXEC_CTRL1);
	u32 primary = saved_primary;
	u32 secondary = saved_secondary;
	bool ctrl = false;
	char str[10] = "disabled";
	u8 i = 0, j;

	/*
	 * First test
	 */
	if (!((ctrl_cpu_rev[0].clr & (CPU_SECONDARY | CPU_TPR_SHADOW)) ==
	    (CPU_SECONDARY | CPU_TPR_SHADOW)))
		return;

	primary |= CPU_SECONDARY;
	primary &= ~CPU_TPR_SHADOW;
	vmcs_write(CPU_EXEC_CTRL0, primary);

	while (1) {
		for (j = 1; j < 8; j++) {
			secondary &= ~(CPU_VIRT_X2APIC | CPU_APIC_REG_VIRT | CPU_VINTD);
			if (primary & CPU_TPR_SHADOW) {
				ctrl = true;
			} else {
				if (! set_bit_pattern(j, &secondary))
					ctrl = true;
				else
					ctrl = false;
			}

			vmcs_write(CPU_EXEC_CTRL1, secondary);
			report_prefix_pushf("Use TPR shadow %s, virtualize x2APIC mode %s, APIC-register virtualization %s, virtual-interrupt delivery %s",
				str, (secondary & CPU_VIRT_X2APIC) ? "enabled" : "disabled", (secondary & CPU_APIC_REG_VIRT) ? "enabled" : "disabled", (secondary & CPU_VINTD) ? "enabled" : "disabled");
			test_vmx_controls(ctrl, false);
			report_prefix_pop();
		}

		if (i == 1)
			break;
		i++;

		primary |= CPU_TPR_SHADOW;
		vmcs_write(CPU_EXEC_CTRL0, primary);
		strcpy(str, "enabled");
	}

	/*
	 * Second test
	 */
	u32 apic_virt_ctls = (CPU_VIRT_X2APIC | CPU_VIRT_APIC_ACCESSES);

	primary = saved_primary;
	secondary = saved_secondary;
	if (!((ctrl_cpu_rev[1].clr & apic_virt_ctls) == apic_virt_ctls))
		return;

	vmcs_write(CPU_EXEC_CTRL0, primary | CPU_SECONDARY);
	secondary &= ~CPU_VIRT_APIC_ACCESSES;
	vmcs_write(CPU_EXEC_CTRL1, secondary & ~CPU_VIRT_X2APIC);
	report_prefix_pushf("Virtualize x2APIC mode disabled; virtualize APIC access disabled");
	test_vmx_controls(true, false);
	report_prefix_pop();

	vmcs_write(CPU_EXEC_CTRL1, secondary | CPU_VIRT_APIC_ACCESSES);
	report_prefix_pushf("Virtualize x2APIC mode disabled; virtualize APIC access enabled");
	test_vmx_controls(true, false);
	report_prefix_pop();

	vmcs_write(CPU_EXEC_CTRL1, secondary | CPU_VIRT_X2APIC);
	report_prefix_pushf("Virtualize x2APIC mode enabled; virtualize APIC access enabled");
	test_vmx_controls(false, false);
	report_prefix_pop();

	vmcs_write(CPU_EXEC_CTRL1, secondary & ~CPU_VIRT_APIC_ACCESSES);
	report_prefix_pushf("Virtualize x2APIC mode enabled; virtualize APIC access disabled");
	test_vmx_controls(true, false);
	report_prefix_pop();

	vmcs_write(CPU_EXEC_CTRL0, saved_primary);
	vmcs_write(CPU_EXEC_CTRL1, saved_secondary);
}

/*
 * If the "virtual-interrupt delivery" VM-execution control is 1, the
 * "external-interrupt exiting" VM-execution control must be 1.
 * [Intel SDM]
 */
static void test_virtual_intr_ctls(void)
{
	u32 saved_primary = vmcs_read(CPU_EXEC_CTRL0);
	u32 saved_secondary = vmcs_read(CPU_EXEC_CTRL1);
	u32 saved_pin = vmcs_read(PIN_CONTROLS);
	u32 primary = saved_primary;
	u32 secondary = saved_secondary;
	u32 pin = saved_pin;

	if (!((ctrl_cpu_rev[1].clr & CPU_VINTD) &&
	    (ctrl_pin_rev.clr & PIN_EXTINT)))
		return;

	vmcs_write(CPU_EXEC_CTRL0, primary | CPU_SECONDARY | CPU_TPR_SHADOW);
	vmcs_write(CPU_EXEC_CTRL1, secondary & ~CPU_VINTD);
	vmcs_write(PIN_CONTROLS, pin & ~PIN_EXTINT);
	report_prefix_pushf("Virtualize interrupt-delivery disabled; external-interrupt exiting disabled");
	test_vmx_controls(true, false);
	report_prefix_pop();

	vmcs_write(CPU_EXEC_CTRL1, secondary | CPU_VINTD);
	report_prefix_pushf("Virtualize interrupt-delivery enabled; external-interrupt exiting disabled");
	test_vmx_controls(false, false);
	report_prefix_pop();

	vmcs_write(PIN_CONTROLS, pin | PIN_EXTINT);
	report_prefix_pushf("Virtualize interrupt-delivery enabled; external-interrupt exiting enabled");
	test_vmx_controls(true, false);
	report_prefix_pop();

	vmcs_write(PIN_CONTROLS, pin & ~PIN_EXTINT);
	report_prefix_pushf("Virtualize interrupt-delivery enabled; external-interrupt exiting disabled");
	test_vmx_controls(false, false);
	report_prefix_pop();

	vmcs_write(CPU_EXEC_CTRL0, saved_primary);
	vmcs_write(CPU_EXEC_CTRL1, saved_secondary);
	vmcs_write(PIN_CONTROLS, saved_pin);
}

static void test_pi_desc_addr(u64 addr, bool ctrl)
{
	vmcs_write(POSTED_INTR_DESC_ADDR, addr);
	report_prefix_pushf("Process-posted-interrupts enabled; posted-interrupt-descriptor-address 0x%lx", addr);
	test_vmx_controls(ctrl, false);
	report_prefix_pop();
}

/*
 * If the â€œprocess posted interruptsâ€ VM-execution control is 1, the
 * following must be true:
 *
 *	- The â€œvirtual-interrupt deliveryâ€ VM-execution control is 1.
 *	- The â€œacknowledge interrupt on exitâ€ VM-exit control is 1.
 *	- The posted-interrupt notification vector has a value in the
 *	- range 0â€“255 (bits 15:8 are all 0).
 *	- Bits 5:0 of the posted-interrupt descriptor address are all 0.
 *	- The posted-interrupt descriptor address does not set any bits
 *	  beyond the processor's physical-address width.
 * [Intel SDM]
 */
static void test_posted_intr(void)
{
	u32 saved_primary = vmcs_read(CPU_EXEC_CTRL0);
	u32 saved_secondary = vmcs_read(CPU_EXEC_CTRL1);
	u32 saved_pin = vmcs_read(PIN_CONTROLS);
	u32 exit_ctl_saved = vmcs_read(EXI_CONTROLS);
	u32 primary = saved_primary;
	u32 secondary = saved_secondary;
	u32 pin = saved_pin;
	u32 exit_ctl = exit_ctl_saved;
	u16 vec;
	int i;

	if (!((ctrl_pin_rev.clr & PIN_POST_INTR) &&
	    (ctrl_cpu_rev[1].clr & CPU_VINTD) &&
	    (ctrl_exit_rev.clr & EXI_INTA)))
		return;

	vmcs_write(CPU_EXEC_CTRL0, primary | CPU_SECONDARY | CPU_TPR_SHADOW);

	/*
	 * Test virtual-interrupt-delivery and acknowledge-interrupt-on-exit
	 */
	pin |= PIN_POST_INTR;
	vmcs_write(PIN_CONTROLS, pin);
	secondary &= ~CPU_VINTD;
	vmcs_write(CPU_EXEC_CTRL1, secondary);
	report_prefix_pushf("Process-posted-interrupts enabled; virtual-interrupt-delivery disabled");
	test_vmx_controls(false, false);
	report_prefix_pop();

	secondary |= CPU_VINTD;
	vmcs_write(CPU_EXEC_CTRL1, secondary);
	report_prefix_pushf("Process-posted-interrupts enabled; virtual-interrupt-delivery enabled");
	test_vmx_controls(false, false);
	report_prefix_pop();

	exit_ctl &= ~EXI_INTA;
	vmcs_write(EXI_CONTROLS, exit_ctl);
	report_prefix_pushf("Process-posted-interrupts enabled; virtual-interrupt-delivery enabled; acknowledge-interrupt-on-exit disabled");
	test_vmx_controls(false, false);
	report_prefix_pop();

	exit_ctl |= EXI_INTA;
	vmcs_write(EXI_CONTROLS, exit_ctl);
	report_prefix_pushf("Process-posted-interrupts enabled; virtual-interrupt-delivery enabled; acknowledge-interrupt-on-exit enabled");
	test_vmx_controls(true, false);
	report_prefix_pop();

	secondary &= ~CPU_VINTD;
	vmcs_write(CPU_EXEC_CTRL1, secondary);
	report_prefix_pushf("Process-posted-interrupts enabled; virtual-interrupt-delivery disabled; acknowledge-interrupt-on-exit enabled");
	test_vmx_controls(false, false);
	report_prefix_pop();

	secondary |= CPU_VINTD;
	vmcs_write(CPU_EXEC_CTRL1, secondary);
	report_prefix_pushf("Process-posted-interrupts enabled; virtual-interrupt-delivery enabled; acknowledge-interrupt-on-exit enabled");
	test_vmx_controls(true, false);
	report_prefix_pop();

	/*
	 * Test posted-interrupt notification vector
	 */
	for (i = 0; i < 8; i++) {
		vec = (1ul << i);
		vmcs_write(PINV, vec);
		report_prefix_pushf("Process-posted-interrupts enabled; posted-interrupt-notification-vector %u", vec);
		test_vmx_controls(true, false);
		report_prefix_pop();
	}
	for (i = 8; i < 16; i++) {
		vec = (1ul << i);
		vmcs_write(PINV, vec);
		report_prefix_pushf("Process-posted-interrupts enabled; posted-interrupt-notification-vector %u", vec);
		test_vmx_controls(false, false);
		report_prefix_pop();
	}

	vec &= ~(0xff << 8);
	vmcs_write(PINV, vec);
	report_prefix_pushf("Process-posted-interrupts enabled; posted-interrupt-notification-vector %u", vec);
	test_vmx_controls(true, false);
	report_prefix_pop();

	/*
	 * Test posted-interrupt descriptor addresss
	 */
	for (i = 0; i < 6; i++) {
		test_pi_desc_addr(1ul << i, false);
	}

	test_pi_desc_addr(0xf0, false);
	test_pi_desc_addr(0xff, false);
	test_pi_desc_addr(0x0f, false);
	test_pi_desc_addr(0x8000, true);
	test_pi_desc_addr(0x00, true);
	test_pi_desc_addr(0xc000, true);

	test_vmcs_page_values("process-posted interrupts", POSTED_INTR_DESC_ADDR, false, false);

	vmcs_write(CPU_EXEC_CTRL0, saved_primary);
	vmcs_write(CPU_EXEC_CTRL1, saved_secondary);
	vmcs_write(PIN_CONTROLS, saved_pin);
}

static void test_apic_ctls(void)
{
	test_apic_virt_addr();
	test_apic_access_addr();
	test_apic_virtual_ctls();
	test_virtual_intr_ctls();
	test_posted_intr();
}

/*
 * If the â€œenable VPIDâ€ VM-execution control is 1, the value of the
 * of the VPID VM-execution control field must not be 0000H.
 * [Intel SDM]
 */
static void test_vpid(void)
{
	u32 saved_primary = vmcs_read(CPU_EXEC_CTRL0);
	u32 saved_secondary = vmcs_read(CPU_EXEC_CTRL1);
	u16 vpid = 0x0000;
	int i;

	if (!((ctrl_cpu_rev[0].clr & CPU_SECONDARY) &&
	    (ctrl_cpu_rev[1].clr & CPU_VPID))) {
		test_skip("Secondary controls and/or VPID not supported");
		return;
	}

	vmcs_write(CPU_EXEC_CTRL0, saved_primary | CPU_SECONDARY);
	vmcs_write(CPU_EXEC_CTRL1, saved_secondary & ~CPU_VPID);
	vmcs_write(VPID, vpid);
	report_prefix_pushf("VPID disabled; VPID value %x", vpid);
	test_vmx_controls(true, false);
	report_prefix_pop();

	vmcs_write(CPU_EXEC_CTRL1, saved_secondary | CPU_VPID);
	report_prefix_pushf("VPID enabled; VPID value %x", vpid);
	test_vmx_controls(false, false);
	report_prefix_pop();

	for (i = 0; i < 16; i++) {
		vpid = (short)1 << i;;
		vmcs_write(VPID, vpid);
		report_prefix_pushf("VPID enabled; VPID value %x", vpid);
		test_vmx_controls(true, false);
		report_prefix_pop();
	}

	vmcs_write(CPU_EXEC_CTRL0, saved_primary);
	vmcs_write(CPU_EXEC_CTRL1, saved_secondary);
}

static void set_vtpr(unsigned vtpr)
{
	*(u32 *)phys_to_virt(vmcs_read(APIC_VIRT_ADDR) + APIC_TASKPRI) = vtpr;
}

static void try_tpr_threshold_and_vtpr(unsigned threshold, unsigned vtpr)
{
	bool valid = true;
	u32 primary = vmcs_read(CPU_EXEC_CTRL0);
	u32 secondary = vmcs_read(CPU_EXEC_CTRL1);

	if ((primary & CPU_TPR_SHADOW) &&
	    (!(primary & CPU_SECONDARY) ||
	     !(secondary & (CPU_VINTD | CPU_VIRT_APIC_ACCESSES))))
		valid = (threshold & 0xf) <= ((vtpr >> 4) & 0xf);

	set_vtpr(vtpr);
	report_prefix_pushf("TPR threshold 0x%x, VTPR.class 0x%x",
	    threshold, (vtpr >> 4) & 0xf);
	test_vmx_controls(valid, false);
	report_prefix_pop();
}

static void test_invalid_event_injection(void)
{
	u32 ent_intr_info_save = vmcs_read(ENT_INTR_INFO);
	u32 ent_intr_error_save = vmcs_read(ENT_INTR_ERROR);
	u32 ent_inst_len_save = vmcs_read(ENT_INST_LEN);
	u32 primary_save = vmcs_read(CPU_EXEC_CTRL0);
	u32 secondary_save = vmcs_read(CPU_EXEC_CTRL1);
	u64 guest_cr0_save = vmcs_read(GUEST_CR0);
	u32 ent_intr_info_base = INTR_INFO_VALID_MASK;
	u32 ent_intr_info, ent_intr_err, ent_intr_len;
	u32 cnt;

	/* Setup */
	report_prefix_push("invalid event injection");
	vmcs_write(ENT_INTR_ERROR, 0x00000000);
	vmcs_write(ENT_INST_LEN, 0x00000001);

	/* The field’s interruption type is not set to a reserved value. */
	ent_intr_info = ent_intr_info_base | INTR_TYPE_RESERVED | DE_VECTOR;
	report_prefix_pushf("%s, VM-entry intr info=0x%x",
			    "RESERVED interruption type invalid [-]",
			    ent_intr_info);
	vmcs_write(ENT_INTR_INFO, ent_intr_info);
	test_vmx_controls(false, false);
	report_prefix_pop();

	ent_intr_info = ent_intr_info_base | INTR_TYPE_EXT_INTR |
			DE_VECTOR;
	report_prefix_pushf("%s, VM-entry intr info=0x%x",
			    "RESERVED interruption type invalid [+]",
			    ent_intr_info);
	vmcs_write(ENT_INTR_INFO, ent_intr_info);
	test_vmx_controls(true, false);
	report_prefix_pop();

	/* If the interruption type is other event, the vector is 0. */
	ent_intr_info = ent_intr_info_base | INTR_TYPE_OTHER_EVENT | DB_VECTOR;
	report_prefix_pushf("%s, VM-entry intr info=0x%x",
			    "(OTHER EVENT && vector != 0) invalid [-]",
			    ent_intr_info);
	vmcs_write(ENT_INTR_INFO, ent_intr_info);
	test_vmx_controls(false, false);
	report_prefix_pop();

	/* If the interruption type is NMI, the vector is 2 (negative case). */
	ent_intr_info = ent_intr_info_base | INTR_TYPE_NMI_INTR | DE_VECTOR;
	report_prefix_pushf("%s, VM-entry intr info=0x%x",
			    "(NMI && vector != 2) invalid [-]", ent_intr_info);
	vmcs_write(ENT_INTR_INFO, ent_intr_info);
	test_vmx_controls(false, false);
	report_prefix_pop();

	/* If the interruption type is NMI, the vector is 2 (positive case). */
	ent_intr_info = ent_intr_info_base | INTR_TYPE_NMI_INTR | NMI_VECTOR;
	report_prefix_pushf("%s, VM-entry intr info=0x%x",
			    "(NMI && vector == 2) valid [+]", ent_intr_info);
	vmcs_write(ENT_INTR_INFO, ent_intr_info);
	test_vmx_controls(true, false);
	report_prefix_pop();

	/*
	 * If the interruption type
	 * is HW exception, the vector is at most 31.
	 */
	ent_intr_info = ent_intr_info_base | INTR_TYPE_HARD_EXCEPTION | 0x20;
	report_prefix_pushf("%s, VM-entry intr info=0x%x",
			    "(HW exception && vector > 31) invalid [-]",
			    ent_intr_info);
	vmcs_write(ENT_INTR_INFO, ent_intr_info);
	test_vmx_controls(false, false);
	report_prefix_pop();

	/*
	 * deliver-error-code is 1 iff either
	 * (a) the "unrestricted guest" VM-execution control is 0
	 * (b) CR0.PE is set.
	 */
	ent_intr_info = ent_intr_info_base | INTR_TYPE_HARD_EXCEPTION |
			GP_VECTOR;
	report_prefix_pushf("%s, VM-entry intr info=0x%x",
			    "error code <-> (!URG || prot_mode) [-]",
			    ent_intr_info);
	disable_unrestricted_guest();
	vmcs_write(GUEST_CR0, guest_cr0_save & ~X86_CR0_PE & ~X86_CR0_PG);
	vmcs_write(ENT_INTR_INFO, ent_intr_info);
	test_vmx_controls(false, false);
	report_prefix_pop();

	ent_intr_info = ent_intr_info_base | INTR_INFO_DELIVER_CODE_MASK |
			INTR_TYPE_HARD_EXCEPTION | GP_VECTOR;
	report_prefix_pushf("%s, VM-entry intr info=0x%x",
			    "error code <-> (!URG || prot_mode) [+]",
			    ent_intr_info);
	disable_unrestricted_guest();
	vmcs_write(GUEST_CR0, guest_cr0_save & ~X86_CR0_PE & ~X86_CR0_PG);
	vmcs_write(ENT_INTR_INFO, ent_intr_info);
	test_vmx_controls(true, false);
	report_prefix_pop();

	ent_intr_info = ent_intr_info_base | INTR_INFO_DELIVER_CODE_MASK |
			INTR_TYPE_HARD_EXCEPTION | GP_VECTOR;
	report_prefix_pushf("%s, VM-entry intr info=0x%x",
			    "error code <-> (!URG || prot_mode) [-]",
			    ent_intr_info);
	enable_unrestricted_guest();
	vmcs_write(GUEST_CR0, guest_cr0_save & ~X86_CR0_PE & ~X86_CR0_PG);
	vmcs_write(ENT_INTR_INFO, ent_intr_info);
	test_vmx_controls(false, false);
	report_prefix_pop();

	ent_intr_info = ent_intr_info_base | INTR_TYPE_HARD_EXCEPTION |
			GP_VECTOR;
	report_prefix_pushf("%s, VM-entry intr info=0x%x",
			    "error code <-> (!URG || prot_mode) [-]",
			    ent_intr_info);
	vmcs_write(GUEST_CR0, guest_cr0_save | X86_CR0_PE);
	vmcs_write(ENT_INTR_INFO, ent_intr_info);
	test_vmx_controls(false, false);
	report_prefix_pop();

	/* deliver-error-code is 1 iff the interruption type is HW exception */
	report_prefix_push("error code <-> HW exception");
	for (cnt = 0; cnt < 8; cnt++) {
		u32 exception_type_mask = cnt << 8;
		u32 deliver_error_code_mask =
			exception_type_mask != INTR_TYPE_HARD_EXCEPTION ?
			INTR_INFO_DELIVER_CODE_MASK : 0;

		ent_intr_info = ent_intr_info_base | deliver_error_code_mask |
				exception_type_mask | GP_VECTOR;
		report_prefix_pushf("VM-entry intr info=0x%x [-]",
				    ent_intr_info);
		vmcs_write(ENT_INTR_INFO, ent_intr_info);
		test_vmx_controls(false, false);
		report_prefix_pop();
	}
	report_prefix_pop();

	/*
	 * deliver-error-code is 1 iff the the vector
	 * indicates an exception that would normally deliver an error code
	 */
	report_prefix_push("error code <-> vector delivers error code");
	for (cnt = 0; cnt < 32; cnt++) {
		bool has_error_code = false;
		u32 deliver_error_code_mask;

		switch (cnt) {
		case DF_VECTOR:
		case TS_VECTOR:
		case NP_VECTOR:
		case SS_VECTOR:
		case GP_VECTOR:
		case PF_VECTOR:
		case AC_VECTOR:
			has_error_code = true;
		}

		/* Negative case */
		deliver_error_code_mask = has_error_code ?
						0 :
						INTR_INFO_DELIVER_CODE_MASK;
		ent_intr_info = ent_intr_info_base | deliver_error_code_mask |
				INTR_TYPE_HARD_EXCEPTION | cnt;
		report_prefix_pushf("VM-entry intr info=0x%x [-]",
				    ent_intr_info);
		vmcs_write(ENT_INTR_INFO, ent_intr_info);
		test_vmx_controls(false, false);
		report_prefix_pop();

		/* Positive case */
		deliver_error_code_mask = has_error_code ?
						INTR_INFO_DELIVER_CODE_MASK :
						0;
		ent_intr_info = ent_intr_info_base | deliver_error_code_mask |
				INTR_TYPE_HARD_EXCEPTION | cnt;
		report_prefix_pushf("VM-entry intr info=0x%x [+]",
				    ent_intr_info);
		vmcs_write(ENT_INTR_INFO, ent_intr_info);
		test_vmx_controls(true, false);
		report_prefix_pop();
	}
	report_prefix_pop();

	/* Reserved bits in the field (30:12) are 0. */
	report_prefix_push("reserved bits clear");
	for (cnt = 12; cnt <= 30; cnt++) {
		ent_intr_info = ent_intr_info_base |
				INTR_INFO_DELIVER_CODE_MASK |
				INTR_TYPE_HARD_EXCEPTION | GP_VECTOR |
				(1U << cnt);
		report_prefix_pushf("VM-entry intr info=0x%x [-]",
				    ent_intr_info);
		vmcs_write(ENT_INTR_INFO, ent_intr_info);
		test_vmx_controls(false, false);
		report_prefix_pop();
	}
	report_prefix_pop();

	/*
	 * If deliver-error-code is 1
	 * bits 31:15 of the VM-entry exception error-code field are 0.
	 */
	ent_intr_info = ent_intr_info_base | INTR_INFO_DELIVER_CODE_MASK |
			INTR_TYPE_HARD_EXCEPTION | GP_VECTOR;
	report_prefix_pushf("%s, VM-entry intr info=0x%x",
			    "VM-entry exception error code[31:15] clear",
			    ent_intr_info);
	vmcs_write(ENT_INTR_INFO, ent_intr_info);
	for (cnt = 15; cnt <= 31; cnt++) {
		ent_intr_err = 1U << cnt;
		report_prefix_pushf("VM-entry intr error=0x%x [-]",
				    ent_intr_err);
		vmcs_write(ENT_INTR_ERROR, ent_intr_err);
		test_vmx_controls(false, false);
		report_prefix_pop();
	}
	vmcs_write(ENT_INTR_ERROR, 0x00000000);
	report_prefix_pop();

	/*
	 * If the interruption type is software interrupt, software exception,
	 * or privileged software exception, the VM-entry instruction-length
	 * field is in the range 0–15.
	 */

	for (cnt = 0; cnt < 3; cnt++) {
		switch (cnt) {
		case 0:
			ent_intr_info = ent_intr_info_base |
					INTR_TYPE_SOFT_INTR;
			break;
		case 1:
			ent_intr_info = ent_intr_info_base |
					INTR_TYPE_SOFT_EXCEPTION;
			break;
		case 2:
			ent_intr_info = ent_intr_info_base |
					INTR_TYPE_PRIV_SW_EXCEPTION;
			break;
		}
		report_prefix_pushf("%s, VM-entry intr info=0x%x",
				    "VM-entry instruction-length check",
				    ent_intr_info);
		vmcs_write(ENT_INTR_INFO, ent_intr_info);

		/* Instruction length set to -1 (0xFFFFFFFF) should fail */
		ent_intr_len = -1;
		report_prefix_pushf("VM-entry intr length = 0x%x [-]",
				    ent_intr_len);
		vmcs_write(ENT_INST_LEN, ent_intr_len);
		test_vmx_controls(false, false);
		report_prefix_pop();

		/* Instruction length set to 16 should fail */
		ent_intr_len = 0x00000010;
		report_prefix_pushf("VM-entry intr length = 0x%x [-]",
				    ent_intr_len);
		vmcs_write(ENT_INST_LEN, 0x00000010);
		test_vmx_controls(false, false);
		report_prefix_pop();

		report_prefix_pop();
	}

	/* Cleanup */
	vmcs_write(ENT_INTR_INFO, ent_intr_info_save);
	vmcs_write(ENT_INTR_ERROR, ent_intr_error_save);
	vmcs_write(ENT_INST_LEN, ent_inst_len_save);
	vmcs_write(CPU_EXEC_CTRL0, primary_save);
	vmcs_write(CPU_EXEC_CTRL1, secondary_save);
	vmcs_write(GUEST_CR0, guest_cr0_save);
	report_prefix_pop();
}

/*
 * Test interesting vTPR values for a given TPR threshold.
 */
static void test_vtpr_values(unsigned threshold)
{
	try_tpr_threshold_and_vtpr(threshold, (threshold - 1) << 4);
	try_tpr_threshold_and_vtpr(threshold, threshold << 4);
	try_tpr_threshold_and_vtpr(threshold, (threshold + 1) << 4);
}

static void try_tpr_threshold(unsigned threshold)
{
	bool valid = true;

	u32 primary = vmcs_read(CPU_EXEC_CTRL0);
	u32 secondary = vmcs_read(CPU_EXEC_CTRL1);

	if ((primary & CPU_TPR_SHADOW) && !((primary & CPU_SECONDARY) &&
	    (secondary & CPU_VINTD)))
		valid = !(threshold >> 4);

	set_vtpr(-1);
	vmcs_write(TPR_THRESHOLD, threshold);
	report_prefix_pushf("TPR threshold 0x%x, VTPR.class 0xf", threshold);
	test_vmx_controls(valid, false);
	report_prefix_pop();

	if (valid)
		test_vtpr_values(threshold);
}

/*
 * Test interesting TPR threshold values.
 */
static void test_tpr_threshold_values(void)
{
	unsigned i;

	for (i = 0; i < 0x10; i++)
		try_tpr_threshold(i);
	for (i = 4; i < 32; i++)
		try_tpr_threshold(1u << i);
	try_tpr_threshold(-1u);
	try_tpr_threshold(0x7fffffff);
}

/*
 * This test covers the following two VM entry checks:
 *
 *      i) If the "use TPR shadow" VM-execution control is 1 and the
 *         "virtual-interrupt delivery" VM-execution control is 0, bits
 *         31:4 of the TPR threshold VM-execution control field must
	   be 0.
 *         [Intel SDM]
 *
 *      ii) If the "use TPR shadow" VM-execution control is 1, the
 *          "virtual-interrupt delivery" VM-execution control is 0
 *          and the "virtualize APIC accesses" VM-execution control
 *          is 0, the value of bits 3:0 of the TPR threshold VM-execution
 *          control field must not be greater than the value of bits
 *          7:4 of VTPR.
 *          [Intel SDM]
 */
static void test_tpr_threshold(void)
{
	u32 primary = vmcs_read(CPU_EXEC_CTRL0);
	void *virtual_apic_page;

	if (!(ctrl_cpu_rev[0].clr & CPU_TPR_SHADOW))
		return;

	virtual_apic_page = alloc_page();
	memset(virtual_apic_page, 0xff, PAGE_SIZE);
	vmcs_write(APIC_VIRT_ADDR, virt_to_phys(virtual_apic_page));

	vmcs_write(CPU_EXEC_CTRL0, primary & ~(CPU_TPR_SHADOW | CPU_SECONDARY));
	report_prefix_pushf("Use TPR shadow disabled, secondary controls disabled");
	test_tpr_threshold_values();
	report_prefix_pop();
	vmcs_write(CPU_EXEC_CTRL0, vmcs_read(CPU_EXEC_CTRL0) | CPU_TPR_SHADOW);
	report_prefix_pushf("Use TPR shadow enabled, secondary controls disabled");
	test_tpr_threshold_values();
	report_prefix_pop();

	if (!((ctrl_cpu_rev[0].clr & CPU_SECONDARY) &&
	    (ctrl_cpu_rev[1].clr & (CPU_VINTD  | CPU_VIRT_APIC_ACCESSES)))) {
		vmcs_write(CPU_EXEC_CTRL0, primary);
		return;
	}

	u32 secondary = vmcs_read(CPU_EXEC_CTRL1);

	if (ctrl_cpu_rev[1].clr & CPU_VINTD) {
		vmcs_write(CPU_EXEC_CTRL1, CPU_VINTD);
		report_prefix_pushf("Use TPR shadow enabled; secondary controls disabled; virtual-interrupt delivery enabled; virtualize APIC accesses disabled");
		test_tpr_threshold_values();
		report_prefix_pop();

		vmcs_write(CPU_EXEC_CTRL0,
			   vmcs_read(CPU_EXEC_CTRL0) | CPU_SECONDARY);
		report_prefix_pushf("Use TPR shadow enabled; secondary controls enabled; virtual-interrupt delivery enabled; virtualize APIC accesses disabled");
		test_tpr_threshold_values();
		report_prefix_pop();
	}

	if (ctrl_cpu_rev[1].clr & CPU_VIRT_APIC_ACCESSES) {
		vmcs_write(CPU_EXEC_CTRL0,
			   vmcs_read(CPU_EXEC_CTRL0) & ~CPU_SECONDARY);
		vmcs_write(CPU_EXEC_CTRL1, CPU_VIRT_APIC_ACCESSES);
		report_prefix_pushf("Use TPR shadow enabled; secondary controls disabled; virtual-interrupt delivery enabled; virtualize APIC accesses enabled");
		test_tpr_threshold_values();
		report_prefix_pop();

		vmcs_write(CPU_EXEC_CTRL0,
			   vmcs_read(CPU_EXEC_CTRL0) | CPU_SECONDARY);
		report_prefix_pushf("Use TPR shadow enabled; secondary controls enabled; virtual-interrupt delivery enabled; virtualize APIC accesses enabled");
		test_tpr_threshold_values();
		report_prefix_pop();
	}

	if ((ctrl_cpu_rev[1].clr &
	     (CPU_VINTD | CPU_VIRT_APIC_ACCESSES)) ==
	    (CPU_VINTD | CPU_VIRT_APIC_ACCESSES)) {
		vmcs_write(CPU_EXEC_CTRL0,
			   vmcs_read(CPU_EXEC_CTRL0) & ~CPU_SECONDARY);
		vmcs_write(CPU_EXEC_CTRL1,
			   CPU_VINTD | CPU_VIRT_APIC_ACCESSES);
		report_prefix_pushf("Use TPR shadow enabled; secondary controls disabled; virtual-interrupt delivery enabled; virtualize APIC accesses enabled");
		test_tpr_threshold_values();
		report_prefix_pop();

		vmcs_write(CPU_EXEC_CTRL0,
			   vmcs_read(CPU_EXEC_CTRL0) | CPU_SECONDARY);
		report_prefix_pushf("Use TPR shadow enabled; secondary controls enabled; virtual-interrupt delivery enabled; virtualize APIC accesses enabled");
		test_tpr_threshold_values();
		report_prefix_pop();
	}

	vmcs_write(CPU_EXEC_CTRL1, secondary);
	vmcs_write(CPU_EXEC_CTRL0, primary);
}

/*
 * This test verifies the following two vmentry checks:
 *
 *  If the "NMI exiting" VM-execution control is 0, "Virtual NMIs"
 *  VM-execution control must be 0.
 *  [Intel SDM]
 *
 *  If the “virtual NMIs” VM-execution control is 0, the “NMI-window
 *  exiting” VM-execution control must be 0.
 *  [Intel SDM]
 */
static void test_nmi_ctrls(void)
{
	u32 pin_ctrls, cpu_ctrls0, test_pin_ctrls, test_cpu_ctrls0;

	if ((ctrl_pin_rev.clr & (PIN_NMI | PIN_VIRT_NMI)) !=
	    (PIN_NMI | PIN_VIRT_NMI)) {
		test_skip("NMI exiting and Virtual NMIs are not supported !");
		return;
	}

	/* Save the controls so that we can restore them after our tests */
	pin_ctrls = vmcs_read(PIN_CONTROLS);
	cpu_ctrls0 = vmcs_read(CPU_EXEC_CTRL0);

	test_pin_ctrls = pin_ctrls & ~(PIN_NMI | PIN_VIRT_NMI);
	test_cpu_ctrls0 = cpu_ctrls0 & ~CPU_NMI_WINDOW;

	vmcs_write(PIN_CONTROLS, test_pin_ctrls);
	report_prefix_pushf("NMI-exiting disabled, virtual-NMIs disabled");
	test_vmx_controls(true, false);
	report_prefix_pop();

	vmcs_write(PIN_CONTROLS, test_pin_ctrls | PIN_VIRT_NMI);
	report_prefix_pushf("NMI-exiting disabled, virtual-NMIs enabled");
	test_vmx_controls(false, false);
	report_prefix_pop();

	vmcs_write(PIN_CONTROLS, test_pin_ctrls | (PIN_NMI | PIN_VIRT_NMI));
	report_prefix_pushf("NMI-exiting enabled, virtual-NMIs enabled");
	test_vmx_controls(true, false);
	report_prefix_pop();

	vmcs_write(PIN_CONTROLS, test_pin_ctrls | PIN_NMI);
	report_prefix_pushf("NMI-exiting enabled, virtual-NMIs disabled");
	test_vmx_controls(true, false);
	report_prefix_pop();

	if (!(ctrl_cpu_rev[0].clr & CPU_NMI_WINDOW)) {
		report_info("NMI-window exiting is not supported, skipping...");
		goto done;
	}

	vmcs_write(PIN_CONTROLS, test_pin_ctrls);
	vmcs_write(CPU_EXEC_CTRL0, test_cpu_ctrls0 | CPU_NMI_WINDOW);
	report_prefix_pushf("Virtual-NMIs disabled, NMI-window-exiting enabled");
	test_vmx_controls(false, false);
	report_prefix_pop();

	vmcs_write(PIN_CONTROLS, test_pin_ctrls);
	vmcs_write(CPU_EXEC_CTRL0, test_cpu_ctrls0);
	report_prefix_pushf("Virtual-NMIs disabled, NMI-window-exiting disabled");
	test_vmx_controls(true, false);
	report_prefix_pop();

	vmcs_write(PIN_CONTROLS, test_pin_ctrls | (PIN_NMI | PIN_VIRT_NMI));
	vmcs_write(CPU_EXEC_CTRL0, test_cpu_ctrls0 | CPU_NMI_WINDOW);
	report_prefix_pushf("Virtual-NMIs enabled, NMI-window-exiting enabled");
	test_vmx_controls(true, false);
	report_prefix_pop();

	vmcs_write(PIN_CONTROLS, test_pin_ctrls | (PIN_NMI | PIN_VIRT_NMI));
	vmcs_write(CPU_EXEC_CTRL0, test_cpu_ctrls0);
	report_prefix_pushf("Virtual-NMIs enabled, NMI-window-exiting disabled");
	test_vmx_controls(true, false);
	report_prefix_pop();

	/* Restore the controls to their original values */
	vmcs_write(CPU_EXEC_CTRL0, cpu_ctrls0);
done:
	vmcs_write(PIN_CONTROLS, pin_ctrls);
}


/*
 * Check that the virtual CPU checks all of the VMX controls as
 * documented in the Intel SDM.
 */
static void vmx_controls_test(void)
{
	/*
	 * Bit 1 of the guest's RFLAGS must be 1, or VM-entry will
	 * fail due to invalid guest state, should we make it that
	 * far.
	 */
	vmcs_write(GUEST_RFLAGS, 0);

	test_pin_based_ctls();
	test_primary_processor_based_ctls();
	test_secondary_processor_based_ctls();
	test_cr3_targets();
	test_io_bitmaps();
	test_msr_bitmap();
	test_apic_ctls();
	test_tpr_threshold();
	test_nmi_ctrls();
	test_invalid_event_injection();
	test_vpid();
}

static bool valid_vmcs_for_vmentry(void)
{
	struct vmcs *current_vmcs = NULL;

	if (vmcs_save(&current_vmcs))
		return false;

	return current_vmcs && !current_vmcs->hdr.shadow_vmcs;
}

static void try_vmentry_in_movss_shadow(void)
{
	u32 vm_inst_err;
	u32 flags;
	bool early_failure = false;
	u32 expected_flags = X86_EFLAGS_FIXED;
	bool valid_vmcs = valid_vmcs_for_vmentry();

	expected_flags |= valid_vmcs ? X86_EFLAGS_ZF : X86_EFLAGS_CF;

	/*
	 * Indirectly set VM_INST_ERR to 12 ("VMREAD/VMWRITE from/to
	 * unsupported VMCS component").
	 */
	vmcs_write(~0u, 0);

	__asm__ __volatile__ ("mov %[host_rsp], %%edx;"
			      "vmwrite %%rsp, %%rdx;"
			      "mov 0f, %%rax;"
			      "mov %[host_rip], %%edx;"
			      "vmwrite %%rax, %%rdx;"
			      "mov $-1, %%ah;"
			      "sahf;"
			      "mov %%ss, %%ax;"
			      "mov %%ax, %%ss;"
			      "vmlaunch;"
			      "mov $1, %[early_failure];"
			      "0: lahf;"
			      "movzbl %%ah, %[flags]"
			      : [early_failure] "+r" (early_failure),
				[flags] "=&a" (flags)
			      : [host_rsp] "i" (HOST_RSP),
				[host_rip] "i" (HOST_RIP)
			      : "rdx", "cc", "memory");
	vm_inst_err = vmcs_read(VMX_INST_ERROR);

	report("Early VM-entry failure", early_failure);
	report("RFLAGS[8:0] is %x (actual %x)", flags == expected_flags,
	       expected_flags, flags);
	if (valid_vmcs)
		report("VM-instruction error is %d (actual %d)",
		       vm_inst_err == VMXERR_ENTRY_EVENTS_BLOCKED_BY_MOV_SS,
		       VMXERR_ENTRY_EVENTS_BLOCKED_BY_MOV_SS, vm_inst_err);
}

static void vmentry_movss_shadow_test(void)
{
	struct vmcs *orig_vmcs;

	TEST_ASSERT(!vmcs_save(&orig_vmcs));

	/*
	 * Set the launched flag on the current VMCS to verify the correct
	 * error priority, below.
	 */
	test_set_guest(v2_null_test_guest);
	enter_guest();

	/*
	 * With bit 1 of the guest's RFLAGS clear, VM-entry should
	 * fail due to invalid guest state (if we make it that far).
	 */
	vmcs_write(GUEST_RFLAGS, 0);

	/*
	 * "VM entry with events blocked by MOV SS" takes precedence over
	 * "VMLAUNCH with non-clear VMCS."
	 */
	report_prefix_push("valid current-VMCS");
	try_vmentry_in_movss_shadow();
	report_prefix_pop();

	/*
	 * VMfailInvalid takes precedence over "VM entry with events
	 * blocked by MOV SS."
	 */
	TEST_ASSERT(!vmcs_clear(orig_vmcs));
	report_prefix_push("no current-VMCS");
	try_vmentry_in_movss_shadow();
	report_prefix_pop();

	TEST_ASSERT(!make_vmcs_current(orig_vmcs));
	vmcs_write(GUEST_RFLAGS, X86_EFLAGS_FIXED);
}

#define X86_FEATURE_PCID       (1 << 17)
#define X86_FEATURE_MCE        (1 << 7)

static int write_cr4_checking(unsigned long val)
{
	asm volatile(ASM_TRY("1f")
		     "mov %0, %%cr4\n\t"
		     "1:": : "r" (val));
	return exception_vector();
}

static void vmx_cr_load_test(void)
{
	struct cpuid _cpuid = cpuid(1);
	unsigned long cr4 = read_cr4(), cr3 = read_cr3();

	if (!(_cpuid.c & X86_FEATURE_PCID)) {
		report_skip("PCID not detected");
		return;
	}
	if (!(_cpuid.d & X86_FEATURE_MCE)) {
		report_skip("MCE not detected");
		return;
	}

	TEST_ASSERT(!(cr4 & (X86_CR4_PCIDE | X86_CR4_MCE)));
	TEST_ASSERT(!(cr3 & X86_CR3_PCID_MASK));

	/* Enable PCID for L1. */
	cr4 |= X86_CR4_PCIDE;
	cr3 |= 0x1;
	TEST_ASSERT(!write_cr4_checking(cr4));
	write_cr3(cr3);

	test_set_guest(v2_null_test_guest);
	vmcs_write(HOST_CR4, cr4);
	vmcs_write(HOST_CR3, cr3);
	enter_guest();

	/*
	 * No exception is expected.
	 *
	 * NB. KVM loads the last guest write to CR4 into CR4 read
	 *     shadow. In order to trigger an exit to KVM, we can set a
	 *     bit that was zero in the above CR4 write and is owned by
	 *     KVM. We choose to set CR4.MCE, which shall have no side
	 *     effect because normally no guest MCE (e.g., as the result
	 *     of bad memory) would happen during this test.
	 */
	TEST_ASSERT(!write_cr4_checking(cr4 | X86_CR4_MCE));

	/* Cleanup L1 state: disable PCID. */
	write_cr3(cr3 & ~X86_CR3_PCID_MASK);
	TEST_ASSERT(!write_cr4_checking(cr4 & ~X86_CR4_PCIDE));
}

static bool cpu_has_apicv(void)
{
	return ((ctrl_cpu_rev[1].clr & CPU_APIC_REG_VIRT) &&
		(ctrl_cpu_rev[1].clr & CPU_VINTD) &&
		(ctrl_pin_rev.clr & PIN_POST_INTR));
}

static void trigger_ioapic_scan_thread(void *data)
{
	/* Wait until other CPU entered L2 */
	while (vmx_get_test_stage() != 1)
		;

	/* Trigger ioapic scan */
	ioapic_set_redir(0xf, 0x79, TRIGGER_LEVEL);
	vmx_set_test_stage(2);
}

static void irq_79_handler_guest(isr_regs_t *regs)
{
	eoi();

	/* L1 expects vmexit on VMX_VMCALL and not VMX_EOI_INDUCED */
	vmcall();
}

/*
 * Constant for num of busy-loop iterations after which
 * a timer interrupt should have happened in host
 */
#define TIMER_INTERRUPT_DELAY 100000000

static void vmx_eoi_bitmap_ioapic_scan_test_guest(void)
{
	handle_irq(0x79, irq_79_handler_guest);
	irq_enable();

	/* Signal to L1 CPU to trigger ioapic scan */
	vmx_set_test_stage(1);
	/* Wait until L1 CPU to trigger ioapic scan */
	while (vmx_get_test_stage() != 2)
		;

	/*
	 * Wait for L0 timer interrupt to be raised while we run in L2
	 * such that L0 will process the IOAPIC scan request before
	 * resuming L2
	 */
	delay(TIMER_INTERRUPT_DELAY);

	asm volatile ("int $0x79");
}

static void vmx_eoi_bitmap_ioapic_scan_test(void)
{
	void *msr_bitmap;
	void *virtual_apic_page;

	if (!cpu_has_apicv() || (cpu_count() < 2)) {
		report_skip(__func__);
		return;
	}

	msr_bitmap = alloc_page();
	virtual_apic_page = alloc_page();

	u64 cpu_ctrl_0 = CPU_SECONDARY | CPU_TPR_SHADOW | CPU_MSR_BITMAP;
	u64 cpu_ctrl_1 = CPU_VINTD | CPU_VIRT_X2APIC;

	memset(msr_bitmap, 0x0, PAGE_SIZE);
	vmcs_write(MSR_BITMAP, (u64)msr_bitmap);

	vmcs_write(APIC_VIRT_ADDR, (u64)virtual_apic_page);
	vmcs_write(PIN_CONTROLS, vmcs_read(PIN_CONTROLS) | PIN_EXTINT);

	vmcs_write(EOI_EXIT_BITMAP0, 0x0);
	vmcs_write(EOI_EXIT_BITMAP1, 0x0);
	vmcs_write(EOI_EXIT_BITMAP2, 0x0);
	vmcs_write(EOI_EXIT_BITMAP3, 0x0);

	vmcs_write(CPU_EXEC_CTRL0, vmcs_read(CPU_EXEC_CTRL0) | cpu_ctrl_0);
	vmcs_write(CPU_EXEC_CTRL1, vmcs_read(CPU_EXEC_CTRL1) | cpu_ctrl_1);

	on_cpu_async(1, trigger_ioapic_scan_thread, NULL);
	test_set_guest(vmx_eoi_bitmap_ioapic_scan_test_guest);

	/*
	 * Launch L2.
	 * We expect the exit reason to be VMX_VMCALL (and not EOI INDUCED).
	 * In case the reason isn't VMX_VMCALL, the asserion inside
	 * skip_exit_vmcall() will fail.
	 */
	enter_guest();
	skip_exit_vmcall();

	/* Let L2 finish */
	enter_guest();
	report(__func__, 1);
}

static void set_irq_line_thread(void *data)
{
	/* Wait until other CPU entered L2 */
	while (vmx_get_test_stage() != 1)
		;

	/* Set irq-line 0xf to raise vector 0x78 for vCPU 0 */
	ioapic_set_redir(0xf, 0x78, TRIGGER_LEVEL);
	vmx_set_test_stage(2);
}

static bool irq_78_handler_vmcall_before_eoi;
static void irq_78_handler_guest(isr_regs_t *regs)
{
	set_irq_line(0xf, 0);
	if (irq_78_handler_vmcall_before_eoi)
		vmcall();
	eoi();
	vmcall();
}

static void vmx_apic_passthrough_guest(void)
{
	handle_irq(0x78, irq_78_handler_guest);
	irq_enable();

	/* If requested, wait for other CPU to trigger ioapic scan */
	if (vmx_get_test_stage() < 1) {
		vmx_set_test_stage(1);
		while (vmx_get_test_stage() != 2)
			;
	}

	set_irq_line(0xf, 1);
}

static void vmx_apic_passthrough(bool set_irq_line_from_thread)
{
	void *msr_bitmap;

	if (set_irq_line_from_thread && (cpu_count() < 2)) {
		report_skip(__func__);
		return;
	}

	msr_bitmap = alloc_page();

	u64 cpu_ctrl_0 = CPU_SECONDARY | CPU_MSR_BITMAP;
	u64 cpu_ctrl_1 = 0;

	memset(msr_bitmap, 0x0, PAGE_SIZE);
	vmcs_write(MSR_BITMAP, (u64)msr_bitmap);

	vmcs_write(PIN_CONTROLS, vmcs_read(PIN_CONTROLS) & ~PIN_EXTINT);

	vmcs_write(CPU_EXEC_CTRL0, vmcs_read(CPU_EXEC_CTRL0) | cpu_ctrl_0);
	vmcs_write(CPU_EXEC_CTRL1, vmcs_read(CPU_EXEC_CTRL1) | cpu_ctrl_1);

	if (set_irq_line_from_thread) {
		irq_78_handler_vmcall_before_eoi = false;
		on_cpu_async(1, set_irq_line_thread, NULL);
	} else {
		irq_78_handler_vmcall_before_eoi = true;
		ioapic_set_redir(0xf, 0x78, TRIGGER_LEVEL);
		vmx_set_test_stage(2);
	}
	test_set_guest(vmx_apic_passthrough_guest);

	if (irq_78_handler_vmcall_before_eoi) {
		/* Before EOI remote_irr should still be set */
		enter_guest();
		skip_exit_vmcall();
		TEST_ASSERT_EQ_MSG(1, (int)ioapic_read_redir(0xf).remote_irr,
			"IOAPIC pass-through: remote_irr=1 before EOI");
	}

	/* After EOI remote_irr should be cleared */
	enter_guest();
	skip_exit_vmcall();
	TEST_ASSERT_EQ_MSG(0, (int)ioapic_read_redir(0xf).remote_irr,
		"IOAPIC pass-through: remote_irr=0 after EOI");

	/* Let L2 finish */
	enter_guest();
	report(__func__, 1);
}

static void vmx_apic_passthrough_test(void)
{
	vmx_apic_passthrough(false);
}

static void vmx_apic_passthrough_thread_test(void)
{
	vmx_apic_passthrough(true);
}

enum vmcs_access {
	ACCESS_VMREAD,
	ACCESS_VMWRITE,
	ACCESS_NONE,
};

struct vmcs_shadow_test_common {
	enum vmcs_access op;
	enum Reason reason;
	u64 field;
	u64 value;
	u64 flags;
	u64 time;
} l1_l2_common;

static inline u64 vmread_flags(u64 field, u64 *val)
{
	u64 flags;

	asm volatile ("vmread %2, %1; pushf; pop %0"
		      : "=r" (flags), "=rm" (*val) : "r" (field) : "cc");
	return flags & X86_EFLAGS_ALU;
}

static inline u64 vmwrite_flags(u64 field, u64 val)
{
	u64 flags;

	asm volatile ("vmwrite %1, %2; pushf; pop %0"
		      : "=r"(flags) : "rm" (val), "r" (field) : "cc");
	return flags & X86_EFLAGS_ALU;
}

static void vmx_vmcs_shadow_test_guest(void)
{
	struct vmcs_shadow_test_common *c = &l1_l2_common;
	u64 start;

	while (c->op != ACCESS_NONE) {
		start = rdtsc();
		switch (c->op) {
		default:
			c->flags = -1ull;
			break;
		case ACCESS_VMREAD:
			c->flags = vmread_flags(c->field, &c->value);
			break;
		case ACCESS_VMWRITE:
			c->flags = vmwrite_flags(c->field, 0);
			break;
		}
		c->time = rdtsc() - start;
		vmcall();
	}
}

static u64 vmread_from_shadow(u64 field)
{
	struct vmcs *primary;
	struct vmcs *shadow;
	u64 value;

	TEST_ASSERT(!vmcs_save(&primary));
	shadow = (struct vmcs *)vmcs_read(VMCS_LINK_PTR);
	TEST_ASSERT(!make_vmcs_current(shadow));
	value = vmcs_read(field);
	TEST_ASSERT(!make_vmcs_current(primary));
	return value;
}

static u64 vmwrite_to_shadow(u64 field, u64 value)
{
	struct vmcs *primary;
	struct vmcs *shadow;

	TEST_ASSERT(!vmcs_save(&primary));
	shadow = (struct vmcs *)vmcs_read(VMCS_LINK_PTR);
	TEST_ASSERT(!make_vmcs_current(shadow));
	vmcs_write(field, value);
	value = vmcs_read(field);
	TEST_ASSERT(!make_vmcs_current(primary));
	return value;
}

static void vmcs_shadow_test_access(u8 *bitmap[2], enum vmcs_access access)
{
	struct vmcs_shadow_test_common *c = &l1_l2_common;

	c->op = access;
	vmcs_write(VMX_INST_ERROR, 0);
	enter_guest();
	c->reason = vmcs_read(EXI_REASON) & 0xffff;
	if (c->reason != VMX_VMCALL) {
		skip_exit_insn();
		enter_guest();
	}
	skip_exit_vmcall();
}

static void vmcs_shadow_test_field(u8 *bitmap[2], u64 field)
{
	struct vmcs_shadow_test_common *c = &l1_l2_common;
	struct vmcs *shadow;
	u64 value;
	uintptr_t flags[2];
	bool good_shadow;
	u32 vmx_inst_error;

	report_prefix_pushf("field %lx", field);
	c->field = field;

	shadow = (struct vmcs *)vmcs_read(VMCS_LINK_PTR);
	if (shadow != (struct vmcs *)-1ull) {
		flags[ACCESS_VMREAD] = vmread_flags(field, &value);
		flags[ACCESS_VMWRITE] = vmwrite_flags(field, value);
		good_shadow = !flags[ACCESS_VMREAD] && !flags[ACCESS_VMWRITE];
	} else {
		/*
		 * When VMCS link pointer is -1ull, VMWRITE/VMREAD on
		 * shadowed-fields should fail with setting RFLAGS.CF.
		 */
		flags[ACCESS_VMREAD] = X86_EFLAGS_CF;
		flags[ACCESS_VMWRITE] = X86_EFLAGS_CF;
		good_shadow = false;
	}

	/* Intercept both VMREAD and VMWRITE. */
	report_prefix_push("no VMREAD/VMWRITE permission");
	/* VMWRITE/VMREAD done on reserved-bit should always intercept */
	if (!(field >> VMCS_FIELD_RESERVED_SHIFT)) {
		set_bit(field, bitmap[ACCESS_VMREAD]);
		set_bit(field, bitmap[ACCESS_VMWRITE]);
	}
	vmcs_shadow_test_access(bitmap, ACCESS_VMWRITE);
	report("not shadowed for VMWRITE", c->reason == VMX_VMWRITE);
	vmcs_shadow_test_access(bitmap, ACCESS_VMREAD);
	report("not shadowed for VMREAD", c->reason == VMX_VMREAD);
	report_prefix_pop();

	if (field >> VMCS_FIELD_RESERVED_SHIFT)
		goto out;

	/* Permit shadowed VMREAD. */
	report_prefix_push("VMREAD permission only");
	clear_bit(field, bitmap[ACCESS_VMREAD]);
	set_bit(field, bitmap[ACCESS_VMWRITE]);
	if (good_shadow)
		value = vmwrite_to_shadow(field, MAGIC_VAL_1 + field);
	vmcs_shadow_test_access(bitmap, ACCESS_VMWRITE);
	report("not shadowed for VMWRITE", c->reason == VMX_VMWRITE);
	vmcs_shadow_test_access(bitmap, ACCESS_VMREAD);
	vmx_inst_error = vmcs_read(VMX_INST_ERROR);
	report("shadowed for VMREAD (in %ld cycles)", c->reason == VMX_VMCALL,
	       c->time);
	report("ALU flags after VMREAD (%lx) are as expected (%lx)",
	       c->flags == flags[ACCESS_VMREAD],
	       c->flags, flags[ACCESS_VMREAD]);
	if (good_shadow)
		report("value read from shadow (%lx) is as expected (%lx)",
		       c->value == value, c->value, value);
	else if (shadow != (struct vmcs *)-1ull && flags[ACCESS_VMREAD])
		report("VMX_INST_ERROR (%d) is as expected (%d)",
		       vmx_inst_error == VMXERR_UNSUPPORTED_VMCS_COMPONENT,
		       vmx_inst_error, VMXERR_UNSUPPORTED_VMCS_COMPONENT);
	report_prefix_pop();

	/* Permit shadowed VMWRITE. */
	report_prefix_push("VMWRITE permission only");
	set_bit(field, bitmap[ACCESS_VMREAD]);
	clear_bit(field, bitmap[ACCESS_VMWRITE]);
	if (good_shadow)
		vmwrite_to_shadow(field, MAGIC_VAL_1 + field);
	vmcs_shadow_test_access(bitmap, ACCESS_VMWRITE);
	vmx_inst_error = vmcs_read(VMX_INST_ERROR);
	report("shadowed for VMWRITE (in %ld cycles)", c->reason == VMX_VMCALL,
		c->time);
	report("ALU flags after VMWRITE (%lx) are as expected (%lx)",
	       c->flags == flags[ACCESS_VMREAD],
	       c->flags, flags[ACCESS_VMREAD]);
	if (good_shadow) {
		value = vmread_from_shadow(field);
		report("shadow VMCS value (%lx) is as expected (%lx)",
		       value == 0, value, 0ul);
	} else if (shadow != (struct vmcs *)-1ull && flags[ACCESS_VMWRITE]) {
		report("VMX_INST_ERROR (%d) is as expected (%d)",
		       vmx_inst_error == VMXERR_UNSUPPORTED_VMCS_COMPONENT,
		       vmx_inst_error, VMXERR_UNSUPPORTED_VMCS_COMPONENT);
	}
	vmcs_shadow_test_access(bitmap, ACCESS_VMREAD);
	report("not shadowed for VMREAD", c->reason == VMX_VMREAD);
	report_prefix_pop();

	/* Permit shadowed VMREAD and VMWRITE. */
	report_prefix_push("VMREAD and VMWRITE permission");
	clear_bit(field, bitmap[ACCESS_VMREAD]);
	clear_bit(field, bitmap[ACCESS_VMWRITE]);
	if (good_shadow)
		vmwrite_to_shadow(field, MAGIC_VAL_1 + field);
	vmcs_shadow_test_access(bitmap, ACCESS_VMWRITE);
	vmx_inst_error = vmcs_read(VMX_INST_ERROR);
	report("shadowed for VMWRITE (in %ld cycles)", c->reason == VMX_VMCALL,
		c->time);
	report("ALU flags after VMWRITE (%lx) are as expected (%lx)",
	       c->flags == flags[ACCESS_VMREAD],
	       c->flags, flags[ACCESS_VMREAD]);
	if (good_shadow) {
		value = vmread_from_shadow(field);
		report("shadow VMCS value (%lx) is as expected (%lx)",
		       value == 0, value, 0ul);
	} else if (shadow != (struct vmcs *)-1ull && flags[ACCESS_VMWRITE]) {
		report("VMX_INST_ERROR (%d) is as expected (%d)",
		       vmx_inst_error == VMXERR_UNSUPPORTED_VMCS_COMPONENT,
		       vmx_inst_error, VMXERR_UNSUPPORTED_VMCS_COMPONENT);
	}
	vmcs_shadow_test_access(bitmap, ACCESS_VMREAD);
	vmx_inst_error = vmcs_read(VMX_INST_ERROR);
	report("shadowed for VMREAD (in %ld cycles)", c->reason == VMX_VMCALL,
	       c->time);
	report("ALU flags after VMREAD (%lx) are as expected (%lx)",
	       c->flags == flags[ACCESS_VMREAD],
	       c->flags, flags[ACCESS_VMREAD]);
	if (good_shadow)
		report("value read from shadow (%lx) is as expected (%lx)",
		       c->value == 0, c->value, 0ul);
	else if (shadow != (struct vmcs *)-1ull && flags[ACCESS_VMREAD])
		report("VMX_INST_ERROR (%d) is as expected (%d)",
		       vmx_inst_error == VMXERR_UNSUPPORTED_VMCS_COMPONENT,
		       vmx_inst_error, VMXERR_UNSUPPORTED_VMCS_COMPONENT);
	report_prefix_pop();

out:
	report_prefix_pop();
}

static void vmx_vmcs_shadow_test_body(u8 *bitmap[2])
{
	unsigned base;
	unsigned index;
	unsigned bit;
	unsigned highest_index = rdmsr(MSR_IA32_VMX_VMCS_ENUM);

	/* Run test on all possible valid VMCS fields */
	for (base = 0;
	     base < (1 << VMCS_FIELD_RESERVED_SHIFT);
	     base += (1 << VMCS_FIELD_TYPE_SHIFT))
		for (index = 0; index <= highest_index; index++)
			vmcs_shadow_test_field(bitmap, base + index);

	/*
	 * Run tests on some invalid VMCS fields
	 * (Have reserved bit set).
	 */
	for (bit = VMCS_FIELD_RESERVED_SHIFT; bit < VMCS_FIELD_BIT_SIZE; bit++)
		vmcs_shadow_test_field(bitmap, (1ull << bit));
}

static void vmx_vmcs_shadow_test(void)
{
	u8 *bitmap[2];
	struct vmcs *shadow;

	if (!(ctrl_cpu_rev[0].clr & CPU_SECONDARY)) {
		printf("\t'Activate secondary controls' not supported.\n");
		return;
	}

	if (!(ctrl_cpu_rev[1].clr & CPU_SHADOW_VMCS)) {
		printf("\t'VMCS shadowing' not supported.\n");
		return;
	}

	if (!(rdmsr(MSR_IA32_VMX_MISC) &
	      MSR_IA32_VMX_MISC_VMWRITE_SHADOW_RO_FIELDS)) {
		printf("\tVMWRITE can't modify VM-exit information fields.\n");
		return;
	}

	test_set_guest(vmx_vmcs_shadow_test_guest);

	bitmap[ACCESS_VMREAD] = alloc_page();
	bitmap[ACCESS_VMWRITE] = alloc_page();

	vmcs_write(VMREAD_BITMAP, virt_to_phys(bitmap[ACCESS_VMREAD]));
	vmcs_write(VMWRITE_BITMAP, virt_to_phys(bitmap[ACCESS_VMWRITE]));

	shadow = alloc_page();
	shadow->hdr.revision_id = basic.revision;
	shadow->hdr.shadow_vmcs = 1;
	TEST_ASSERT(!vmcs_clear(shadow));

	vmcs_clear_bits(CPU_EXEC_CTRL0, CPU_RDTSC);
	vmcs_set_bits(CPU_EXEC_CTRL0, CPU_SECONDARY);
	vmcs_set_bits(CPU_EXEC_CTRL1, CPU_SHADOW_VMCS);

	vmcs_write(VMCS_LINK_PTR, virt_to_phys(shadow));
	report_prefix_push("valid link pointer");
	vmx_vmcs_shadow_test_body(bitmap);
	report_prefix_pop();

	vmcs_write(VMCS_LINK_PTR, -1ull);
	report_prefix_push("invalid link pointer");
	vmx_vmcs_shadow_test_body(bitmap);
	report_prefix_pop();

	l1_l2_common.op = ACCESS_NONE;
	enter_guest();
}

#define TEST(name) { #name, .v2 = name }

/* name/init/guest_main/exit_handler/syscall_handler/guest_regs */
struct vmx_test vmx_tests[] = {
	{ "null", NULL, basic_guest_main, basic_exit_handler, NULL, {0} },
	{ "vmenter", NULL, vmenter_main, vmenter_exit_handler, NULL, {0} },
	{ "preemption timer", preemption_timer_init, preemption_timer_main,
		preemption_timer_exit_handler, NULL, {0} },
	{ "control field PAT", test_ctrl_pat_init, test_ctrl_pat_main,
		test_ctrl_pat_exit_handler, NULL, {0} },
	{ "control field EFER", test_ctrl_efer_init, test_ctrl_efer_main,
		test_ctrl_efer_exit_handler, NULL, {0} },
	{ "CR shadowing", NULL, cr_shadowing_main,
		cr_shadowing_exit_handler, NULL, {0} },
	{ "I/O bitmap", iobmp_init, iobmp_main, iobmp_exit_handler,
		NULL, {0} },
	{ "instruction intercept", insn_intercept_init, insn_intercept_main,
		insn_intercept_exit_handler, NULL, {0} },
	{ "EPT A/D disabled", ept_init, ept_main, ept_exit_handler, NULL, {0} },
	{ "EPT A/D enabled", eptad_init, eptad_main, eptad_exit_handler, NULL, {0} },
	{ "PML", pml_init, pml_main, pml_exit_handler, NULL, {0} },
	{ "VPID", vpid_init, vpid_main, vpid_exit_handler, NULL, {0} },
	{ "interrupt", interrupt_init, interrupt_main,
		interrupt_exit_handler, NULL, {0} },
	{ "debug controls", dbgctls_init, dbgctls_main, dbgctls_exit_handler,
		NULL, {0} },
	{ "MSR switch", msr_switch_init, msr_switch_main,
		msr_switch_exit_handler, NULL, {0}, msr_switch_entry_failure },
	{ "vmmcall", vmmcall_init, vmmcall_main, vmmcall_exit_handler, NULL, {0} },
	{ "disable RDTSCP", disable_rdtscp_init, disable_rdtscp_main,
		disable_rdtscp_exit_handler, NULL, {0} },
	{ "int3", int3_init, int3_guest_main, int3_exit_handler, NULL, {0} },
	{ "into", into_init, into_guest_main, into_exit_handler, NULL, {0} },
	{ "exit_monitor_from_l2_test", NULL, exit_monitor_from_l2_main,
		exit_monitor_from_l2_handler, NULL, {0} },
	/* Basic V2 tests. */
	TEST(v2_null_test),
	TEST(v2_multiple_entries_test),
	TEST(fixture_test_case1),
	TEST(fixture_test_case2),
	/* Opcode tests. */
	TEST(invvpid_test_v2),
	/* VM-entry tests */
	TEST(vmx_controls_test),
	TEST(vmentry_movss_shadow_test),
	/* APICv tests */
	TEST(vmx_eoi_bitmap_ioapic_scan_test),
	/* APIC pass-through tests */
	TEST(vmx_apic_passthrough_test),
	TEST(vmx_apic_passthrough_thread_test),
	/* VMCS Shadowing tests */
	TEST(vmx_vmcs_shadow_test),
	/* Regression tests */
	TEST(vmx_cr_load_test),
	/* EPT access tests. */
	TEST(ept_access_test_not_present),
	TEST(ept_access_test_read_only),
	TEST(ept_access_test_write_only),
	TEST(ept_access_test_read_write),
	TEST(ept_access_test_execute_only),
	TEST(ept_access_test_read_execute),
	TEST(ept_access_test_write_execute),
	TEST(ept_access_test_read_write_execute),
	TEST(ept_access_test_reserved_bits),
	TEST(ept_access_test_ignored_bits),
	TEST(ept_access_test_paddr_not_present_ad_disabled),
	TEST(ept_access_test_paddr_not_present_ad_enabled),
	TEST(ept_access_test_paddr_read_only_ad_disabled),
	TEST(ept_access_test_paddr_read_only_ad_enabled),
	TEST(ept_access_test_paddr_read_write),
	TEST(ept_access_test_paddr_read_write_execute),
	TEST(ept_access_test_paddr_read_execute_ad_disabled),
	TEST(ept_access_test_paddr_read_execute_ad_enabled),
	TEST(ept_access_test_paddr_not_present_page_fault),
	TEST(ept_access_test_force_2m_page),
	{ NULL, NULL, NULL, NULL, NULL, {0} },
};
