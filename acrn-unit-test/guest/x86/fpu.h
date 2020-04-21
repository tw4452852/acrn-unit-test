#ifndef _FPU_H_
#define _FPU_H_

#include "apic-defs.h"

#define MSR_EFER_ME		(1ULL << 8)
#define EDX_PAT			(1ULL << 16)

#define INIT_BASE_REG_ADDR				0x6000UL
#define STARTUP_BASE_REG_ADDR			0x7000UL
#define UNCHANGED_BASE_REG_ADDR			0x8000UL

#define STARTUP_CR0_REG_ADDR			STARTUP_BASE_REG_ADDR
#define INIT_FPU_SAVE_ADDR				0x6500UL
#define INIT_UNCHANGED_FPU_SAVE_ADDR	0x8500UL

#define INVALID_ADDR_OUT_PHY			(3UL << 30)

#define RING1_CS32_GDT_DESC (0x00cfbb000000ffffULL)
#define RING1_CS64_GDT_DESC	(0x00afbb000000ffffULL)
#define RING1_DS_GDT_DESC	(0x00cfb3000000ffffULL)

#define RING2_CS32_GDT_DESC (0x00cfdb000000ffffULL)
#define RING2_CS64_GDT_DESC (0x00afdb000000ffffULL)
#define RING2_DS_GDT_DESC	(0x00cfd3000000ffffULL)
#endif
