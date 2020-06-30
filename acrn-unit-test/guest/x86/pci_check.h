#ifndef __PCI_CHECK_H__
#define __PCI_CHECK_H__

#define HCIVERSION	(0x2U)
#define GBECSR_00	(0x00U)
#define PCI_CONFIG_SPACE_SIZE		0x100U
#define PCI_CONFIG_RESERVE		0x36
#define BAR_REMAP_BASE		0xDFF00000
#define BAR_REMAP_BASE_1		0xF0000000
#define BAR_REMAP_BASE_2		0xDFFF0000
#define PCI_NET_STATUS_VAL_NATIVE		(0x0010)
#define PCI_USB_STATUS_VAL_NATIVE		(0x0290)
#define	MSI_NET_IRQ_VECTOR	(0x40)
#define VALID_APIC_ID_1 (0x01)
#define INVALID_APIC_ID_A (0x0A)
#define INVALID_APIC_ID_B (0xFFFF)
#define INVALID_REG_VALUE_U	(0xFFFFFFFFU)
#define PCI_EXIST_DEV_NUM	3
#define BAR_HOLE_LOW	0xC0000000
#define BAR_HOLE_HIGH 0xDFFFFFFF
#define BAR_ALLIGN_USB 0x10000
#define BAR_ALLIGN_NET 0x100000
#define PCI_NET_REVISION_ID	(0x21)
#define PCI_USB_REVISION_ID (0x21)
#define PCI_USB_VENDOR_ID	(0x8086)
#define PCI_NET_VENDOR_ID	(0x8086)
#define PCI_USB_HEADER_TYPE	(0x80)
#define PCI_NET_HEADER_TYPE	(0x00)
#define PCI_NET_DEVICE_ID	(0x156f)
#define PCI_USB_DEVICE_ID	(0x9d2f)
#define HCIVERSION_VALUE	(0x100)
#define GBECSR_00_VALUE		(0x180240)
#define HOSTBRIDGE_CLASS_CODE	(0x060000)
#define HOSTBRIDGE_REVISION_ID	(0x0b)
#define HOSTBRIDGE_DEVICE_ID	(0x5AF0)
#define HOSTBRIDGE_VENDOR_ID	(0x8086)

#endif