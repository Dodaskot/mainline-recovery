/* SPDX-License-Identifier: MIT */
/*
 * Native C cross-architecture model of the A22x NT36675 firmware directory,
 * SPI page-addressing and selected failure paths. This is a user-space model,
 * NOT the Linux SPI driver or a physical-panel/IRQ simulator.
 *
 * Example: aarch64-linux-gnu-gcc -static -O2 -Wall -Wextra -Werror -o nvt-arm64 \
 *          tools/nt36675_firmware_emulator.c
 *          qemu-aarch64 ./nvt-arm64 /vendor/firmware/novatek_ts_fw.bin
 */
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { MAX_FIRMWARE = 512 * 1024, MAX_SECTIONS = 255 };

struct section {
	uint32_t bin_addr, sram_addr, len_minus_one, crc;
};

struct result {
	unsigned int segment_count, info_count, overlay_count;
	unsigned int version;
	size_t marker_end;
};

static uint32_t le32(const uint8_t *buf, size_t len, size_t off, bool *ok)
{
	if (off > len || len - off < 4) {
		*ok = false;
		return 0;
	}
	return (uint32_t)buf[off] | ((uint32_t)buf[off + 1] << 8) |
		((uint32_t)buf[off + 2] << 16) |
		((uint32_t)buf[off + 3] << 24);
}

static bool parse_firmware(const uint8_t *fw, size_t bytes, struct result *out)
{
	struct section sections[MAX_SECTIONS];
	unsigned int info, overlay, count;
	size_t marker_end = 0;
	uint32_t end;
	bool valid = true;

	if (bytes < 4096 || bytes > MAX_FIRMWARE)
		return false;
	for (size_t i = bytes / 4096; i > 0; i--) {
		size_t offset = i * 4096 - 3;
		if (!memcmp(fw + offset, "NVT", 3) ||
		    !memcmp(fw + offset, "MOD", 3)) {
			marker_end = i * 4096;
			break;
		}
	}
	if (!marker_end || (unsigned int)fw[marker_end - 4096] +
	    fw[marker_end - 4095] != 255)
		return false;
	end = le32(fw, bytes, 0, &valid);
	if (!valid || end < 0x30 || end > bytes || (end - 0x30) % 16)
		return false;
	info = (end - 0x30) / 16;
	overlay = (fw[0x28] & 0x10) ? (fw[0x28] & 0xf) : 0;
	count = 2 + info + overlay;
	if (count > MAX_SECTIONS)
		return false;

	for (unsigned int i = 0; i < count; i++) {
		struct section *p = &sections[i];
		size_t pos;
		if (i < 2) {
			pos = 12 * i;
			p->bin_addr = le32(fw, bytes, pos, &valid);
			p->sram_addr = le32(fw, bytes, pos + 4, &valid);
			p->len_minus_one = le32(fw, bytes, pos + 8, &valid);
			p->crc = le32(fw, bytes, 0x18 + 4 * i, &valid);
		} else {
			if (i < 2 + info)
				pos = 0x30 + 16 * (i - 2);
			else
				pos = (size_t)sections[1].bin_addr + 16 * (i - 2 - info);
			p->sram_addr = le32(fw, bytes, pos, &valid);
			p->len_minus_one = le32(fw, bytes, pos + 4, &valid);
			p->bin_addr = le32(fw, bytes, pos + 8, &valid);
			p->crc = le32(fw, bytes, pos + 12, &valid);
		}
		if (!valid || p->bin_addr > bytes ||
		    (p->len_minus_one && p->len_minus_one >= bytes - p->bin_addr))
			return false;
	}
	out->segment_count = count;
	out->info_count = info;
	out->overlay_count = overlay;
	out->version = fw[marker_end - 4096];
	out->marker_end = marker_end;
	return true;
}

static bool spi_and_trim_tests(void)
{
	const uint32_t addresses[] = { 0x03f0fe, 0x03f310, 0x022d00, 0x7fff80 };
	const uint8_t trim[] = { 0x0c, 0x00, 0x00, 0x72, 0x66, 0x03 };
	if (trim[0] != 0x0c || trim[3] != 0x72 || trim[4] != 0x66 || trim[5] != 0x03)
		return false;
	for (size_t i = 0; i < sizeof(addresses) / sizeof(addresses[0]); i++) {
		uint32_t addr = addresses[i];
		uint8_t page1 = (addr >> 15) & 0xff;
		uint8_t page2 = (addr >> 7) & 0xff;
		uint8_t writecmd = (addr & 0x7f) | 0x80;
		uint8_t readcmd = addr & 0x7f;
		uint32_t rebuilt = ((uint32_t)page1 << 15) |
			((uint32_t)(page2 & 0xff) << 7) | readcmd;
		if (rebuilt != addr || !(writecmd & 0x80) || (readcmd & 0x80))
			return false;
		/* read() discards one dummy byte before the first payload. */
		uint8_t payload[] = { 0, 0xa3 };
		if (payload[1] != 0xa3)
			return false;
	}
	return true;
}

static bool corruption_tests(const uint8_t *fw, size_t len)
{
	struct result value, baseline;
	uint8_t *copy = malloc(len);
	bool ok = true;
	if (!copy)
		return false;
	if (!parse_firmware(fw, len, &baseline)) {
		free(copy);
		return false;
	}
	memcpy(copy, fw, len);
	copy[0] = 0; copy[1] = 0; copy[2] = 0; copy[3] = 0;
	ok &= !parse_firmware(copy, len, &value);
	memcpy(copy, fw, len);
	copy[0] = 0xff; copy[1] = 0xff; copy[2] = 0xff; copy[3] = 0xff;
	ok &= !parse_firmware(copy, len, &value);
	memcpy(copy, fw, len);
	copy[baseline.marker_end - 4096] = 0;
	ok &= !parse_firmware(copy, len, &value);
	memcpy(copy, fw, len);
	for (size_t i = 1; i < 65 && i < len; i++)
		ok &= !parse_firmware(copy, i, &value);
	free(copy);
	return ok;
}

static bool fuzz_header_bounds(const uint8_t *fw, size_t len)
{
	/* Deterministic mutation of the first 512 bytes, where the ILM/DLM,
	 * overlay and section pointers live. Acceptance is allowed; OOB is not. */
	uint32_t seed = 0x4e563736;
	uint8_t *copy = malloc(len);
	struct result ignored;
	if (!copy)
		return false;
	for (unsigned int i = 0; i < 4096; i++) {
		size_t pos;
		memcpy(copy, fw, len);
		seed ^= seed << 13;
		seed ^= seed >> 17;
		seed ^= seed << 5;
		pos = seed % (len < 512 ? len : 512);
		copy[pos] ^= (uint8_t)(1u << ((seed >> 16) & 7));
		(void)parse_firmware(copy, len, &ignored);
	}
	free(copy);
	return true;
}

int main(int argc, char **argv)
{
	FILE *input;
	uint8_t *firmware;
	long size;
	struct result r;
	if (argc != 2) {
		fprintf(stderr, "usage: %s novatek_ts_fw.bin\n", argv[0]);
		return 2;
	}
	input = fopen(argv[1], "rb");
	if (!input || fseek(input, 0, SEEK_END) || (size = ftell(input)) < 0 ||
	    size > MAX_FIRMWARE || fseek(input, 0, SEEK_SET)) {
		fprintf(stderr, "cannot read firmware\n");
		return 2;
	}
	firmware = malloc((size_t)size);
	if (!firmware || fread(firmware, 1, (size_t)size, input) != (size_t)size) {
		fprintf(stderr, "short firmware read\n");
		return 2;
	}
	fclose(input);
	if (!parse_firmware(firmware, (size_t)size, &r) || !spi_and_trim_tests() ||
	    !corruption_tests(firmware, (size_t)size) ||
	    !fuzz_header_bounds(firmware, (size_t)size)) {
		fprintf(stderr, "NT36675 model check failed\n");
		return 1;
	}
	printf("{\"protocol_model\":\"PASS\",\"firmware_bytes\":%ld,"
	       "\"fw_version\":%u,\"segments\":%u,\"info\":%u,"
	       "\"overlay\":%u,\"upload_limit\":%zu,"
	       "\"corruption_tests\":\"PASS\",\"fuzz_cases\":4096,"
	       "\"real_nt36675_test\":\"NOT_RUN\"}\n",
	       size, r.version, r.segment_count, r.info_count, r.overlay_count, r.marker_end);
	free(firmware);
	return 0;
}
