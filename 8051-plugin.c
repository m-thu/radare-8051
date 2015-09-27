/* 8051/8052 disassembler plugin for radare2 */
/* All 8051/8052 mnemonics (c) Intel Corporation,
 * http://datasheets.chipdb.org/Intel/MCS51/MANUALS/27238302.PDF */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <r_asm.h>
#include <r_lib.h>
#include <r_types.h>

#define STR_BUFFER 20

/* addressing modes,
 * used for mov part 1, 2, 3, cjne, djnz */
static const char *regs[] = {"@r0", "@r1", "r0", "r1", "r2",
	"r3", "r4", "r5", "r6", "r7"};

/* SFR map for 8052, used in 'decode_sfr' */
static const char *sfr_map[] = {
/* 0x80 -- 0x87 */
	"P0", "SP", "DPL", "DPH", "", "", "", "PCON",
/* 0x88 -- 0x8f */
	"TCON", "TMOD", "TL0", "TL1", "TH0", "TH1", "", "",
/* 0x90 -- 0x97 */
	"P1", "", "", "", "", "", "", "",
/* 0x98 -- 0x9f */
	"SCON", "SBUF", "", "", "", "", "", "",
/* 0xa0 -- 0xa7 */
	"P2", "", "", "", "", "", "", "",
/* 0xa8 -- 0xaf */
	"IE", "", "", "", "", "", "", "",
/* 0xb0 -- 0xb7 */
	"P3", "", "", "", "", "", "", "",
/* 0xb8 -- 0xbf */
	"IP", "", "", "", "", "", "", "",
/* 0xc0 -- 0xc7 */
	"", "", "", "", "", "", "", "",
/* 0xc8 -- 0xcf */
	"T2CON", "", "RCAP2L", "RCAP2H", "TL2", "TH2", "", "",
/* 0xd0 -- 0xd7 */
	"PSW", "", "", "", "", "", "", "",
/* 0xd8 -- 0xdf */
	"", "", "", "", "", "", "", "",
/* 0xe0 -- 0xe7 */
	"ACC", "", "", "", "", "", "", "",
/* 0xe8 -- 0xef */
	"", "", "", "", "", "", "", "",
/* 0xf0 -- 0xf7 */
	"B", "", "", "", "", "", "", "",
/* 0xf8 -- 0xff */
	"", "", "", "", "", "", "", ""};

/* map of bit addressable SFRs, used in 'decode_bit' */
static const char *sfr_bit_map[] = {
/* P0   : 0x80 -- 0x87 */
	"P0.0", "P0.1", "P0.2", "P0.3", "P0.4", "P0.5", "P0.6", "P0.7",
/* TCON : 0x88 -- 0x8f */
	"IT0", "IE0", "IT1", "IE1", "TR0", "TF0", "TR1", "TF1",
/* P1   : 0x90 -- 0x97 */
	"P1.0", "P1.1", "P1.2", "P1.3", "P1.4", "P1.5", "P1.6", "P1.7",
/* SCON : 0x98 -- 0x9f */
	"RI", "TI", "RB8", "TB8", "REN", "SM2", "SM1", "SM0",
/* P2   : 0xa0 -- 0xa7 */
	"P2.0", "P2.1", "P2.2", "P2.3", "P2.4", "P2.5", "P2.6", "P2.7",
/* IE   : 0xa8 -- 0xaf */
	"EX0", "ET0", "EX1", "ET1", "ES", "ET2", "IE.6", "EA",
/* P3   : 0xb0 -- 0xb7 */
	"P3.0", "P3.1", "P3.2", "P3.3", "P3.4", "P3.5", "P3.6", "P3.7",
/* IP   : 0xb8 -- 0xbf */
	"PX0", "PT0", "PX1", "PT1", "PS", "PT2", "IP.6", "IP.7",
/* --   : 0xc0 -- 0xc7 */
	"", "", "", "", "", "", "", "",
/* T2CON: 0xc8 -- 0xcf */
	"CP/RL2", "CP/T2", "TR2", "EXEN2", "TLCK", "RCLK", "EXF2", "TF2",
/* PSW  : 0xd0 -- 0xd7 */
	"P", "PSW.1", "OV", "RS0", "RS1", "F0", "AC", "CY",
/* --   : 0xd8 -- 0xdf */
	"", "", "", "", "", "", "", "",
/* ACC  : 0xe0 -- 0xe7 */
	"ACC.0", "ACC.1", "ACC.2", "ACC.3", "ACC.4", "ACC.5", "ACC.6", "ACC.7",
/* --   : 0xe8 -- 0xef */
	"", "", "", "", "", "", "", "",
/* B    : 0xf0 -- 0xf7 */
	"B.0", "B.1", "B.2", "B.3", "B.4", "B.5", "B.6", "B.7",
/* --   : 0xf8 -- 0xff */
	"", "", "", "", "", "", "", ""};

/* decode special function registers */
static void decode_sfr(uint8_t address, char *s)
{
	/* SFR: 0x80 - 0xff */
	if (address >= 0x80) {
		if (strlen(sfr_map[address-0x80]) > 0) {
			strncpy(s, sfr_map[address-0x80], STR_BUFFER);
			return;
		}
	}

	snprintf(s, STR_BUFFER, "0x%x", address);
}

/* decode bit addresses */
static void decode_bit(uint8_t address, char *s)
{
	/* 0x80 -- 0xff: bit addressable SFRs */
	if (address >= 0x80) {
		if (strlen(sfr_bit_map[address-0x80]) > 0) {
			strncpy(s, sfr_bit_map[address-0x80], STR_BUFFER);
		} else {
			snprintf(s, STR_BUFFER, "0x%x", address);
		}
	/* 0x00 -- 0x7f: bit addressable RAM (0x20 -- 0x2f) */
	} else {
		snprintf(s, STR_BUFFER, "0x%x.%i", address/8+0x20, address%8);
	}
}

/* decode addressing mode of an instruction,
 * used for inc, dec, add, addc, orl, anl, xrl, subb, xch, mov part 4, 5 */
static int decode_a_mode(uint8_t low_nibble, uint8_t *buf, char *s)
{
	switch (low_nibble) {
	/* immediate */
	case 0x4:
		snprintf(s, STR_BUFFER, "#0x%x", buf[1]);
		return 2;

	/* memory direct */
	case 0x5:
		decode_sfr(buf[1], s);
		return 2;

	/* register indirect: @r0, @r1 */
	case 0x6:
		snprintf(s, STR_BUFFER, "@r0");
		return 1;
	case 0x7:
		snprintf(s, STR_BUFFER, "@r1");
		return 1;

	/* register direct: r0-r7 */
	case 0x8:
	case 0x9:
	case 0xa:
	case 0xb:
	case 0xc:
	case 0xd:
	case 0xe:
	case 0xf:
		snprintf(s, STR_BUFFER, "r%i", low_nibble-0x8);
		return 1;
	}

	return 0;
}

static int disassemble (RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	uint8_t h, l;
	uint16_t pc, dest;
	char a_mode[STR_BUFFER], bit_addr[STR_BUFFER], sfr[STR_BUFFER],
	     sfr2[STR_BUFFER];
	int size;

	/* get current program counter */
	pc = a->pc & 0xffff;

	/* high nibble of the opcode specifies the instruction,
	 * low nibble the addressing mode or an irregular instruction,
	 * ajmp and acall are exceptions  */
	h = *buf & 0xf0;
	l = *buf & 0x0f;

	/* ajmp */
	if ((*buf & 0x1f) == 0x1) {
		pc += 2;
		dest = (pc&0xf800) | (*buf&0xe0)<<3 | buf[1];
		snprintf(op->buf_asm, R_ASM_BUFSIZE, "ajmp 0x%x", dest);
		op->size = 2;
		return 2;
	}

	/* acall */
	if ((*buf & 0x1f) == 0x11) {
		pc += 2;
		dest = (pc&0xf800) | (*buf&0xe0)<<3 | buf[1];
		snprintf(op->buf_asm, R_ASM_BUFSIZE, "acall 0x%x", dest);
		op->size = 2;
		return 2;
	}

	switch (h) {
	/* inc */
	case 0x00:
		/* nop */
		if (l == 0x0) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "nop");
			op->size = 1;
			return 1;
		}

		/* ljmp code16 */
		if (l == 0x2) {
			dest = buf[1]<<8 | buf[2];
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "ljmp 0x%x", dest);
			op->size = 3;
			return 3;
		}

		/* rr a */
		if (l == 0x3) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "rr a");
			op->size = 1;
			return 1;
		}

		/* inc a */
		if (l == 0x4) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "inc a");
			op->size = 1;
			return 1;
		}

		/* inc xxx */
		if ((size = decode_a_mode(l, (uint8_t *)buf, a_mode)) > 0) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "inc %s", a_mode);
			op->size = size;
			return size;
		}

	/* dec */
	case 0x10:
		/* jbc bit addr., code addr.*/
		if (l == 0x0) {
			pc += 3;
			decode_bit(buf[1], bit_addr);
			dest = pc + (int8_t)buf[2];
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "jbc %s, 0x%x",
			         bit_addr, dest);
			op->size = 3;
			return 3;
		}

		/* lcall code16 */
		if (l == 0x2) {
			dest = buf[1]<<8 | buf[2];
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "lcall 0x%x",
			         dest);
			op->size = 3;
			return 3;
		}

		/* rrc a */
		if (l == 0x3) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "rrc a");
			op->size = 1;
			return 1;
		}

		/* dec a */
		if (l == 0x4) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "dec a");
			op->size = 1;
			return 1;
		}

		/* dec xxx */
		if ((size = decode_a_mode(l, (uint8_t *)buf, a_mode)) > 0) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "dec %s", a_mode);
			op->size = size;
			return size;
		}

	/* add */
	case 0x20:
		/* jb bit addr., code addr.*/
		if (l == 0x0) {
			pc += 3;
			decode_bit(buf[1], bit_addr);
			dest = pc + (int8_t)buf[2];
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "jb %s, 0x%x",
			         bit_addr, dest);
			op->size = 3;
			return 3;
		}

		/* ret */
		if (l == 0x2) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "ret");
			op->size = 1;
			return 1;
		}

		/* rl a */
		if (l == 0x3) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "rl a");
			op->size = 1;
			return 1;
		}

		/* add a, xxx */
		if ((size = decode_a_mode(l, (uint8_t *)buf, a_mode)) > 0) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "add a, %s",
			         a_mode);
			op->size = size;
			return size;
		}

	/* addc */
	case 0x30:
		/* jnb bit addr., code addr.*/
		if (l == 0x0) {
			pc += 3;
			decode_bit(buf[1], bit_addr);
			dest = pc + (int8_t)buf[2];
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "jnb %s, 0x%x",
			         bit_addr, dest);
			op->size = 3;
			return 3;
		}

		/* reti */
		if (l == 0x2) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "reti");
			op->size = 1;
			return 1;
		}

		/* rlc a */
		if (l == 0x3) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "rlc a");
			op->size = 1;
			return 1;
		}

		/* addc a, xxx */
		if ((size = decode_a_mode(l, (uint8_t *)buf, a_mode)) > 0) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "addc a, %s",
			         a_mode);
			op->size = size;
			return size;
		}

	/* orl */
	case 0x40:
		/* jc code addr.*/
		if (l == 0x0) {
			pc += 2;
			dest = pc + (int8_t)buf[1];
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "jc 0x%x", dest);
			op->size = 2;
			return 2;
		}

		/* orl data addr., a */
		if (l == 0x2) {
			decode_sfr(buf[1], sfr);
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "orl %s, a", sfr);
			op->size = 2;
			return 2;
		}

		/* orl data addr., #imm */
		if (l == 0x3) {
			decode_sfr(buf[1], sfr);
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "orl %s, #0x%x",
			         sfr, buf[2]);
			op->size = 3;
			return 3;
		}

		/* orl a, xxx */
		if ((size = decode_a_mode(l, (uint8_t *)buf, a_mode)) > 0) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "orl a, %s",
			         a_mode);
			op->size = size;
			return size;
		}

	/* anl */
	case 0x50:
		/* jnc code addr. */
		if (l == 0x0) {
			pc += 2;
			dest = pc + (int8_t)buf[1];
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "jnc 0x%x", dest);
			op->size = 2;
			return 2;
		}

		/* anl data addr., a */
		if (l == 0x2) {
			decode_sfr(buf[1], sfr);
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "anl %s, a", sfr);
			op->size = 2;
			return 2;
		}

		/* anl data addr., #imm */
		if (l == 0x3) {
			decode_sfr(buf[1], sfr);
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "anl %s, #0x%x",
			         sfr, buf[2]);
			op->size = 3;
			return 3;
		}

		/* anl a, xxx */
		if ((size = decode_a_mode(l, (uint8_t *)buf, a_mode)) > 0) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "anl a, %s",
			         a_mode);
			op->size = size;
			return size;
		}

	/* xrl */
	case 0x60:
		/* jz code addr. */
		if (l == 0x0) {
			pc += 2;
			dest = pc + (int8_t)buf[1];
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "jz 0x%x", dest);
			op->size = 2;
			return 2;
		}

		/* xrl data addr., a */
		if (l == 0x2) {
			decode_sfr(buf[1], sfr);
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "xrl %s, a", sfr);
			op->size = 2;
			return 2;
		}

		/* xrl data addr., #imm */
		if (l == 0x3) {
			decode_sfr(buf[1], sfr);
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "xrl %s, #0x%x",
			         sfr, buf[2]);
			op->size = 3;
			return 3;
		}

		/* xrl a, xxx */
		if ((size = decode_a_mode(l, (uint8_t *)buf, a_mode)) > 0) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "xrl a, %s",
			         a_mode);
			op->size = size;
			return size;
		}

	/* mov part 1 */
	case 0x70:
		/* jnz code addr. */
		if (l == 0x0) {
			pc += 2;
			dest = pc + (int8_t)buf[1];
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "jnz 0x%x", dest);
			op->size = 2;
			return 2;
		}

		/* orl c, bit addr. */
		if (l == 0x2) {
			decode_bit(buf[1], bit_addr);
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "orl c, %s",
			         bit_addr);
			op->size = 2;
			return 2;
		}

		/* jmp @a+dptr */
		if (l == 0x3) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "jmp @a+dptr");
			op->size = 1;
			return 1;
		}

		/* mov a, #imm */
		if (l == 0x4) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "mov a, #0x%x",
			         buf[1]);
			op->size = 2;
			return 2;
		}

		/* mov data addr., #imm */
		if (l == 0x5) {
			decode_sfr(buf[1], sfr);
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "mov %s, #0x%x",
			         sfr, buf[2]);
			op->size = 3;
			return 3;
		}

		/* mov xxx, #imm */
		snprintf(op->buf_asm, R_ASM_BUFSIZE, "mov %s, #0x%x",
		         regs[l-0x6], buf[1]);
		op->size = 2;
		return 2;

	/* mov part 2 */
	case 0x80:
		/* sjmp code addr. */
		if (l == 0x0) {
			pc += 2;
			dest = pc + (int8_t)buf[1];
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "sjmp 0x%x",
			         dest);
			op->size = 2;
			return 2;
		}

		/* anl c, bit addr. */
		if (l == 0x2) {
			decode_bit(buf[1], bit_addr);
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "anl c, %s",
			         bit_addr);
			op->size = 2;
			return 2;
		}

		/* movc a, @a+pc */
		if (l == 0x3) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "movc a, @a+pc");
			op->size = 1;
			return 1;
		}

		/* div */
		if (l == 0x4) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "div ab");
			op->size = 1;
			return 1;
		}

		/* mov data addr., data addr. */
		if (l == 0x5) {
			decode_sfr(buf[1], sfr); /* src */
			decode_sfr(buf[2], sfr2); /* dest */
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "mov %s, %s",
			         sfr2, sfr);
			op->size = 3;
			return 3;
		}

		/* mov data addr., xxx */
		decode_sfr(buf[1], sfr);
		snprintf(op->buf_asm, R_ASM_BUFSIZE, "mov %s, %s",
		         sfr, regs[l-0x6]);
		op->size = 2;
		return 2;

	/* subb */
	case 0x90:
		/* mov dptr, #imm */
		if (l == 0x0) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "mov dptr, #0x%x",
			         ((buf[1]<<8) | buf[2]) & 0xffff);
			op->size = 3;
			return 3;
		}

		/* mov bit addr., c */
		if (l == 0x2) {
			decode_bit(buf[1], bit_addr);
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "mov %s, c",
			         bit_addr);
			op->size = 2;
			return 2;
		}

		/* movc a, @a+dptr */
		if (l == 0x3) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "movc a, @a+dptr");
			op->size = 1;
			return 1;
		}

		/* subb a, xxx */
		if ((size = decode_a_mode(l, (uint8_t *)buf, a_mode)) > 0) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "subb a, %s",
			         a_mode);
			op->size = size;
			return size;
		}

	/* mov part 3 */
	case 0xa0:
		/* orl c, /bit addr. */
		if (l == 0x0) {
			decode_bit(buf[1], bit_addr);
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "orl c, /%s",
			         bit_addr);
			op->size = 2;
			return 2;
		}

		/* mov c, bit addr. */
		if (l == 0x2) {
			decode_bit(buf[1], bit_addr);
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "mov c, %s",
			         bit_addr);
			op->size = 2;
			return 2;
		}

		/* inc dptr */
		if (l == 0x3) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "inc dptr");
			op->size = 1;
			return 1;
		}

		/* mul ab */
		if (l == 0x4) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "mul ab");
			op->size = 1;
			return 1;
		}

		/* reserved */
		if (l == 0x5) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "reserved");
			/* size is actually not defined */
			op->size = 1;
			return 1;
		}

		/* mov xxx, data addr. */
		decode_sfr(buf[1], sfr);
		snprintf(op->buf_asm, R_ASM_BUFSIZE, "mov %s, %s",
		         regs[l-0x6], sfr);
		op->size = 2;
		return 2;

	/* cjne */
	case 0xb0:
		/* anl c, /bit addr. */
		if (l == 0x0) {
			decode_bit(buf[1], bit_addr);
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "anl c, /%s",
			         bit_addr);
			op->size = 2;
			return 2;
		}

		/* cpl bit addr. */
		if (l == 0x2) {
			decode_bit(buf[1], bit_addr);
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "cpl %s",
			         bit_addr);
			op->size = 2;
			return 2;
		}

		/* cpl c */
		if (l == 0x3) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "cpl c");
			op->size = 1;
			return 1;
		}

		/* cjne a, #imm, code addr. */
		if (l == 0x4) {
			pc += 3;
			dest = pc + (int8_t)buf[2];
			snprintf(op->buf_asm, R_ASM_BUFSIZE,
			         "cjne a, #0x%x, 0x%x", buf[1], dest);
			op->size = 3;
			return 3;
		}

		/* cjne a, data addr., code addr. */
		if (l == 0x5) {
			pc += 3;
			dest = pc + (int8_t)buf[2];
			decode_sfr(buf[1], sfr);
			snprintf(op->buf_asm, R_ASM_BUFSIZE,
			         "cjne a, %s, 0x%x", sfr, dest);
			op->size = 3;
			return 3;
		}

		/* cjne xxx, #imm, code addr. */
		pc += 3;
		dest = pc + (int8_t)buf[2];
		snprintf(op->buf_asm, R_ASM_BUFSIZE,
		         "cjne %s, #0x%x, 0x%x",
		         regs[l-0x6], buf[1], dest);
		op->size = 3;
		return 3;

	/* xch */
	case 0xc0:
		/* push data addr. */
		if (l == 0x0) {
			decode_sfr(buf[1], sfr);
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "push %s", sfr);
			op->size = 2;
			return 2;
		}

		/* clr bit addr. */
		if (l == 0x2) {
			decode_bit(buf[1], bit_addr);
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "clr %s",
			         bit_addr);
			op->size = 2;
			return 2;
		}

		/* clr c */
		if (l == 0x3) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "clr c");
			op->size = 1;
			return 1;
		}

		/* swap a */
		if (l == 0x4) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "swap a");
			op->size = 1;
			return 1;
		}

		/* xch a, xxx */
		if ((size = decode_a_mode(l, (uint8_t *)buf, a_mode)) > 0) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "xch a, %s",
			         a_mode);
			op->size = size;
			return size;
		}

	/* djnz */
	case 0xd0:
		/* pop data addr. */
		if (l == 0x0) {
			decode_sfr(buf[1], sfr);
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "pop %s", sfr);
			op->size = 2;
			return 2;
		}

		/* setb bit addr. */
		if (l == 0x2) {
			decode_bit(buf[1], bit_addr);
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "setb %s",
			         bit_addr);
			op->size = 2;
			return 2;
		}

		/* setb c */
		if (l == 0x3) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "setb c");
			op->size = 1;
			return 1;
		}

		/* da a */
		if (l == 0x4) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "da a");
			op->size = 1;
			return 1;
		}

		/* djnz data addr., code addr. */
		if (l == 0x5) {
			pc += 2;
			dest = pc + (int8_t)buf[2];
			decode_sfr(buf[1], sfr);
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "djnz %s, 0x%x",
			         sfr, dest);
			op->size = 3;
			return 3;
		}

		/* xchd a, @r0 */
		if (l == 0x6) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "xchd a, @r0");
			op->size = 1;
			return 1;
		}

		/* xchd a, @r1 */
		if (l == 0x7) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "xchd a, @r1");
			op->size = 1;
			return 1;
		}

		/* djnz rx, code addr. */
		pc += 2;
		dest = pc + (int8_t)buf[1];
		snprintf(op->buf_asm, R_ASM_BUFSIZE, "djnz %s, 0x%x",
		         regs[l-0x6], dest);
		op->size = 2;
		return 2;

	/* mov part 4 */
	case 0xe0:
		/* movx a, @dptr */
		if (l == 0x0) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "movx a, @dptr");
			op->size = 1;
			return 1;
		}

		/* movx a, @r0 */
		if (l == 0x2) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "movx a, @r0");
			op->size = 1;
			return 1;
		}

		/* movx a, @r1 */
		if (l == 0x3) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "movx a, @r1");
			op->size = 1;
			return 1;
		}

		/* clr a */
		if (l == 0x4) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "clr a");
			op->size = 1;
			return 1;
		}

		/* mov a, xxx */
		if ((size = decode_a_mode(l, (uint8_t *)buf, a_mode)) > 0) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "mov a, %s",
			         a_mode);
			op->size = size;
			return size;
		}

	/* mov part 5 */
	case 0xf0:
		/* movx @dptr, a */
		if (l == 0x0) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "movx @dptr, a");
			op->size = 1;
			return 1;
		}

		/* movx @r0, a */
		if (l == 0x2) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "movx @r0, a");
			op->size = 1;
			return 1;
		}

		/* movx @r1, a */
		if (l == 0x3) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "movx @r1, a");
			op->size = 1;
			return 1;
		}

		/* cpl a */
		if (l == 0x4) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "cpl a");
			op->size = 1;
			return 1;
		}

		/* mov xxx, a */
		if ((size = decode_a_mode(l, (uint8_t *)buf, a_mode)) > 0) {
			snprintf(op->buf_asm, R_ASM_BUFSIZE, "mov %s, a",
			         a_mode);
			op->size = size;
			return size;
		}
	}

	return 0;
}

RAsmPlugin r_asm_plugin_mycpu = {
        .name = "8051-plugin",
        .arch = "8051",
        .license = "MIT License",
        .bits = 8,
        .desc = "8051/8052 plugin",
        .disassemble = &disassemble,
	.init = NULL,
	.fini = NULL,
	.modify = NULL,
	.assemble = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
        .type = R_LIB_TYPE_ASM,
        .data = &r_asm_plugin_mycpu
};
#endif
