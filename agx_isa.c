#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <math.h>
#include <err.h>

#define MIN2(a,b) ((a) < (b) ? (a) : (b))
#define ARRAYSIZE(x) (sizeof(x) / sizeof(*(x)))

enum agx_src_flags {
	AGX_SRC_DEP = 1<<0,
	AGX_SRC_SIGNEXTEND = 1<<1,
	AGX_SRC_ABS = 1<<2,
	AGX_SRC_NEG = 1<<3,
	AGX_SRC_HI = 1<<4,
};

enum agx_src_size {
	AGX_SRC_SIZE16,
	AGX_SRC_SIZE32,
};

enum agx_src_type {
	AGX_SRC_TYPE_NONE = 0,
	AGX_SRC_TYPE_IMMEDIATE,
	AGX_SRC_TYPE_IMMFLOAT,
	AGX_SRC_TYPE_UNIFORM,
	AGX_SRC_TYPE_REG,
	AGX_SRC_TYPE_SYSVAL,
};

struct agx_src {
	uint32_t type:3;
	uint32_t size:1;
	uint32_t flags:4;
	uint32_t shift:3;
	uint32_t nr_regs:5;
	uint32_t value;
};

struct agx_src make_src(uint32_t type, uint32_t size, uint32_t flags,
		uint32_t shift, uint32_t nr_regs, uint32_t value)
{
	struct agx_src a = { type, size, flags, shift, nr_regs, value };
	return a;
}

enum agx_insn_flags {
	AGX_INSN_DEP = 1<<0,
	AGX_INSN_COND = 1<<1,
};

/* Note: logical opcode. actual encodings vary */
enum agx_op {
	AGX_OP_UNK = 0,
	AGX_OP_MOV = 1,
	AGX_OP_FCSEL = 2,
	AGX_OP_LD = 3,
	AGX_OP_WAIT = 4,
	AGX_OP_FADD = 5,
	AGX_OP_FADD_SAT = 6,
	AGX_OP_ST = 7,
	AGX_OP_STOP = 8,
};

static char const * const op_names[] = {
	[AGX_OP_UNK] = "unk",
	[AGX_OP_MOV] = "mov",
	[AGX_OP_FCSEL] = "fcsel",
	[AGX_OP_LD] = "ld",
	[AGX_OP_WAIT] = "wait",
	[AGX_OP_FADD] = "fadd",
	[AGX_OP_FADD_SAT] = "fadd.sat",
	[AGX_OP_ST] = "st",
	[AGX_OP_STOP] = "stop",
};

struct agx_insn {
	struct agx_src dst;
	struct agx_src srcs[4];
	uint32_t op : 16;
	uint32_t flags : 2;
	uint32_t control : 14;
};

struct field {
	uint32_t val;
	uint32_t nr_bits;
};

void field_concat(struct field *f, uint16_t const *buf, int first, int len) {
	assert(f->nr_bits + len <= 32);

	buf += first >> 4;
	first &= 0x0f;

	while (len) {
		int n = MIN2(16 - first, len);
		uint16_t v = *buf;
		if (first) {
			v >>= first;
			first = 0;
		}
		v &= (1<<n) - 1;

		f->val |= (uint32_t)v << f->nr_bits;
		f->nr_bits += n;
		len -= n;
		buf++;
	}
}

struct field field_extract(uint16_t const *buf, int first, int len) {
	struct field f = { 0, 0 };
	field_concat(&f, buf, first, len);
	return f;
} 

struct agx_insn_pattern {
	uint16_t opcode_bits;
	uint16_t mask_bits;
	uint16_t len;		/* in words */
	struct agx_insn (*decode)(uint16_t const *buf);
};

struct agx_src agx_decode_bitop_dst(struct field f)
{
	if (f.val & 1)
		return make_src(AGX_SRC_TYPE_REG, AGX_SRC_SIZE32,
				0, 0, 1, f.val >> 2);
	else
		return make_src(AGX_SRC_TYPE_REG, AGX_SRC_SIZE16,
				(f.val & 2) ? AGX_SRC_HI : 0, 0, 1, f.val >> 2);
}

struct agx_insn agx_decode_movsr(uint16_t const *buf) {
	struct agx_insn insn = { 0 };
	insn.op = AGX_OP_MOV;

	struct field dst = field_extract(buf, 8, 7);
	field_concat(&dst, buf, 28, 2);

	insn.dst = agx_decode_bitop_dst(dst);

	struct field src = field_extract(buf, 16, 6);
	field_concat(&src, buf, 24, 2);

	insn.srcs[0] = make_src(AGX_SRC_TYPE_SYSVAL, AGX_SRC_SIZE32,
		0, 0, 1, src.val);

	return insn;
}

struct agx_insn agx_decode_fcsel(uint16_t const *buf) {
	struct agx_insn insn = { 0 };
	insn.op = AGX_OP_FCSEL;

	struct field dst = field_extract(buf, 8, 7);

	return insn;
}

struct agx_insn agx_decode_load(uint16_t const *buf) {
	struct agx_insn insn = { 0 };
	insn.op = AGX_OP_LD;

	struct field dst = field_extract(buf, 10, 6);
	field_concat(&dst, buf, 40, 2);

	/* XXX: load size??? for now, let's assume everything is 32 */
	insn.dst = make_src(AGX_SRC_TYPE_REG, AGX_SRC_SIZE32,
			0, 0, 1, dst.val);

	struct field addr = field_extract(buf, 17, 3);
	field_concat(&addr, buf, 36, 4);

	struct field idx = field_extract(buf, 21, 3);
	field_concat(&idx, buf, 32, 4);

	bool ua = field_extract(buf, 27, 1).val != 0;
	bool ic = field_extract(buf, 24, 1).val != 0;

	insn.srcs[0] = make_src(ua ? AGX_SRC_TYPE_UNIFORM : AGX_SRC_TYPE_REG,
			AGX_SRC_SIZE32,
			0, 0, 2, addr.val);

	insn.srcs[1] = make_src(ic ? AGX_SRC_TYPE_IMMEDIATE : AGX_SRC_TYPE_REG,
			AGX_SRC_SIZE32,
			0, 0, 1, idx.val);

	return insn;
}

struct agx_insn agx_decode_store(uint16_t const *buf) {
	struct agx_insn insn = { 0 };
	insn.op = AGX_OP_ST;

	struct field addr = field_extract(buf, 17, 3);
	field_concat(&addr, buf, 36, 4);

	struct field idx = field_extract(buf, 21, 3);
	field_concat(&idx, buf, 32, 4);

	bool ua = field_extract(buf, 27, 1).val != 0;
	bool ic = field_extract(buf, 24, 1).val != 0;

	insn.srcs[0] = make_src(ua ? AGX_SRC_TYPE_UNIFORM : AGX_SRC_TYPE_REG,
			AGX_SRC_SIZE32,
			0, 0, 2, addr.val);

	insn.srcs[1] = make_src(ic ? AGX_SRC_TYPE_IMMEDIATE : AGX_SRC_TYPE_REG,
			AGX_SRC_SIZE32,
			0, 0, 1, idx.val);

	struct field src = field_extract(buf, 10, 6);
	field_concat(&src, buf, 40, 2);

	/* XXX: store size??? for now, let's assume everything is 32 */
	insn.srcs[2] = make_src(AGX_SRC_TYPE_REG, AGX_SRC_SIZE32,
			0, 0, 1, src.val);

	return insn;
}

struct agx_insn agx_decode_wait(uint16_t const *buf) {
	(void) buf;
	struct agx_insn insn = { 0 };
	/* XXX: are the remaining bits ever nonzero? */
	insn.op = AGX_OP_WAIT;
	return insn;
}

struct agx_insn agx_decode_stop(uint16_t const *buf) {
	(void) buf;
	struct agx_insn insn = { 0 };
	insn.op = AGX_OP_STOP;
	return insn;
}

struct agx_src agx_decode_float_src(struct field src, struct field type) {
	uint32_t flags = 0;
	if (type.val != AGX_SRC_TYPE_IMMEDIATE) {
		if (src.val & 1)
			flags |= AGX_SRC_HI;
		if (type.val & 0x10)
			flags |= AGX_SRC_NEG;
		if (type.val & 0x02)
			flags |= AGX_SRC_DEP;
		if (type.val & 0x8)
			flags |= AGX_SRC_ABS;
	}

	switch (type.val & 0x7) {
		case 0:	// float immediate. XXX: port over tiny float decoder
			return make_src(AGX_SRC_TYPE_IMMFLOAT, AGX_SRC_SIZE16,
					0, 0, 1, src.val);
		case 1:
		case 3:
			return make_src(AGX_SRC_TYPE_REG, AGX_SRC_SIZE16,
					flags, 0, 1, src.val >> 1);
		case 4:
		case 5:
			/* low bit of type becomes top bit of uniform reg# */
			field_concat(&src, (uint16_t const *)&type.val, 0, 1);
			return make_src(AGX_SRC_TYPE_UNIFORM, AGX_SRC_SIZE16,
					flags, 0, 1, src.val >> 1);
		default:
			assert(!"unk");
			return make_src(AGX_SRC_TYPE_NONE, 0, 0, 0, 0, 0);
	}
}

struct agx_insn agx_decode_fadd16(uint16_t const *buf) {
	struct agx_insn insn = { 0 };

	if (field_extract(buf, 6, 1).val) {
		insn.op = AGX_OP_FADD_SAT;
	} else {
		insn.op = AGX_OP_FADD;
	}

	struct field dst = field_extract(buf, 9, 6);
	field_concat(&dst, buf, 44, 2);

	insn.dst = make_src(AGX_SRC_TYPE_REG, AGX_SRC_SIZE16,
			field_extract(buf, 8, 1).val ? AGX_SRC_HI : 0,
			0, 1, dst.val);

	struct field src1 = field_extract(buf, 16, 6);
	field_concat(&src1, buf, 42, 2);
	struct field type1 = field_extract(buf, 22, 6);
	insn.srcs[0] = agx_decode_float_src(src1, type1);

	struct field src2 = field_extract(buf, 28, 6);
	field_concat(&src2, buf, 40, 2);
	struct field type2 = field_extract(buf, 34, 6);
	insn.srcs[1] = agx_decode_float_src(src2, type2);

	return insn;
}

void agx_print_reg(struct agx_src src, FILE *fp) {
	while (src.nr_regs > 0) {
		switch (src.type) {
			case AGX_SRC_TYPE_IMMEDIATE:
				fprintf(fp, "#%u", src.value);
				break;
			case AGX_SRC_TYPE_IMMFLOAT:
				{
					float sign = (src.value & 0x80) ? -1.0f : 1.0f;
					int e = ((src.value & 0x70) >> 4);
					if (e == 0) {
						/* denorm */
						fprintf(fp, "#%f", sign * (src.value & 0x0f) / 64.0f);
					} else {
						fprintf(fp, "#%f", sign * ldexpf((src.value & 0x0f) | 0x10, e - 7));
					}
				} break;
			case AGX_SRC_TYPE_UNIFORM:
				fprintf(fp, "u%d", src.value);
				break;
			case AGX_SRC_TYPE_REG:
				fprintf(fp, "r%d", src.value);
				break;
			case AGX_SRC_TYPE_SYSVAL:
				fprintf(fp, "sr%d", src.value);
				break;
		}

		if (src.size == AGX_SRC_SIZE16 && src.type != AGX_SRC_TYPE_IMMEDIATE)
			fprintf(fp, "%c", (src.flags & AGX_SRC_HI) ? 'h' : 'l');

		if (src.nr_regs > 1)
		{
			fprintf(fp, ":");

			if (src.size == AGX_SRC_SIZE16 && (~src.flags & AGX_SRC_HI)) {
				src.flags |= AGX_SRC_HI;
			} else {
				src.flags &= ~AGX_SRC_HI;
				src.value++;
			}
		}

		src.nr_regs--;
	}
}

void agx_print_operand(struct agx_src const *src, FILE *fp) {
	if (src->flags & AGX_SRC_DEP)
		fprintf(fp, "*");

	struct agx_src s = *src;
	agx_print_reg(s, fp);

	if (s.flags & AGX_SRC_ABS)
		fprintf(fp, ".abs");
	if (s.flags & AGX_SRC_NEG)
		fprintf(fp, ".neg");
}

void agx_print_insn(struct agx_insn const *insn, FILE *fp) {
	fprintf(fp, "%c%s ",
			(insn->flags & AGX_INSN_DEP) ? '+' : ' ',
			op_names[insn->op]);

	if (insn->flags & AGX_INSN_COND) {
		fprintf(fp, "%x", insn->control);
	}

	if (insn->dst.type != AGX_SRC_TYPE_NONE) {
		agx_print_operand(&insn->dst, fp);
		fprintf(fp, ", ");
	}

	for (int i = 0; i < ARRAYSIZE(insn->srcs); i++) {
		if (insn->srcs[i].type != AGX_SRC_TYPE_NONE) {
			agx_print_operand(&insn->srcs[i], fp);

			if (i < ARRAYSIZE(insn->srcs) - 1 &&
					insn->srcs[i+1].type != AGX_SRC_TYPE_NONE)
				fprintf(fp, ", ");
		}
	}

	fprintf(fp, "\n");
}

struct agx_insn_pattern patterns[] = {
	{ 0x72, 0x807f, 2, agx_decode_movsr },
	{ 0x02, 0x807f, 4, agx_decode_fcsel },
	{ 0x05, 0x037f, 4, agx_decode_load },
	{ 0x38, 0xffff, 1, agx_decode_wait },
	{ 0x8026, 0x813f, 3, agx_decode_fadd16 },
	{ 0x45, 0x007f, 4, agx_decode_store },
	{ 0x88, 0x00ff, 1, agx_decode_stop },
};

void agx_disassemble_one(uint16_t const **p, int *n) {
	uint8_t const *q = (uint8_t const *) *p;

	for (int i = 0; i < ARRAYSIZE(patterns); i++) {
		struct agx_insn_pattern const *pat = &patterns[i];
		if ((**p & pat->mask_bits) == pat->opcode_bits) {
			struct agx_insn insn = pat->decode(*p);
			if (q[0] & 0x80)
				insn.flags |= AGX_INSN_DEP;

			printf("%02x %02x ", q[0], q[1]);
			for (int j = 1; j < 5; j++) {
				if (j < pat->len)
					printf("%02x %02x ",
							q[2*j], q[2*j+1]);
				else
					printf("      ");
			}

			agx_print_insn(&insn, stdout);

			/* advance */
			*p += pat->len;
			*n -= pat->len;	

			/* detect end. don't try to disassemble any epilog padding */
			if (insn.op == AGX_OP_STOP)
				*n = 0;
			return;
		}
	}

	printf("Err: unrecognized insn: %02x %02x\n", q[0], q[1]);
	(*p)++;
	(*n)--;
	*n = 0;
}

int main(int argc, char **argv) {

	if (argc != 3)
		errx(1, "usage: disasm FILE hex-offset");
		
	FILE *f = fopen(argv[1], "rb");
	if (!f)
		err(2, "Failed to open file");

	int offset = strtol(argv[2], NULL, 16);
	fseek(f, offset, SEEK_SET);

	uint16_t code[2048];
	int n = fread(code, 2, 2048, f);

	fclose(f);

	uint16_t const *p = code;

	while (n)
		agx_disassemble_one(&p, &n);
}
