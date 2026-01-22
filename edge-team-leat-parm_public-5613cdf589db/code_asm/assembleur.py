#!/usr/bin/env python3
import re
import sys

# ----------------------------
# Cleaning / parsing helpers
# ----------------------------

def strip_comment(line: str) -> str:
    return line.split("@", 1)[0]

def norm_ws(line: str) -> str:
    # keep punctuation, just normalize whitespace
    return re.sub(r"\s+", " ", line.strip())

# Split operands but DO NOT split on commas inside [ ... ]
def split_operands_respecting_brackets(s: str) -> list[str]:
    ops: list[str] = []
    cur: list[str] = []
    depth = 0  # inside [ ... ]

    for ch in s:
        if ch == "[":
            depth += 1
            cur.append(ch)
        elif ch == "]":
            depth = max(0, depth - 1)
            cur.append(ch)
        elif ch == "," and depth > 0:
            # comma inside brackets -> keep it
            cur.append(ch)
        elif ch == "," and depth == 0:
            # comma separating operands
            op = "".join(cur).strip()
            if op:
                ops.append(op)
            cur = []
        else:
            cur.append(ch)

    last = "".join(cur).strip()
    if last:
        ops.append(last)
    return ops

def split_mnemonic_operands(line: str):
    parts = line.split(" ", 1)
    mnem = parts[0].lower()
    ops: list[str] = []
    if len(parts) > 1:
        ops = split_operands_respecting_brackets(parts[1])
    return mnem, ops

def parse_reg(tok: str) -> int:
    t = tok.strip().lower()
    if t == "sp":
        return 13
    if not t.startswith("r"):
        raise ValueError(f"registre invalide: {tok}")
    n = int(t[1:], 10)
    if not (0 <= n <= 7):
        raise ValueError(f"registre hors plage r0..r7: {tok}")
    return n

def parse_imm(tok: str) -> int:
    t = tok.strip().lower()
    if not t.startswith("#"):
        raise ValueError(f"immédiat attendu (#..): {tok}")
    s = t[1:]
    if s.startswith("0x"):
        return int(s, 16)
    return int(s, 10)

# labels can be ".goto:" or "goto:" etc.
LABEL_RE = re.compile(r"^([A-Za-z_\.][A-Za-z0-9_\.]*):$")

def is_label_line(line: str) -> str | None:
    m = LABEL_RE.match(line)
    return m.group(1) if m else None

# SP memory operand: [sp] or [sp,#4] or [sp, #0x10]
SP_MEM_RE = re.compile(r"^\[\s*sp\s*(?:,\s*#([^]]+))?\s*\]$", re.IGNORECASE)

def parse_sp_mem(tok: str) -> int:
    t = tok.strip()
    m = SP_MEM_RE.match(t)
    if not m:
        raise ValueError(f"adresse SP invalide: {tok}")
    if m.group(1) is None:
        return 0
    s = m.group(1).strip().lower()
    if s.startswith("0x"):
        return int(s, 16)
    return int(s, 10)

# ----------------------------
# Encoders (Thumb 16-bit subset)
# ----------------------------

# MOVS (imm8): 00100 Rd imm8
def enc_movs_imm(rd: int, imm8: int) -> int:
    if not (0 <= rd <= 7):
        raise ValueError("MOVS: rd doit être r0..r7")
    if not (0 <= imm8 <= 0xFF):
        raise ValueError("MOVS: imm8 doit être 0..255")
    return 0x2000 | (rd << 8) | imm8

# Shift (immediate): 00000/00001/00010 imm5 Rn Rd
def enc_shift_imm(kind: str, rd: int, rn: int, imm5: int) -> int:
    if not (0 <= rd <= 7 and 0 <= rn <= 7):
        raise ValueError("SHIFT imm: rd/rn doivent être r0..r7")
    if not (0 <= imm5 <= 31):
        raise ValueError("SHIFT imm: imm5 doit être 0..31")
    op = {"lsls": 0b00000, "lsrs": 0b00001, "asrs": 0b00010}[kind]
    return (op << 11) | (imm5 << 6) | (rn << 3) | rd

# ADD/SUB (register): 0001100 / 0001101 Rm Rn Rd
def enc_add_reg(rd: int, rn: int, rm: int) -> int:
    return 0x1800 | (rm << 6) | (rn << 3) | rd

def enc_sub_reg(rd: int, rn: int, rm: int) -> int:
    return 0x1A00 | (rm << 6) | (rn << 3) | rd

# ADD/SUB (imm3): 0001110 / 0001111 imm3 Rn Rd
def enc_add_imm3(rd: int, rn: int, imm3: int) -> int:
    if not (0 <= imm3 <= 7):
        raise ValueError("ADDS imm3: imm3 doit être 0..7")
    return 0x1C00 | (imm3 << 6) | (rn << 3) | rd

def enc_sub_imm3(rd: int, rn: int, imm3: int) -> int:
    if not (0 <= imm3 <= 7):
        raise ValueError("SUBS imm3: imm3 doit être 0..7")
    return 0x1E00 | (imm3 << 6) | (rn << 3) | rd

# Data-processing register: 010000 op4 Rm Rdn
def enc_dp(op4: int, rm: int, rdn: int) -> int:
    if not (0 <= rm <= 7 and 0 <= rdn <= 7):
        raise ValueError("DP: rm/rdn doivent être r0..r7")
    return 0x4000 | (op4 << 6) | (rm << 3) | rdn

DP_OPCODES = {
    "ands": 0b0000,
    "eors": 0b0001,
    "lsls": 0b0010,  # register form: lsls rdn, rm
    "lsrs": 0b0011,  # register form: lsrs rdn, rm
    "asrs": 0b0100,  # register form: asrs rdn, rm
    "adcs": 0b0101,
    "sbcs": 0b0110,
    "rors": 0b0111,
    "tst":  0b1000,  # tst rn, rm (rdn=rn)
    "rsbs": 0b1001,  # rsbs rd, rn, #0 (rdn=rd, rm=rn)
    "cmp":  0b1010,  # cmp rn, rm (rdn=rn)
    "cmn":  0b1011,  # cmn rn, rm (rdn=rn)
    "orrs": 0b1100,
    "muls": 0b1101,  # muls rdm, rn, rdm (rdn=rdm, rm=rn)
    "bics": 0b1110,
    "mvns": 0b1111,
}

def enc_rsbs(rd: int, rn: int) -> int:
    return enc_dp(DP_OPCODES["rsbs"], rn, rd)

def enc_cmp(rn: int, rm: int) -> int:
    return enc_dp(DP_OPCODES["cmp"], rm, rn)

def enc_cmn(rn: int, rm: int) -> int:
    return enc_dp(DP_OPCODES["cmn"], rm, rn)

def enc_tst(rn: int, rm: int) -> int:
    return enc_dp(DP_OPCODES["tst"], rm, rn)

def enc_shift_reg(kind: str, rdn: int, rm: int) -> int:
    return enc_dp(DP_OPCODES[kind], rm, rdn)

def enc_binary_dp(kind: str, rdn: int, rm: int) -> int:
    return enc_dp(DP_OPCODES[kind], rm, rdn)

def enc_mvns(rd: int, rm: int) -> int:
    return enc_dp(DP_OPCODES["mvns"], rm, rd)

def enc_muls(rdm: int, rn: int, rdm2: int) -> int:
    if rdm2 != rdm:
        raise ValueError("MULS: la 3e opérande doit être identique à la 1ère (Rdm)")
    return enc_dp(DP_OPCODES["muls"], rn, rdm)

# SP-relative load/store + SP add/sub (offset multiples of 4)
def enc_add_sp(offset: int) -> int:
    if offset % 4 != 0:
        raise ValueError("ADD SP: offset doit être multiple de 4")
    imm7 = offset // 4
    if not (0 <= imm7 <= 0x7F):
        raise ValueError("ADD SP: imm7 hors plage (0..127)")
    return 0xB000 | imm7

def enc_sub_sp(offset: int) -> int:
    if offset % 4 != 0:
        raise ValueError("SUB SP: offset doit être multiple de 4")
    imm7 = offset // 4
    if not (0 <= imm7 <= 0x7F):
        raise ValueError("SUB SP: imm7 hors plage (0..127)")
    return 0xB080 | imm7

def enc_str_sp(rt: int, offset: int) -> int:
    if offset % 4 != 0:
        raise ValueError("STR: offset doit être multiple de 4")
    imm8 = offset // 4
    if not (0 <= imm8 <= 0xFF):
        raise ValueError("STR: imm8 hors plage (0..255)")
    if not (0 <= rt <= 7):
        raise ValueError("STR: Rt doit être r0..r7")
    return 0x9000 | (rt << 8) | imm8

def enc_ldr_sp(rt: int, offset: int) -> int:
    if offset % 4 != 0:
        raise ValueError("LDR: offset doit être multiple de 4")
    imm8 = offset // 4
    if not (0 <= imm8 <= 0xFF):
        raise ValueError("LDR: imm8 hors plage (0..255)")
    if not (0 <= rt <= 7):
        raise ValueError("LDR: Rt doit être r0..r7")
    return 0x9800 | (rt << 8) | imm8

# Branches
COND_CODES = {
    "eq": 0x0, "ne": 0x1,
    "cs": 0x2, "hs": 0x2,
    "cc": 0x3, "lo": 0x3,
    "mi": 0x4, "pl": 0x5,
    "vs": 0x6, "vc": 0x7,
    "hi": 0x8, "ls": 0x9,
    "ge": 0xA, "lt": 0xB,
    "gt": 0xC, "le": 0xD,
    "al": 0xE,
}

def enc_b_cond(cond: int, imm8_signed: int) -> int:
    if not (-128 <= imm8_signed <= 127):
        raise ValueError("B<c>: imm8 hors plage (-128..127)")
    return 0xD000 | (cond << 8) | (imm8_signed & 0xFF)

def enc_b_uncond(imm11_signed: int) -> int:
    if not (-1024 <= imm11_signed <= 1023):
        raise ValueError("B: imm11 hors plage (-1024..1023)")
    return 0xE000 | (imm11_signed & 0x7FF)

# ----------------------------
# Two-pass assembly
# ----------------------------

def preprocess_lines(path_in: str) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    with open(path_in, "r", encoding="utf-8") as f:
        for lineno, raw in enumerate(f, 1):
            line = strip_comment(raw)
            line = norm_ws(line)
            if not line:
                continue
            low = line.lower()

            # ignore per spec
            if low.startswith("push "):
                continue
            if low.startswith("add r7, sp"):
                continue

            # directives start with '.' BUT labels like ".goto:" must be kept
            if line.startswith(".") and not line.endswith(":"):
                continue

            out.append((lineno, line))
    return out

def pass1_collect_labels(lines: list[tuple[int, str]]) -> dict[str, int]:
    labels: dict[str, int] = {}
    instr_index = 0
    for _, line in lines:
        lab = is_label_line(line)
        if lab is not None:
            labels[lab] = instr_index
        else:
            instr_index += 1
    return labels

def assemble_instruction(line: str, labels: dict[str, int], instr_index: int) -> int:
    low = line.lower()
    mnem, ops = split_mnemonic_operands(low)

    # Branches: b label / b<cond> label (but not bics)
    if mnem.startswith("b") and mnem != "bics":
        if len(ops) != 1:
            raise ValueError("B attend un seul opérande label")
        target = ops[0]
        if target not in labels:
            raise ValueError(f"label inconnu: {target}")
        imm = labels[target] - instr_index - 3
        if mnem == "b":
            return enc_b_uncond(imm)
        cond_str = mnem[1:]
        cond = COND_CODES.get(cond_str.lower())
        if cond is None:
            raise ValueError(f"condition inconnue dans {mnem}")
        return enc_b_cond(cond, imm)

    # MOVS
    if mnem == "movs":
        if len(ops) != 2:
            raise ValueError("MOVS attend: movs rd, #imm8")
        rd = parse_reg(ops[0])
        imm8 = parse_imm(ops[1])
        return enc_movs_imm(rd, imm8)

    # SP add/sub
    if mnem == "add":
        if len(ops) == 2 and ops[0].lower() == "sp" and ops[1].startswith("#"):
            return enc_add_sp(parse_imm(ops[1]))
        raise ValueError("ADD supporté ici: add sp, #offset")

    if mnem == "sub":
        if len(ops) == 2 and ops[0].lower() == "sp" and ops[1].startswith("#"):
            return enc_sub_sp(parse_imm(ops[1]))
        raise ValueError("SUB supporté ici: sub sp, #offset")

    # LDR/STR SP-relative
    if mnem == "str":
        if len(ops) != 2:
            raise ValueError("STR attend: str rt, [sp, #offset]")
        rt = parse_reg(ops[0])
        off = parse_sp_mem(ops[1])
        return enc_str_sp(rt, off)

    if mnem == "ldr":
        if len(ops) != 2:
            raise ValueError("LDR attend: ldr rt, [sp, #offset]")
        rt = parse_reg(ops[0])
        off = parse_sp_mem(ops[1])
        return enc_ldr_sp(rt, off)

    # Shift immediate (3 operands with #imm5)
    if mnem in ("lsls", "lsrs", "asrs") and len(ops) == 3 and ops[2].startswith("#"):
        rd = parse_reg(ops[0])
        rn = parse_reg(ops[1])
        imm5 = parse_imm(ops[2])
        return enc_shift_imm(mnem, rd, rn, imm5)

    # Shift register (2 operands)
    if mnem in ("lsls", "lsrs", "asrs") and len(ops) == 2:
        rdn = parse_reg(ops[0])
        rm = parse_reg(ops[1])
        return enc_shift_reg(mnem, rdn, rm)

    # ADDS/SUBS (reg or imm3)
    if mnem in ("adds", "subs"):
        if len(ops) != 3:
            raise ValueError(f"{mnem.upper()} attend 3 opérandes")
        rd = parse_reg(ops[0])
        rn = parse_reg(ops[1])
        if ops[2].startswith("#"):
            imm3 = parse_imm(ops[2])
            return enc_add_imm3(rd, rn, imm3) if mnem == "adds" else enc_sub_imm3(rd, rn, imm3)
        rm = parse_reg(ops[2])
        return enc_add_reg(rd, rn, rm) if mnem == "adds" else enc_sub_reg(rd, rn, rm)

    # RSBS
    if mnem == "rsbs":
        if len(ops) != 3:
            raise ValueError("RSBS attend: rsbs rd, rn, #0")
        rd = parse_reg(ops[0])
        rn = parse_reg(ops[1])
        imm = parse_imm(ops[2])
        if imm != 0:
            raise ValueError("RSBS: seul #0 est supporté")
        return enc_rsbs(rd, rn)

    # DP reg ops
    if mnem in ("ands", "eors", "orrs", "bics", "adcs", "sbcs", "rors"):
        if len(ops) != 2:
            raise ValueError(f"{mnem.upper()} attend: {mnem} rdn, rm")
        rdn = parse_reg(ops[0])
        rm = parse_reg(ops[1])
        return enc_binary_dp(mnem, rdn, rm)

    if mnem == "mvns":
        if len(ops) != 2:
            raise ValueError("MVNS attend: mvns rd, rm")
        rd = parse_reg(ops[0])
        rm = parse_reg(ops[1])
        return enc_mvns(rd, rm)

    if mnem == "tst":
        if len(ops) != 2:
            raise ValueError("TST attend: tst rn, rm")
        rn = parse_reg(ops[0])
        rm = parse_reg(ops[1])
        return enc_tst(rn, rm)

    if mnem == "cmp":
        if len(ops) != 2:
            raise ValueError("CMP attend: cmp rn, rm")
        rn = parse_reg(ops[0])
        rm = parse_reg(ops[1])
        return enc_cmp(rn, rm)

    if mnem == "cmn":
        if len(ops) != 2:
            raise ValueError("CMN attend: cmn rn, rm")
        rn = parse_reg(ops[0])
        rm = parse_reg(ops[1])
        return enc_cmn(rn, rm)

    if mnem == "muls":
        if len(ops) != 3:
            raise ValueError("MULS attend: muls rdm, rn, rdm")
        rdm = parse_reg(ops[0])
        rn = parse_reg(ops[1])
        rdm2 = parse_reg(ops[2])
        return enc_muls(rdm, rn, rdm2)

    raise ValueError(f"instruction non supportée: {mnem}")

def assemble_file(path_in: str) -> list[int]:
    lines = preprocess_lines(path_in)
    labels = pass1_collect_labels(lines)

    halfwords: list[int] = []
    instr_index = 0
    for lineno, line in lines:
        if is_label_line(line) is not None:
            continue
        try:
            hw = assemble_instruction(line, labels, instr_index)
            halfwords.append(hw & 0xFFFF)
            instr_index += 1
        except Exception as e:
            raise RuntimeError(f"Ligne {lineno}: {line}\n  Erreur: {e}") from e

    return halfwords

def write_logisim(path_out: str, halfwords: list[int], per_line: int = 16):
    with open(path_out, "w", encoding="utf-8") as f:
        f.write("v2.0 raw\n")
        for i, hw in enumerate(halfwords):
            if i and (i % per_line == 0):
                f.write("\n")
            f.write(f"{hw:04x}")
            if i != len(halfwords) - 1:
                f.write(" ")
        f.write("\n")

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 assembleur.py input.s output.bin")
        sys.exit(2)

    inp, outp = sys.argv[1], sys.argv[2]
    halfwords = assemble_file(inp)
    write_logisim(outp, halfwords)

    # stdout for quick diff
    print("v2.0 raw")
    print(" ".join(f"{x:04x}" for x in halfwords))

if __name__ == "__main__":
    main()
