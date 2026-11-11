package bvm02.hook;

import java.util.Locale;

/**
 * Pure-Java, strictly read-only Thumb-16 / Thumb-32 getter & version-copier simulator.
 *
 * Evaluates short Bluedroid getter functions (such as {@code BTM_ReadLocalFeatures},
 * {@code BTM_ReadLocalSupportedCommands}, {@code BTM_ReadBrcmFeatures}, {@code BTM_ReadLocalVersion},
 * and {@code bt_hc_get_interface}) in Java without executing native instructions or mutating process RAM.
 * Any memory stores (e.g. {@code BTM_ReadLocalVersion(p_vers)}) are isolated strictly to an internal
 * 128-byte virtual scratch buffer mapped at {@code SCRATCH_BASE}.
 */
public final class Thumb2GetterSim {

    public static final long SCRATCH_BASE = 0x70000000L;
    public static final int SCRATCH_SIZE = 128;
    private static final long STACK_TOP = 0x700000F0L;
    private static final long RETURN_LR = 0xFFFFFFFFL;

    public interface MemReader {
        byte[] read(long addr, int len);
    }

    public static final class SimResult {
        public final boolean ok;
        public final long r0;
        public final long gotTarget;
        public final byte[] scratch;
        public final int steps;
        public final String stopReason;

        public SimResult(boolean ok, long r0, long gotTarget, byte[] scratch, int steps, String stopReason) {
            this.ok = ok;
            this.r0 = r0;
            this.gotTarget = gotTarget;
            this.scratch = scratch;
            this.steps = steps;
            this.stopReason = stopReason;
        }
    }

    private Thumb2GetterSim() {}

    public static SimResult simulate(long fnCleanVaddr, int fnMaxBytes, long initialR0, MemReader mem) {
        byte[] scratch = new byte[SCRATCH_SIZE];
        if (mem == null || fnCleanVaddr <= 0 || fnMaxBytes < 2) {
            return new SimResult(false, 0L, 0L, scratch, 0, "invalid_args");
        }
        int limitBytes = Math.min(Math.max(fnMaxBytes, 24), 256);
        byte[] code = mem.read(fnCleanVaddr, limitBytes);
        if (code == null || code.length < 2) {
            return new SimResult(false, 0L, 0L, scratch, 0, "unreadable_code");
        }

        long[] regs = new long[16];
        regs[0] = initialR0 & 0xFFFFFFFFL;
        regs[13] = STACK_TOP;
        regs[14] = RETURN_LR;
        byte[] stack = new byte[64];

        long gotBase = 0L;
        long gotTarget = 0L;
        int off = 0;
        int steps = 0;

        while (steps < 40 && off >= 0 && off + 2 <= code.length) {
            steps++;
            long pcInsn = fnCleanVaddr + off;
            int hw1 = u16le(code, off);

            // 32-bit Thumb-2 instruction check: bits [15:11] in {11101, 11110, 11111}
            if (hw1 >= 0xE800) {
                if (off + 4 > code.length) {
                    return new SimResult(false, regs[0], gotTarget, scratch, steps, "truncated_thumb32");
                }
                int hw2 = u16le(code, off + 2);

                // PUSH.W {regs, lr}: 0xE92D <reglist>
                if (hw1 == 0xE92D) {
                    for (int r = 14; r >= 0; r--) {
                        if ((hw2 & (1 << r)) != 0) {
                            regs[13] = (regs[13] - 4L) & 0xFFFFFFFFL;
                            writeStack32(stack, regs[13], regs[r]);
                        }
                    }
                    off += 4;
                    continue;
                }

                // POP.W {regs, pc}: 0xE8BD <reglist>
                if (hw1 == 0xE8BD) {
                    for (int r = 0; r <= 15; r++) {
                        if ((hw2 & (1 << r)) != 0) {
                            long val = readStack32(stack, regs[13]);
                            regs[13] = (regs[13] + 4L) & 0xFFFFFFFFL;
                            if (r == 15) {
                                if (val == RETURN_LR) {
                                    return new SimResult(true, regs[0], gotTarget, scratch, steps, "pop_w_pc");
                                }
                                return new SimResult(false, regs[0], gotTarget, scratch, steps, "pop_w_non_lr");
                            }
                            regs[r] = val;
                        }
                    }
                    off += 4;
                    continue;
                }

                // ADD.W Rd, Rn, #<ThumbExpandImm> (T3): 11110 i 0 1000 S Rn | 0 imm3 Rd imm8
                if ((hw1 & 0xFBEF) == 0xF100 && (hw1 & 0xF) != 15 && (hw2 & 0x8000) == 0) {
                    int rn = hw1 & 0xF;
                    int rd = (hw2 >> 8) & 0xF;
                    long imm = thumbExpandImm((hw1 >> 10) & 1, (hw2 >> 12) & 7, hw2 & 0xFF);
                    if (rd != 15 && rd != 13) {
                        regs[rd] = (regs[rn] + imm) & 0xFFFFFFFFL;
                    }
                    off += 4;
                    continue;
                }

                // SUB.W Rd, Rn, #<ThumbExpandImm> (T3): 11110 i 0 1101 S Rn | 0 imm3 Rd imm8
                if ((hw1 & 0xFBEF) == 0xF1A0 && (hw1 & 0xF) != 15 && (hw2 & 0x8000) == 0) {
                    int rn = hw1 & 0xF;
                    int rd = (hw2 >> 8) & 0xF;
                    long imm = thumbExpandImm((hw1 >> 10) & 1, (hw2 >> 12) & 7, hw2 & 0xFF);
                    if (rd != 15 && rd != 13) {
                        regs[rd] = (regs[rn] - imm) & 0xFFFFFFFFL;
                    }
                    off += 4;
                    continue;
                }

                // ADDW Rd, Rn, #imm12 (T4): 11110 i 10 0000 Rn | 0 imm3 Rd imm8
                if ((hw1 & 0xFBF0) == 0xF200 && (hw2 & 0x8000) == 0) {
                    int rn = hw1 & 0xF;
                    int rd = (hw2 >> 8) & 0xF;
                    long imm12 = (((hw1 >> 10) & 1) << 11) | (((hw2 >> 12) & 7) << 8) | (hw2 & 0xFF);
                    long base = (rn == 15) ? ((pcInsn + 4L) & ~3L) : regs[rn];
                    regs[rd] = (base + imm12) & 0xFFFFFFFFL;
                    off += 4;
                    continue;
                }

                // SUBW Rd, Rn, #imm12 (T4): 11110 i 10 1010 Rn | 0 imm3 Rd imm8
                if ((hw1 & 0xFBF0) == 0xF2A0 && (hw2 & 0x8000) == 0) {
                    int rn = hw1 & 0xF;
                    int rd = (hw2 >> 8) & 0xF;
                    long imm12 = (((hw1 >> 10) & 1) << 11) | (((hw2 >> 12) & 7) << 8) | (hw2 & 0xFF);
                    long base = (rn == 15) ? ((pcInsn + 4L) & ~3L) : regs[rn];
                    regs[rd] = (base - imm12) & 0xFFFFFFFFL;
                    off += 4;
                    continue;
                }

                // MOV.W Rd, #<ThumbExpandImm>: 11110 i 0 0010 S 1111 | 0 imm3 Rd imm8
                if ((hw1 & 0xFBEF) == 0xF04F && (hw2 & 0x8000) == 0) {
                    int rd = (hw2 >> 8) & 0xF;
                    long imm = thumbExpandImm((hw1 >> 10) & 1, (hw2 >> 12) & 7, hw2 & 0xFF);
                    regs[rd] = imm;
                    off += 4;
                    continue;
                }

                // MOVW Rd, #imm16: 11110 i 10 0100 imm4 | 0 imm3 Rd imm8
                if ((hw1 & 0xFBF0) == 0xF240 && (hw2 & 0x8000) == 0) {
                    int rd = (hw2 >> 8) & 0xF;
                    long imm16 = ((long) (hw1 & 0xF) << 12)
                            | (((long) ((hw1 >> 10) & 1)) << 11)
                            | (((long) ((hw2 >> 12) & 7)) << 8)
                            | (hw2 & 0xFF);
                    regs[rd] = imm16;
                    off += 4;
                    continue;
                }

                // LDR.W / LDRH.W / LDRB.W Rt, [Rn, #imm12]
                if ((hw1 & 0xFFF0) == 0xF8D0 || (hw1 & 0xFFF0) == 0xF8B0 || (hw1 & 0xFFF0) == 0xF890) {
                    int rn = hw1 & 0xF;
                    int rt = (hw2 >> 12) & 0xF;
                    int imm12 = hw2 & 0xFFF;
                    long addr = ((rn == 15 ? ((pcInsn + 4L) & ~3L) : regs[rn]) + imm12) & 0xFFFFFFFFL;
                    int width = ((hw1 & 0xFFF0) == 0xF8D0) ? 4 : (((hw1 & 0xFFF0) == 0xF8B0) ? 2 : 1);
                    Long loaded = readVal(addr, width, scratch, mem);
                    if (loaded == null) {
                        return new SimResult(false, regs[0], gotTarget, scratch, steps,
                                String.format(Locale.US, "ldr_w_fault@0x%x", Long.valueOf(addr)));
                    }
                    regs[rt] = loaded.longValue();
                    off += 4;
                    continue;
                }

                // STR.W / STRH.W / STRB.W Rt, [Rn, #imm12] (strictly to virtual scratch)
                if ((hw1 & 0xFFF0) == 0xF8C0 || (hw1 & 0xFFF0) == 0xF8A0 || (hw1 & 0xFFF0) == 0xF880) {
                    int rn = hw1 & 0xF;
                    int rt = (hw2 >> 12) & 0xF;
                    int imm12 = hw2 & 0xFFF;
                    long addr = (regs[rn] + imm12) & 0xFFFFFFFFL;
                    int width = ((hw1 & 0xFFF0) == 0xF8C0) ? 4 : (((hw1 & 0xFFF0) == 0xF8A0) ? 2 : 1);
                    if (!writeScratch(scratch, addr, width, regs[rt])) {
                        return new SimResult(false, regs[0], gotTarget, scratch, steps,
                                String.format(Locale.US, "str_w_outside_scratch@0x%x", Long.valueOf(addr)));
                    }
                    off += 4;
                    continue;
                }

                return new SimResult(false, regs[0], gotTarget, scratch, steps,
                        String.format(Locale.US, "unhandled_t32=0x%04x_%04x@+0x%x",
                                Integer.valueOf(hw1), Integer.valueOf(hw2), Integer.valueOf(off)));
            }

            // ---- 16-bit Thumb instructions ----

            // NOP / IT hints (0xBF00)
            if (hw1 == 0xBF00) {
                off += 2;
                continue;
            }

            // BX Rm: 010001 11 0 Rm 000
            if ((hw1 & 0xFF87) == 0x4700) {
                int rm = (hw1 >> 3) & 0xF;
                if (regs[rm] == RETURN_LR) {
                    return new SimResult(true, regs[0], gotTarget, scratch, steps, "bx_lr");
                }
                return new SimResult(false, regs[0], gotTarget, scratch, steps, "bx_non_lr");
            }

            // PUSH {reglist, lr}: 1011 010 M reglist
            if ((hw1 & 0xFE00) == 0xB400) {
                if ((hw1 & 0x0100) != 0) {
                    regs[13] = (regs[13] - 4L) & 0xFFFFFFFFL;
                    writeStack32(stack, regs[13], regs[14]);
                }
                for (int r = 7; r >= 0; r--) {
                    if ((hw1 & (1 << r)) != 0) {
                        regs[13] = (regs[13] - 4L) & 0xFFFFFFFFL;
                        writeStack32(stack, regs[13], regs[r]);
                    }
                }
                off += 2;
                continue;
            }

            // POP {reglist, pc}: 1011 110 P reglist
            if ((hw1 & 0xFE00) == 0xBC00) {
                for (int r = 0; r <= 7; r++) {
                    if ((hw1 & (1 << r)) != 0) {
                        regs[r] = readStack32(stack, regs[13]);
                        regs[13] = (regs[13] + 4L) & 0xFFFFFFFFL;
                    }
                }
                if ((hw1 & 0x0100) != 0) {
                    long retPc = readStack32(stack, regs[13]);
                    regs[13] = (regs[13] + 4L) & 0xFFFFFFFFL;
                    if (retPc == RETURN_LR) {
                        return new SimResult(true, regs[0], gotTarget, scratch, steps, "pop_pc");
                    }
                    return new SimResult(false, regs[0], gotTarget, scratch, steps, "pop_non_lr");
                }
                off += 2;
                continue;
            }

            // LDR Rt, [PC, #imm8*4]: 01001 Rt imm8
            if ((hw1 & 0xF800) == 0x4800) {
                int rt = (hw1 >> 8) & 7;
                long litAddr = ((pcInsn + 4L) & ~3L) + ((hw1 & 0xFF) << 2);
                Long loaded = readVal(litAddr, 4, scratch, mem);
                if (loaded == null) {
                    return new SimResult(false, regs[0], gotTarget, scratch, steps,
                            String.format(Locale.US, "ldr_lit_fault@0x%x", Long.valueOf(litAddr)));
                }
                regs[rt] = loaded.longValue();
                off += 2;
                continue;
            }

            // ADD Rdn, Rm (high registers): 010001 00 DN Rm Rdn
            if ((hw1 & 0xFF00) == 0x4400) {
                int rdn = ((hw1 & 0x80) >> 4) | (hw1 & 7);
                int rm = (hw1 >> 3) & 0xF;
                long valM = (rm == 15) ? (pcInsn + 4L) : regs[rm];
                long valD = (rdn == 15) ? (pcInsn + 4L) : regs[rdn];
                if (rdn == 15) {
                    return new SimResult(false, regs[0], gotTarget, scratch, steps, "add_pc");
                }
                regs[rdn] = (valD + valM) & 0xFFFFFFFFL;
                if (rm == 15) {
                    gotBase = regs[rdn];
                }
                off += 2;
                continue;
            }

            // MOV Rd, Rm (high registers): 010001 10 D Rm Rd
            if ((hw1 & 0xFF00) == 0x4600) {
                int rd = ((hw1 & 0x80) >> 4) | (hw1 & 7);
                int rm = (hw1 >> 3) & 0xF;
                long valM = (rm == 15) ? (pcInsn + 4L) : regs[rm];
                if (rd == 15) {
                    if (valM == RETURN_LR) {
                        return new SimResult(true, regs[0], gotTarget, scratch, steps, "mov_pc_lr");
                    }
                    return new SimResult(false, regs[0], gotTarget, scratch, steps, "mov_pc");
                }
                regs[rd] = valM & 0xFFFFFFFFL;
                off += 2;
                continue;
            }

            // LDR / LDRH / LDRB Rt, [Rn, Rm]: 0101 1xx Rm Rn Rt
            if ((hw1 & 0xFE00) == 0x5800 || (hw1 & 0xFE00) == 0x5A00 || (hw1 & 0xFE00) == 0x5C00) {
                int rm = (hw1 >> 6) & 7;
                int rn = (hw1 >> 3) & 7;
                int rt = hw1 & 7;
                long addr = (regs[rn] + regs[rm]) & 0xFFFFFFFFL;
                int width = ((hw1 & 0xFE00) == 0x5800) ? 4 : (((hw1 & 0xFE00) == 0x5A00) ? 2 : 1);
                Long loaded = readVal(addr, width, scratch, mem);
                if (loaded == null) {
                    return new SimResult(false, regs[0], gotTarget, scratch, steps,
                            String.format(Locale.US, "ldr_reg_fault@0x%x", Long.valueOf(addr)));
                }
                if (width == 4 && (regs[rn] == gotBase || regs[rm] == gotBase || (regs[rm] & 0x80000000L) != 0L)) {
                    gotTarget = loaded.longValue();
                }
                regs[rt] = loaded.longValue();
                off += 2;
                continue;
            }

            // LDR Rt, [Rn, #imm5*4] (0x6800) / LDRB (0x7800) / LDRH (0x8800)
            if ((hw1 & 0xF800) == 0x6800 || (hw1 & 0xF800) == 0x7800 || (hw1 & 0xF800) == 0x8800) {
                int imm5 = (hw1 >> 6) & 0x1F;
                int rn = (hw1 >> 3) & 7;
                int rt = hw1 & 7;
                int scale = ((hw1 & 0xF800) == 0x6800) ? 4 : (((hw1 & 0xF800) == 0x8800) ? 2 : 1);
                long addr = (regs[rn] + (long) imm5 * scale) & 0xFFFFFFFFL;
                Long loaded = readVal(addr, scale, scratch, mem);
                if (loaded == null) {
                    return new SimResult(false, regs[0], gotTarget, scratch, steps,
                            String.format(Locale.US, "ldr_imm_fault@0x%x", Long.valueOf(addr)));
                }
                if (scale == 4 && imm5 == 0 && regs[rn] == gotBase) {
                    gotTarget = loaded.longValue();
                }
                regs[rt] = loaded.longValue();
                off += 2;
                continue;
            }

            // STR Rt, [Rn, #imm5*4] (0x6000) / STRB (0x7000) / STRH (0x8000) -> virtual scratch only
            if ((hw1 & 0xF800) == 0x6000 || (hw1 & 0xF800) == 0x7000 || (hw1 & 0xF800) == 0x8000) {
                int imm5 = (hw1 >> 6) & 0x1F;
                int rn = (hw1 >> 3) & 7;
                int rt = hw1 & 7;
                int scale = ((hw1 & 0xF800) == 0x6000) ? 4 : (((hw1 & 0xF800) == 0x8000) ? 2 : 1);
                long addr = (regs[rn] + (long) imm5 * scale) & 0xFFFFFFFFL;
                if (!writeScratch(scratch, addr, scale, regs[rt])) {
                    return new SimResult(false, regs[0], gotTarget, scratch, steps,
                            String.format(Locale.US, "str_imm_outside_scratch@0x%x", Long.valueOf(addr)));
                }
                off += 2;
                continue;
            }

            // LSLS / LSRS Rd, Rm, #imm5 (0x0000..0x0FFF)
            if ((hw1 & 0xF000) == 0x0000) {
                boolean isRight = (hw1 & 0x0800) != 0;
                int imm5 = (hw1 >> 6) & 0x1F;
                int rm = (hw1 >> 3) & 7;
                int rd = hw1 & 7;
                long v = regs[rm] & 0xFFFFFFFFL;
                if (!isRight) {
                    regs[rd] = (v << imm5) & 0xFFFFFFFFL;
                } else {
                    regs[rd] = (imm5 == 0) ? 0L : ((v >>> imm5) & 0xFFFFFFFFL);
                }
                off += 2;
                continue;
            }

            // ADDS / SUBS Rd, Rn, Rm (0x1800 / 0x1A00) & ADDS / SUBS Rd, Rn, #imm3 (0x1C00 / 0x1E00)
            if ((hw1 & 0xF800) == 0x1800) {
                int subOp = (hw1 >> 9) & 3;
                int rmOrImm = (hw1 >> 6) & 7;
                int rn = (hw1 >> 3) & 7;
                int rd = hw1 & 7;
                long rhs = (subOp < 2) ? regs[rmOrImm] : rmOrImm;
                regs[rd] = ((subOp & 1) == 0 ? (regs[rn] + rhs) : (regs[rn] - rhs)) & 0xFFFFFFFFL;
                off += 2;
                continue;
            }

            // MOVS / CMP / ADDS / SUBS Rdn, #imm8 (0x2000..0x3FFF)
            if ((hw1 & 0xE000) == 0x2000) {
                int op = (hw1 >> 11) & 3;
                int rdn = (hw1 >> 8) & 7;
                long imm8 = hw1 & 0xFF;
                if (op == 0) {
                    regs[rdn] = imm8;
                } else if (op == 2) {
                    regs[rdn] = (regs[rdn] + imm8) & 0xFFFFFFFFL;
                } else if (op == 3) {
                    regs[rdn] = (regs[rdn] - imm8) & 0xFFFFFFFFL;
                }
                off += 2;
                continue;
            }

            // UXTH / UXTB Rd, Rm (0xB280 / 0xB2C0)
            if ((hw1 & 0xFFC0) == 0xB280 || (hw1 & 0xFFC0) == 0xB2C0) {
                int rm = (hw1 >> 3) & 7;
                int rd = hw1 & 7;
                long mask = ((hw1 & 0xFFC0) == 0xB280) ? 0xFFFFL : 0xFFL;
                regs[rd] = regs[rm] & mask;
                off += 2;
                continue;
            }

            // CBZ / CBNZ Rn, #imm (0xB100..0xB3FF, 0xB900..0xBBFF)
            if ((hw1 & 0xF500) == 0xB100) {
                boolean isNonZero = (hw1 & 0x0800) != 0;
                int rn = hw1 & 7;
                int branchDisp = (((hw1 >> 9) & 1) << 6) | (((hw1 >> 3) & 0x1F) << 1);
                boolean take = isNonZero ? (regs[rn] != 0L) : (regs[rn] == 0L);
                if (take) {
                    off = off + 4 + branchDisp;
                } else {
                    off += 2;
                }
                continue;
            }

            return new SimResult(false, regs[0], gotTarget, scratch, steps,
                    String.format(Locale.US, "unhandled_t16=0x%04x@+0x%x",
                            Integer.valueOf(hw1), Integer.valueOf(off)));
        }

        return new SimResult(false, regs[0], gotTarget, scratch, steps, "step_or_bounds_limit");
    }

    public static long thumbExpandImm(int iBit, int imm3, int imm8) {
        int imm12 = ((iBit & 1) << 11) | ((imm3 & 7) << 8) | (imm8 & 0xFF);
        if ((imm12 >> 10) == 0) {
            int sub = (imm12 >> 8) & 3;
            long b = imm8 & 0xFFL;
            switch (sub) {
                case 0:
                    return b;
                case 1:
                    return (b << 16) | b;
                case 2:
                    return (b << 24) | (b << 8);
                default:
                    return (b << 24) | (b << 16) | (b << 8) | b;
            }
        }
        int unrotated = 0x80 | (imm12 & 0x7F);
        int rot = (imm12 >> 7) & 0x1F;
        return Integer.rotateRight(unrotated, rot) & 0xFFFFFFFFL;
    }

    private static Long readVal(long addr, int width, byte[] scratch, MemReader mem) {
        if (addr >= SCRATCH_BASE && addr + width <= SCRATCH_BASE + scratch.length) {
            int o = (int) (addr - SCRATCH_BASE);
            if (width == 1) return Long.valueOf(scratch[o] & 0xFFL);
            if (width == 2) return Long.valueOf(u16le(scratch, o));
            return Long.valueOf(u32le(scratch, o));
        }
        byte[] b = mem.read(addr, width);
        if (b == null || b.length < width) return null;
        if (width == 1) return Long.valueOf(b[0] & 0xFFL);
        if (width == 2) return Long.valueOf(u16le(b, 0));
        return Long.valueOf(u32le(b, 0));
    }

    private static boolean writeScratch(byte[] scratch, long addr, int width, long val) {
        if (addr < SCRATCH_BASE || addr + width > SCRATCH_BASE + scratch.length) {
            return false;
        }
        int o = (int) (addr - SCRATCH_BASE);
        scratch[o] = (byte) (val & 0xFFL);
        if (width >= 2) {
            scratch[o + 1] = (byte) ((val >> 8) & 0xFFL);
        }
        if (width == 4) {
            scratch[o + 2] = (byte) ((val >> 16) & 0xFFL);
            scratch[o + 3] = (byte) ((val >> 24) & 0xFFL);
        }
        return true;
    }

    private static void writeStack32(byte[] stack, long sp, long val) {
        int o = (int) (sp - (STACK_TOP - stack.length));
        if (o >= 0 && o + 4 <= stack.length) {
            stack[o] = (byte) (val & 0xFFL);
            stack[o + 1] = (byte) ((val >> 8) & 0xFFL);
            stack[o + 2] = (byte) ((val >> 16) & 0xFFL);
            stack[o + 3] = (byte) ((val >> 24) & 0xFFL);
        }
    }

    private static long readStack32(byte[] stack, long sp) {
        int o = (int) (sp - (STACK_TOP - stack.length));
        if (o >= 0 && o + 4 <= stack.length) {
            return u32le(stack, o);
        }
        return 0L;
    }

    private static int u16le(byte[] b, int off) {
        return (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8);
    }

    private static long u32le(byte[] b, int off) {
        return ((long) (b[off] & 0xFF))
                | (((long) (b[off + 1] & 0xFF)) << 8)
                | (((long) (b[off + 2] & 0xFF)) << 16)
                | (((long) (b[off + 3] & 0xFF)) << 24);
    }
}
