`timescale 1ns/1ps
//------------------------------------------------------------------------------
// ecdsa_secp256k1_sign : microcoded ECDSA signer for secp256k1
//
//   Inputs : d_in  private key   (1 <= d < n)
//            k_in  per-signature nonce (1 <= k < n)  -- supplied by the caller
//            z_in  message hash (e.g. SHA-256d of the message), any 256-bit value
//   Outputs: r_out, s_out   (s normalised to the low half of the range,
//                            as required by Bitcoin/Ethereum; see LOW_S)
//            fail  : set instead of a signature if k or d is out of range,
//                    or if r == 0 or s == 0  (caller must pick a new k)
//
// Interface:  pulse `start` while `busy` is low with inputs stable.
//             `done` pulses for one cycle when r_out/s_out/fail are valid.
//
// Architecture
//   * one 1-bit/clock modular multiplier (modmul_serial), shared by mod p and mod n
//   * combinational modular add/sub
//   * 32 x 256-bit register file
//   * microcode ROM (ecdsa_ucode_rom) holding straight-line routines for the
//     Renes-Costello-Batina complete point add / double formulas (a=0, b=7),
//     the inversion step, and the final signature arithmetic
//   * FSM: constant-time Montgomery ladder over all 256 bits of k, Fermat
//     inversions (a^(m-2)) for Z^-1 mod p and k^-1 mod n
//
// Timing is independent of the secret values (fixed 256-cycle multiplies,
// fixed iteration counts, conditional swap instead of branches).
// ~ 1.9 M clock cycles per signature (about 19 ms at 100 MHz).
//
// IMPORTANT: nonce generation is NOT done here.  k must be unpredictable and
// never reused: use RFC 6979 or a vetted TRNG+DRBG in front of this core.
//------------------------------------------------------------------------------
module ecdsa_secp256k1_sign #(
    parameter LOW_S = 1
) (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         wipe,        // synchronous: abort and clear every register
    input  wire         start,
    input  wire         mode_pub,    // 1: compute public key d*G (k_in must equal d_in)
    input  wire [255:0] d_in,
    input  wire [255:0] k_in,
    input  wire [255:0] z_in,
    input  wire         use_base,    // 1: multiply (bx_in,by_in) instead of G (ECDH); caller must
    input  wire [255:0] bx_in,       //    have validated that the point is on the curve
    input  wire [255:0] by_in,
    output reg          busy,
    output reg          done,
    output reg          fail,
    output wire [255:0] r_out,
    output wire [255:0] s_out,
    output wire [255:0] px_out,      // public key x (valid after a mode_pub run)
    output wire [255:0] py_out       // public key y
);
    // ------------------------------------------------------------ curve ---
    localparam [255:0] P      = 256'hFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    localparam [255:0] N      = 256'hFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    localparam [255:0] GX     = 256'h79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    localparam [255:0] GY     = 256'h483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
    localparam [255:0] P_M2   = P - 256'd2;     // Fermat exponent for 1/x mod p
    localparam [255:0] N_M2   = N - 256'd2;     // Fermat exponent for 1/x mod n
    localparam [255:0] HALF_N = N >> 1;

    // microcode entry points (A_*) and register indices (I_*)
    `include "ecdsa_ucode_entries.vh"

    // ----------------------------------------------------- register file --
    reg [255:0] rf [0:31];
    integer ii;
    initial for (ii = 0; ii < 32; ii = ii + 1) rf[ii] = 256'd0;

    // ------------------------------------------------------------- FSM ----
    localparam [4:0]
        ST_IDLE      = 5'd0,
        ST_SWAP1     = 5'd1,
        ST_CALL_DBL  = 5'd2,
        ST_CALL_MOVE = 5'd3,
        ST_SWAP2     = 5'd4,
        ST_INV_STEP  = 5'd5,
        ST_INV_SEL   = 5'd6,
        ST_CHECK_R   = 5'd7,
        ST_LOWS      = 5'd8,
        ST_FINISH    = 5'd9,
        ST_FETCH     = 5'd10,
        ST_WAITMUL   = 5'd11;

    reg [4:0] st, ret;
    reg [8:0] pc;
    reg [7:0] idx;          // ladder bit index
    reg [7:0] idx2;         // inversion exponent bit index
    reg       invmod;       // 0: inversion mod p, 1: mod n
    reg [4:0] dst_r;        // destination of the multiply in flight
    reg       mp;           // latched mode_pub

    // ----------------------------------------------- micro-op decode ------
    wire [17:0] instr;
    ecdsa_ucode_rom u_rom (.addr(pc), .instr(instr));

    wire [1:0]  op    = instr[17:16];
    wire        modb  = instr[15];
    wire [4:0]  rd    = instr[14:10];
    wire [4:0]  ra    = instr[9:5];
    wire [4:0]  rb    = instr[4:0];
    wire [255:0] ea   = rf[ra];
    wire [255:0] eb   = rf[rb];
    wire [255:0] em   = modb ? N : P;

    // combinational modular add / sub (operands < 2m for add, < m for sub)
    wire [256:0] sum    = {1'b0, ea} + {1'b0, eb};
    wire [256:0] sum_m  = sum - {1'b0, em};
    wire [255:0] alu_add = sum_m[256] ? sum[255:0] : sum_m[255:0];
    wire [256:0] diff   = {1'b0, ea} - {1'b0, eb};
    wire [255:0] alu_sub = diff[256] ? (diff[255:0] + em) : diff[255:0];

    // -------------------------------------------------- multiplier --------
    wire        mul_start = (st == ST_FETCH) && (op == 2'd1);
    wire        mm_busy, mm_done;
    wire [255:0] mm_res;
    modmul_serial u_mul (
        .clk(clk), .wipe(wipe), .start(mul_start),
        .a(ea), .b(eb), .m(em),
        .busy(mm_busy), .done(mm_done), .result(mm_res)
    );

    // ------------------------------------------------ helper signals ------
    wire        k_bit   = rf[I_K][idx];
    wire        e_bit   = invmod ? N_M2[idx2] : P_M2[idx2];
    wire        k_bad   = (k_in == 256'd0) || (k_in >= N);
    wire        d_bad   = (d_in == 256'd0) || (d_in >= N);
    wire [255:0] s_cur  = rf[I_S];
    wire [255:0] s_fin  = (LOW_S != 0 && s_cur > HALF_N) ? rf[I_T5] : s_cur;

    assign r_out  = fail ? 256'd0 : rf[I_R];
    assign s_out  = fail ? 256'd0 : rf[I_S];
    assign px_out = rf[I_XA];
    assign py_out = rf[I_YA];

    // ----------------------------------------------------- sequencer ------
    always @(posedge clk) begin
        done <= 1'b0;
        if (wipe) begin
            for (ii = 0; ii < 32; ii = ii + 1) rf[ii] <= 256'd0;
            st <= ST_IDLE; busy <= 1'b0; fail <= 1'b0; pc <= 9'd0;
            idx <= 8'd0; idx2 <= 8'd0; invmod <= 1'b0; mp <= 1'b0;
        end else if (!rst_n) begin
            st <= ST_IDLE; busy <= 1'b0; fail <= 1'b0; pc <= 9'd0;
        end else begin
            case (st)
            // -------------------------------------------------------------
            ST_IDLE: if (start) begin
                rf[I_K]    <= k_in;
                rf[I_D]    <= d_in;
                rf[I_H]    <= z_in;
                rf[I_X0]   <= 256'd0;  rf[I_Y0] <= 256'd1;  rf[I_Z0] <= 256'd0;  // R0 = O
                rf[I_X1]   <= use_base ? bx_in : GX;  rf[I_Y1] <= use_base ? by_in : GY;  rf[I_Z1] <= 256'd1;  // R1 = G or given point
                rf[I_B3]   <= 256'd21; // 3*b
                rf[I_ONE]  <= 256'd1;
                rf[I_ZERO] <= 256'd0;
                fail       <= 1'b0;
                busy       <= 1'b1;
                mp         <= mode_pub;
                idx        <= 8'd255;
                if (k_bad || d_bad) begin
                    fail <= 1'b1;
                    st   <= ST_FINISH;
                end else begin
                    st   <= ST_SWAP1;
                end
            end

            // ---- Montgomery ladder: cswap, add, double, move, cswap -------
            ST_SWAP1: begin
                if (k_bit) begin
                    rf[I_X0] <= rf[I_X1]; rf[I_X1] <= rf[I_X0];
                    rf[I_Y0] <= rf[I_Y1]; rf[I_Y1] <= rf[I_Y0];
                    rf[I_Z0] <= rf[I_Z1]; rf[I_Z1] <= rf[I_Z0];
                end
                pc  <= A_PT_ADD;
                ret <= ST_CALL_DBL;
                st  <= ST_FETCH;
            end
            ST_CALL_DBL: begin
                pc  <= A_PT_DBL;
                ret <= ST_CALL_MOVE;
                st  <= ST_FETCH;
            end
            ST_CALL_MOVE: begin
                pc  <= A_MOVE;
                ret <= ST_SWAP2;
                st  <= ST_FETCH;
            end
            ST_SWAP2: begin
                if (k_bit) begin
                    rf[I_X0] <= rf[I_X1]; rf[I_X1] <= rf[I_X0];
                    rf[I_Y0] <= rf[I_Y1]; rf[I_Y1] <= rf[I_Y0];
                    rf[I_Z0] <= rf[I_Z1]; rf[I_Z1] <= rf[I_Z0];
                end
                if (idx == 8'd0) begin
                    // ladder finished: start Z0^-1 mod p
                    invmod <= 1'b0;
                    idx2   <= 8'd255;
                    pc     <= A_PREP_INVZ;
                    ret    <= ST_INV_STEP;
                    st     <= ST_FETCH;
                end else begin
                    idx <= idx - 8'd1;
                    st  <= ST_SWAP1;
                end
            end

            // ---- Fermat inversion: square, multiply, select ---------------
            ST_INV_STEP: begin
                pc  <= invmod ? A_INVN_STEP : A_INVP_STEP;
                ret <= ST_INV_SEL;
                st  <= ST_FETCH;
            end
            ST_INV_SEL: begin
                if (e_bit) rf[I_ACC] <= rf[I_TMP];
                if (idx2 == 8'd0) begin
                    if (!invmod) begin       // finished 1/Z: affine x, r = x mod n
                        pc  <= A_AFFINE;
                        ret <= ST_CHECK_R;
                    end else begin           // finished 1/k: compute s
                        pc  <= A_SIGN;
                        ret <= ST_LOWS;
                    end
                    st <= ST_FETCH;
                end else begin
                    idx2 <= idx2 - 8'd1;
                    st   <= ST_INV_STEP;
                end
            end
            ST_CHECK_R: begin
                if (mp) begin                // public-key mode: also need affine y
                    pc  <= A_AFFINE_Y;
                    ret <= ST_FINISH;
                    st  <= ST_FETCH;
                end else if (rf[I_R] == 256'd0) begin
                    fail <= 1'b1;
                    st   <= ST_FINISH;
                end else begin
                    invmod <= 1'b1;
                    idx2   <= 8'd255;
                    pc     <= A_PREP_INVK;
                    ret    <= ST_INV_STEP;
                    st     <= ST_FETCH;
                end
            end
            ST_LOWS: begin
                rf[I_S] <= s_fin;
                if (s_fin == 256'd0) fail <= 1'b1;
                st <= ST_FINISH;
            end
            ST_FINISH: begin
                busy <= 1'b0;
                done <= 1'b1;
                st   <= ST_IDLE;
            end

            // ---- micro-op executor ---------------------------------------
            ST_FETCH: begin
                case (op)
                    2'd0: st <= ret;                             // END
                    2'd1: begin dst_r <= rd; st <= ST_WAITMUL; end // MUL (started this cycle)
                    2'd2: begin rf[rd] <= alu_add; pc <= pc + 9'd1; end
                    2'd3: begin rf[rd] <= alu_sub; pc <= pc + 9'd1; end
                endcase
            end
            ST_WAITMUL: if (mm_done) begin
                rf[dst_r] <= mm_res;
                pc <= pc + 9'd1;
                st <= ST_FETCH;
            end

            default: st <= ST_IDLE;
            endcase
        end
    end

    initial begin
        st = ST_IDLE; busy = 1'b0; done = 1'b0; fail = 1'b0; pc = 9'd0;
        ret = ST_IDLE; idx = 8'd0; idx2 = 8'd0; invmod = 1'b0; dst_r = 5'd0; mp = 1'b0;
    end
endmodule
