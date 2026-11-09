`timescale 1ns/1ps
//------------------------------------------------------------------------------
// trng_ro : ring-oscillator true random number generator with online health tests
//
//   raw bits  : N_RO free-running ring oscillators (different odd lengths) are XORed
//               and sampled by the system clock every SAMPLE_DIV cycles
//   conditioner: von Neumann debiasing (pairs 01 -> 0, 10 -> 1, 00/11 discarded)
//   health    : NIST SP 800-90B style continuous tests on the raw samples
//                 - Repetition Count Test  (RCT_CUTOFF identical samples in a row)
//                 - Adaptive Proportion Test (ones per 1024-sample window outside
//                   [APT_LO, APT_HI])
//               plus a start-up test: no output until one full window has passed.
//               A failure is sticky until reset and blocks all output.
//   output    : 256-bit words, handshake via word_valid / ack
//
// !!  SIM_MODEL = 1 replaces the oscillators with a deterministic xorshift generator
// !!  so simulation can run.  It is NOT random.  Never use it in hardware.
//
// !!  The ring oscillators, SAMPLE_DIV and the health-test cut-offs MUST be
// !!  characterised on the actual silicon (raw-bit entropy, bias, voltage and
// !!  temperature corners) before this is trusted.  The defaults are placeholders.
//
//   In the nonce path this TRNG only supplies *hedging* entropy on top of RFC 6979,
//   so a dead TRNG cannot leak the key by itself.  It is the sole entropy source
//   for key generation, so it must be validated.
//------------------------------------------------------------------------------
module trng_ro #(
    parameter SIM_MODEL  = 0,
    parameter N_RO       = 8,
    parameter SAMPLE_DIV = 32,
    parameter RCT_CUTOFF = 32,
    parameter APT_LO     = 400,
    parameter APT_HI     = 624
) (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         enable,        // accumulate output words only while set
    input  wire         ack,           // pulse: word consumed
    output reg          word_valid,
    output reg  [255:0] word,
    output reg          health_fail
);
    // ------------------------------------------------------------ raw source
    wire raw_async;
    generate
        if (SIM_MODEL == 0) begin : g_ro
            wire [N_RO-1:0] ro;
            genvar gi;
            for (gi = 0; gi < N_RO; gi = gi + 1) begin : r
                localparam LEN = 2*gi + 3;                       // odd number of inverters
                (* keep = "true", dont_touch = "true", allow_combinational_loops = "true" *)
                wire [LEN-1:0] chain;
                assign chain[0] = ~chain[LEN-1];
                genvar j;
                for (j = 1; j < LEN; j = j + 1) begin : inv
                    assign chain[j] = ~chain[j-1];
                end
                assign ro[gi] = chain[LEN-1];
            end
            assign raw_async = ^ro;
        end else begin : g_sim
            reg [63:0] xs = 64'h9E3779B97F4A7C15;
            wire [63:0] x1 = xs ^ (xs << 13);
            wire [63:0] x2 = x1 ^ (x1 >> 7);
            wire [63:0] x3 = x2 ^ (x2 << 17);
            always @(posedge clk) xs <= x3;
            assign raw_async = xs[0] ^ xs[21] ^ xs[42];
        end
    endgenerate

    reg [1:0] rs;
    always @(posedge clk) rs <= {rs[0], raw_async};
    wire raw_bit = rs[1];

    // -------------------------------------------------------------- sampling
    reg [15:0] div;
    wire       smp = (div == SAMPLE_DIV - 1);
    always @(posedge clk) begin
        if (!rst_n || smp) div <= 16'd0; else div <= div + 16'd1;
    end

    // ---------------------------------------------------------- health tests
    reg        last_bit;
    reg [7:0]  rct_cnt;
    reg [10:0] apt_n, apt_ones;
    reg        started;

    // ------------------------------------------------- von Neumann + packing
    reg        have_first, first_bit;
    reg [8:0]  nbits;
    wire       vn_emit = smp && have_first && (first_bit != raw_bit);

    initial begin
        word_valid = 1'b0; word = 256'd0; health_fail = 1'b0; div = 16'd0;
        last_bit = 1'b0; rct_cnt = 8'd0; apt_n = 11'd0; apt_ones = 11'd0; started = 1'b0;
        have_first = 1'b0; first_bit = 1'b0; nbits = 9'd0; rs = 2'b00;
    end

    always @(posedge clk) begin
        if (!rst_n) begin
            word_valid <= 1'b0; word <= 256'd0; health_fail <= 1'b0;
            rct_cnt <= 8'd0; apt_n <= 11'd0; apt_ones <= 11'd0; started <= 1'b0;
            have_first <= 1'b0; nbits <= 9'd0;
        end else begin
            if (ack) begin
                word_valid <= 1'b0; word <= 256'd0; nbits <= 9'd0;
            end
            if (smp) begin
                // ---- Repetition Count Test
                last_bit <= raw_bit;
                if (raw_bit == last_bit) begin
                    rct_cnt <= rct_cnt + 8'd1;
                    if (rct_cnt + 8'd1 >= RCT_CUTOFF) health_fail <= 1'b1;
                end else rct_cnt <= 8'd1;
                // ---- Adaptive Proportion Test (1024-sample windows)
                if (apt_n == 11'd1023) begin
                    if ((apt_ones + raw_bit) < APT_LO || (apt_ones + raw_bit) > APT_HI)
                        health_fail <= 1'b1;
                    else
                        started <= 1'b1;
                    apt_n <= 11'd0; apt_ones <= 11'd0;
                end else begin
                    apt_n    <= apt_n + 11'd1;
                    apt_ones <= apt_ones + raw_bit;
                end
                // ---- von Neumann pairing
                if (!have_first) begin first_bit <= raw_bit; have_first <= 1'b1; end
                else have_first <= 1'b0;
            end
            // ---- collect debiased bits into the output word
            if (vn_emit && started && enable && !health_fail && !word_valid && !ack) begin
                word  <= {word[254:0], first_bit};
                nbits <= nbits + 9'd1;
                if (nbits == 9'd255) word_valid <= 1'b1;
            end
            // a failure invalidates anything pending
            if (health_fail) begin word_valid <= 1'b0; end
        end
    end
endmodule
