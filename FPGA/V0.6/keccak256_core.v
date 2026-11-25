`timescale 1ns/1ps
//------------------------------------------------------------------------------
// keccak256_core : Keccak-f[1600] sponge, rate 1088 bits, 256-bit output
//
//   Ethereum's Keccak-256 (original Keccak padding 0x01 ... 0x80, NOT NIST
//   SHA3-256, which pads with 0x06).  Added in V0.6 as a standalone, tested
//   block: the sequencer does not use it yet.  It is the hash core a
//   hash-based (post-quantum) signer will need, and it lets the node hash
//   transactions itself instead of trusting the SoC's digest.  See
//   docs/POST_QUANTUM.md.
//
//   * One round per clock: a block takes 24 cycles after `start`.
//   * The caller pads.  Feed 136-byte blocks; the last block carries the
//     message tail, then 0x01, zeros, and 0x80 OR-ed into byte 135.
//   * Byte order follows the rest of the design (big-endian buses): message
//     byte 0 is block[1087:1080]; digest byte 0 is digest[255:248], so the
//     digest reads as the usual hex string.
//   * init clears the state (start of a new message).  wipe clears
//     everything, at any time, like the other engines.
//------------------------------------------------------------------------------
module keccak256_core (
    input  wire          clk,
    input  wire          wipe,
    input  wire          init,
    input  wire          start,
    input  wire [1087:0] block,
    output reg           busy,
    output reg           done,
    output wire [255:0]  digest
);
    reg [1599:0] A;
    reg [4:0]    rnd;

    // lane i (= x + 5y) of the state, 64 bits, little-endian bytes
    function [63:0] lane(input [1599:0] s, input integer i);
        lane = s[64*i +: 64];
    endfunction

    function [63:0] rotl(input [63:0] v, input integer n);
        rotl = (n == 0) ? v : ((v << n) | (v >> (64 - n)));
    endfunction

    function integer rho(input integer i);     // rotation offset of lane x + 5y
        case (i)
        0: rho = 0;   1: rho = 1;   2: rho = 62;  3: rho = 28;  4: rho = 27;
        5: rho = 36;  6: rho = 44;  7: rho = 6;   8: rho = 55;  9: rho = 20;
        10: rho = 3;  11: rho = 10; 12: rho = 43; 13: rho = 25; 14: rho = 39;
        15: rho = 41; 16: rho = 45; 17: rho = 15; 18: rho = 21; 19: rho = 8;
        20: rho = 18; 21: rho = 2;  22: rho = 61; 23: rho = 56; default: rho = 14;
        endcase
    endfunction

    function [63:0] rc(input [4:0] r);
        case (r)
        5'd0:  rc = 64'h0000000000000001; 5'd1:  rc = 64'h0000000000008082;
        5'd2:  rc = 64'h800000000000808A; 5'd3:  rc = 64'h8000000080008000;
        5'd4:  rc = 64'h000000000000808B; 5'd5:  rc = 64'h0000000080000001;
        5'd6:  rc = 64'h8000000080008081; 5'd7:  rc = 64'h8000000000008009;
        5'd8:  rc = 64'h000000000000008A; 5'd9:  rc = 64'h0000000000000088;
        5'd10: rc = 64'h0000000080008009; 5'd11: rc = 64'h000000008000000A;
        5'd12: rc = 64'h000000008000808B; 5'd13: rc = 64'h800000000000008B;
        5'd14: rc = 64'h8000000000008089; 5'd15: rc = 64'h8000000000008003;
        5'd16: rc = 64'h8000000000008002; 5'd17: rc = 64'h8000000000000080;
        5'd18: rc = 64'h000000000000800A; 5'd19: rc = 64'h800000008000000A;
        5'd20: rc = 64'h8000000080008081; 5'd21: rc = 64'h8000000000008080;
        5'd22: rc = 64'h0000000080000001; default: rc = 64'h8000000080008008;
        endcase
    endfunction

    // one Keccak-f[1600] round: theta, rho, pi, chi, iota
    function [1599:0] round(input [1599:0] s, input [4:0] r);
        reg [63:0] C [0:4];
        reg [63:0] D [0:4];
        reg [63:0] B [0:24];
        reg [63:0] t;
        integer x, y;
        begin
            for (x = 0; x < 5; x = x + 1)
                C[x] = lane(s, x) ^ lane(s, x + 5) ^ lane(s, x + 10) ^ lane(s, x + 15) ^ lane(s, x + 20);
            for (x = 0; x < 5; x = x + 1)
                D[x] = C[(x + 4) % 5] ^ rotl(C[(x + 1) % 5], 1);
            for (y = 0; y < 5; y = y + 1)
                for (x = 0; x < 5; x = x + 1) begin
                    t = lane(s, x + 5*y) ^ D[x];
                    B[y + 5*((2*x + 3*y) % 5)] = rotl(t, rho(x + 5*y));
                end
            for (y = 0; y < 5; y = y + 1)
                for (x = 0; x < 5; x = x + 1)
                    round[64*(x + 5*y) +: 64] = B[x + 5*y] ^ (~B[((x + 1) % 5) + 5*y] & B[((x + 2) % 5) + 5*y]);
            round[63:0] = round[63:0] ^ rc(r);
        end
    endfunction

    // big-endian block bytes -> little-endian lanes of the rate part
    function [1599:0] absorb(input [1599:0] s, input [1087:0] b);
        integer i;
        begin
            absorb = s;
            for (i = 0; i < 136; i = i + 1)
                absorb[8*i +: 8] = s[8*i +: 8] ^ b[1087 - 8*i -: 8];
        end
    endfunction

    genvar g;
    generate
        for (g = 0; g < 32; g = g + 1) begin : g_out
            assign digest[255 - 8*g -: 8] = A[8*g +: 8];
        end
    endgenerate

    initial begin A = 1600'd0; rnd = 5'd0; busy = 1'b0; done = 1'b0; end

    always @(posedge clk) begin
        done <= 1'b0;
        if (wipe) begin
            A <= 1600'd0; rnd <= 5'd0; busy <= 1'b0;
        end else if (busy) begin
            A   <= round(A, rnd);
            rnd <= rnd + 5'd1;
            if (rnd == 5'd23) begin busy <= 1'b0; done <= 1'b1; end
        end else if (start) begin
            A    <= absorb(init ? 1600'd0 : A, block);
            rnd  <= 5'd0;
            busy <= 1'b1;
        end else if (init) begin
            A <= 1600'd0;
        end
    end
endmodule
