`timescale 1ns/1ps
//------------------------------------------------------------------------------
// aes256_core : AES-256 block encryption (no decryption needed for GCM)
//
//   key_load  : pulse with `key` -> expands the key schedule (~52 cycles),
//               `key_ready` rises when done
//   blk_start : pulse with `blk_in` -> 15 cycles later `blk_done` pulses and
//               `blk_out` holds the encrypted block
//   byte 0 of a block / key is the most significant byte
//   `wipe` clears the key schedule
//------------------------------------------------------------------------------
module aes256_core (
    input  wire         clk,
    input  wire         wipe,
    input  wire         key_load,
    input  wire [255:0] key,
    output reg          key_ready,
    input  wire         blk_start,
    input  wire [127:0] blk_in,
    output reg          blk_done,
    output reg  [127:0] blk_out,
    output reg          busy
);
    `include "aes_sbox.vh"

    reg [31:0] w [0:59];
    reg [5:0]  ki;
    reg        kx;                      // key expansion running
    reg [127:0] s;
    reg [3:0]  rnd;
    reg        enc;
    integer    n;

    function [7:0] xtime(input [7:0] a);
        xtime = {a[6:0], 1'b0} ^ (a[7] ? 8'h1b : 8'h00);
    endfunction

    function [31:0] subword(input [31:0] x);
        subword = {sbox(x[31:24]), sbox(x[23:16]), sbox(x[15:8]), sbox(x[7:0])};
    endfunction

    function [7:0] rcon(input [2:0] i);
        case (i)
            3'd1: rcon = 8'h01; 3'd2: rcon = 8'h02; 3'd3: rcon = 8'h04; 3'd4: rcon = 8'h08;
            3'd5: rcon = 8'h10; 3'd6: rcon = 8'h20; 3'd7: rcon = 8'h40; default: rcon = 8'h00;
        endcase
    endfunction

    // SubBytes + ShiftRows (state is column-major, byte 0 = MSB)
    function [127:0] sub_shift(input [127:0] st);
        integer r, c;
        reg [7:0] t;
        begin
            sub_shift = 128'd0;
            for (c = 0; c < 4; c = c + 1)
                for (r = 0; r < 4; r = r + 1) begin
                    t = st[127 - 8*(r + 4*((c + r) % 4)) -: 8];
                    sub_shift[127 - 8*(r + 4*c) -: 8] = sbox(t);
                end
        end
    endfunction

    function [127:0] mix_cols(input [127:0] st);
        integer c;
        reg [7:0] a0, a1, a2, a3;
        begin
            mix_cols = 128'd0;
            for (c = 0; c < 4; c = c + 1) begin
                a0 = st[127 - 32*c      -: 8];
                a1 = st[127 - 32*c - 8  -: 8];
                a2 = st[127 - 32*c - 16 -: 8];
                a3 = st[127 - 32*c - 24 -: 8];
                mix_cols[127 - 32*c      -: 8] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3;
                mix_cols[127 - 32*c - 8  -: 8] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3;
                mix_cols[127 - 32*c - 16 -: 8] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3);
                mix_cols[127 - 32*c - 24 -: 8] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3);
            end
        end
    endfunction

    wire [127:0] rk_cur = {w[{rnd, 2'b00}], w[{rnd, 2'b01}], w[{rnd, 2'b10}], w[{rnd, 2'b11}]};
    wire [127:0] after_sub = sub_shift(s);
    wire [127:0] next_mid  = mix_cols(after_sub) ^ rk_cur;
    wire [127:0] next_last = after_sub ^ rk_cur;

    reg [31:0] t;

    initial begin
        key_ready = 1'b0; blk_done = 1'b0; blk_out = 128'd0; busy = 1'b0;
        ki = 6'd0; kx = 1'b0; s = 128'd0; rnd = 4'd0; enc = 1'b0;
        for (n = 0; n < 60; n = n + 1) w[n] = 32'd0;
    end

    always @(posedge clk) begin
        blk_done <= 1'b0;
        if (wipe) begin
            for (n = 0; n < 60; n = n + 1) w[n] <= 32'd0;
            key_ready <= 1'b0; busy <= 1'b0; kx <= 1'b0; enc <= 1'b0;
            s <= 128'd0; blk_out <= 128'd0;
        end else if (key_load && !busy) begin
            w[0] <= key[255:224]; w[1] <= key[223:192]; w[2] <= key[191:160]; w[3] <= key[159:128];
            w[4] <= key[127:96];  w[5] <= key[95:64];   w[6] <= key[63:32];   w[7] <= key[31:0];
            ki <= 6'd8; kx <= 1'b1; key_ready <= 1'b0; busy <= 1'b1;
        end else if (kx) begin
            t = w[ki - 6'd1];
            if (ki[2:0] == 3'd0)      t = subword({t[23:0], t[31:24]}) ^ {rcon(ki[5:3]), 24'd0};
            else if (ki[2:0] == 3'd4) t = subword(t);
            w[ki] <= w[ki - 6'd8] ^ t;
            ki <= ki + 6'd1;
            if (ki == 6'd59) begin kx <= 1'b0; key_ready <= 1'b1; busy <= 1'b0; end
        end else if (blk_start && key_ready && !busy) begin
            s <= blk_in ^ {w[0], w[1], w[2], w[3]};
            rnd <= 4'd1; enc <= 1'b1; busy <= 1'b1;
        end else if (enc) begin
            if (rnd == 4'd14) begin
                blk_out <= next_last; blk_done <= 1'b1; enc <= 1'b0; busy <= 1'b0;
            end else begin
                s <= next_mid; rnd <= rnd + 4'd1;
            end
        end
    end
endmodule
