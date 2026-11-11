`timescale 1ns/1ps
//------------------------------------------------------------------------------
// modmul_serial : interleaved shift-and-add modular multiplier, 1 bit / clock
//
//   result = (a * b) mod m          requires  a < m  and  b < m,  m < 2^256
//
// Works for ANY modulus (used for both the field prime p and the group order n),
// so a single instance serves the whole signer.  Latency is always exactly
// 256 cycles after `start`, independent of the operand values (constant time).
//
// Each iteration:  acc <- (2*acc + a_bit*b) mod m
//   acc < m  =>  2*acc + b <= 3m-3,  so at most two conditional subtractions.
//------------------------------------------------------------------------------
module modmul_serial (
    input  wire         clk,
    input  wire         wipe,           // synchronous clear of all operand/result state
    input  wire         start,          // pulse; ignored while busy
    input  wire [255:0] a,
    input  wire [255:0] b,
    input  wire [255:0] m,
    output reg          busy,
    output reg          done,           // 1-cycle pulse, result valid
    output reg  [255:0] result
);
    reg [255:0] a_sh;       // multiplier, consumed MSB first
    reg [255:0] b_r;
    reg [255:0] m_r;
    reg [255:0] acc;
    reg [7:0]   cnt;

    // t = 2*acc + (a_bit ? b : 0)          (max 3m-3 < 2^258)
    wire [258:0] t    = {2'b00, acc, 1'b0} + (a_sh[255] ? {3'b000, b_r} : 259'd0);
    // trial subtractions with a borrow bit on top (bit 259 set => negative)
    wire [259:0] t_m  = {1'b0, t} - {4'b0000, m_r};
    wire [259:0] t_2m = {1'b0, t} - {3'b000, m_r, 1'b0};
    wire         ge_m  = ~t_m[259];
    wire         ge_2m = ~t_2m[259];
    wire [255:0] nxt   = ge_2m ? t_2m[255:0] :
                         ge_m  ? t_m[255:0]  : t[255:0];

    initial begin
        busy = 1'b0; done = 1'b0; result = 256'd0;
    end

    always @(posedge clk) begin
        done <= 1'b0;
        if (wipe) begin
            a_sh <= 256'd0; b_r <= 256'd0; m_r <= 256'd0; acc <= 256'd0;
            result <= 256'd0; cnt <= 8'd0; busy <= 1'b0;
        end else if (!busy) begin
            if (start) begin
                a_sh <= a;
                b_r  <= b;
                m_r  <= m;
                acc  <= 256'd0;
                cnt  <= 8'd0;
                busy <= 1'b1;
            end
        end else begin
            acc  <= nxt;
            a_sh <= {a_sh[254:0], 1'b0};
            cnt  <= cnt + 8'd1;
            if (cnt == 8'd255) begin
                result <= nxt;
                done   <= 1'b1;
                busy   <= 1'b0;
            end
        end
    end
endmodule
