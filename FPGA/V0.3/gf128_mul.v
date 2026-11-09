`timescale 1ns/1ps
//------------------------------------------------------------------------------
// gf128_mul : GF(2^128) multiplier for GHASH (NIST SP 800-38D bit order),
//             bit-serial, 128 cycles per product
//------------------------------------------------------------------------------
module gf128_mul (
    input  wire         clk,
    input  wire         wipe,
    input  wire         start,
    input  wire [127:0] x,
    input  wire [127:0] h,
    output reg          busy,
    output reg          done,
    output reg  [127:0] z
);
    reg [127:0] v, xr;
    reg [7:0]   cnt;
    initial begin busy = 1'b0; done = 1'b0; z = 128'd0; v = 128'd0; xr = 128'd0; cnt = 8'd0; end
    always @(posedge clk) begin
        done <= 1'b0;
        if (wipe) begin
            busy <= 1'b0; z <= 128'd0; v <= 128'd0; xr <= 128'd0;
        end else if (!busy) begin
            if (start) begin z <= 128'd0; v <= h; xr <= x; cnt <= 8'd0; busy <= 1'b1; end
        end else begin
            if (xr[127]) z <= z ^ v;
            xr <= {xr[126:0], 1'b0};
            v  <= v[0] ? ({1'b0, v[127:1]} ^ {8'hE1, 120'd0}) : {1'b0, v[127:1]};
            cnt <= cnt + 8'd1;
            if (cnt == 8'd127) begin busy <= 1'b0; done <= 1'b1; end
        end
    end
endmodule
