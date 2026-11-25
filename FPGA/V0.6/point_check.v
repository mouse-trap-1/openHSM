`timescale 1ns/1ps
//------------------------------------------------------------------------------
// point_check : validates an affine secp256k1 point before it is used for ECDH
//               (defends against invalid-curve attacks)
//
//   valid = (x < p) && (y < p) && (y^2 == x^3 + 7  mod p)
//   The point at infinity / (0,0) are rejected.  secp256k1 has cofactor 1, so
//   on-curve implies the point has prime order n.
//   Pulse `start` with x,y stable until `done`.  ~770 cycles.
//------------------------------------------------------------------------------
module point_check (
    input  wire         clk,
    input  wire         wipe,
    input  wire         start,
    input  wire [255:0] x,
    input  wire [255:0] y,
    output reg          busy,
    output reg          done,
    output reg          valid
);
    localparam [255:0] P = 256'hFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    reg [2:0]   st;
    reg [255:0] ma, mb, y2, x2;
    reg         ms;
    wire        mbusy, mdone;
    wire [255:0] mres;
    modmul_serial u_m (.clk(clk), .wipe(wipe), .start(ms), .a(ma), .b(mb), .m(P),
                       .busy(mbusy), .done(mdone), .result(mres));

    wire [256:0] rhs_s = {1'b0, mres} + 257'd7;
    wire [255:0] rhs   = (rhs_s >= {1'b0, P}) ? (rhs_s - {1'b0, P}) : rhs_s[255:0];

    initial begin st = 3'd0; busy = 1'b0; done = 1'b0; valid = 1'b0; ma = 0; mb = 0; y2 = 0; x2 = 0; ms = 1'b0; end

    always @(posedge clk) begin
        done <= 1'b0; ms <= 1'b0;
        if (wipe) begin
            st <= 3'd0; busy <= 1'b0; valid <= 1'b0; ma <= 0; mb <= 0; y2 <= 0; x2 <= 0;
        end else case (st)
            3'd0: if (start) begin
                busy <= 1'b1; valid <= 1'b0;
                if (x >= P || y >= P) begin st <= 3'd6; end
                else begin ma <= y; mb <= y; ms <= 1'b1; st <= 3'd1; end
            end
            3'd1: if (mdone) begin y2 <= mres; ma <= x; mb <= x; ms <= 1'b1; st <= 3'd2; end
            3'd2: if (mdone) begin x2 <= mres; ma <= mres; mb <= x; ms <= 1'b1; st <= 3'd3; end
            3'd3: if (mdone) begin valid <= (y2 == rhs); st <= 3'd6; end
            3'd6: begin busy <= 1'b0; done <= 1'b1; st <= 3'd0; ma <= 0; mb <= 0; y2 <= 0; x2 <= 0; end
            default: st <= 3'd0;
        endcase
    end
endmodule
