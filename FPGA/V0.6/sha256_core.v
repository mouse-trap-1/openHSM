`timescale 1ns/1ps
//------------------------------------------------------------------------------
// sha256_core : iterative SHA-256 compression function, one round per clock
//
//   Process one 512-bit block per `start` pulse (66 cycles).
//   first=1 : chain from the SHA-256 IV (first block of a message)
//   first=0 : chain from the previous digest
//   `digest` holds the running hash value and is valid after `done`.
//   `wipe` synchronously clears all state.
//------------------------------------------------------------------------------
module sha256_core (
    input  wire         clk,
    input  wire         wipe,
    input  wire         start,
    input  wire         first,
    input  wire [511:0] block,
    output reg          busy,
    output reg          done,
    output wire [255:0] digest
);
    localparam [255:0] IV = {32'h6a09e667, 32'hbb67ae85, 32'h3c6ef372, 32'ha54ff53a,
                             32'h510e527f, 32'h9b05688c, 32'h1f83d9ab, 32'h5be0cd19};

    localparam [2047:0] KROM = {
        32'h428a2f98, 32'h71374491, 32'hb5c0fbcf, 32'he9b5dba5, 32'h3956c25b, 32'h59f111f1, 32'h923f82a4, 32'hab1c5ed5,
        32'hd807aa98, 32'h12835b01, 32'h243185be, 32'h550c7dc3, 32'h72be5d74, 32'h80deb1fe, 32'h9bdc06a7, 32'hc19bf174,
        32'he49b69c1, 32'hefbe4786, 32'h0fc19dc6, 32'h240ca1cc, 32'h2de92c6f, 32'h4a7484aa, 32'h5cb0a9dc, 32'h76f988da,
        32'h983e5152, 32'ha831c66d, 32'hb00327c8, 32'hbf597fc7, 32'hc6e00bf3, 32'hd5a79147, 32'h06ca6351, 32'h14292967,
        32'h27b70a85, 32'h2e1b2138, 32'h4d2c6dfc, 32'h53380d13, 32'h650a7354, 32'h766a0abb, 32'h81c2c92e, 32'h92722c85,
        32'ha2bfe8a1, 32'ha81a664b, 32'hc24b8b70, 32'hc76c51a3, 32'hd192e819, 32'hd6990624, 32'hf40e3585, 32'h106aa070,
        32'h19a4c116, 32'h1e376c08, 32'h2748774c, 32'h34b0bcb5, 32'h391c0cb3, 32'h4ed8aa4a, 32'h5b9cca4f, 32'h682e6ff3,
        32'h748f82ee, 32'h78a5636f, 32'h84c87814, 32'h8cc70208, 32'h90befffa, 32'ha4506ceb, 32'hbef9a3f7, 32'hc67178f2
    };

    reg [255:0] H;
    reg [31:0]  a, b, c, d, e, f, g, h;
    reg [511:0] w;          // sliding window W[t] .. W[t+15]
    reg [6:0]   t;

    assign digest = H;

    function [31:0] rotr(input [31:0] x, input integer n);
        rotr = (x >> n) | (x << (32 - n));
    endfunction

    wire [31:0] w0  = w[511:480];
    wire [31:0] w1  = w[479:448];
    wire [31:0] w9  = w[223:192];
    wire [31:0] w14 = w[63:32];

    wire [31:0] sig0 = rotr(w1, 7)  ^ rotr(w1, 18)  ^ (w1  >> 3);
    wire [31:0] sig1 = rotr(w14, 17) ^ rotr(w14, 19) ^ (w14 >> 10);
    wire [31:0] wnew = sig1 + w9 + sig0 + w0;

    wire [31:0] S1  = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    wire [31:0] S0  = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    wire [31:0] ch  = (e & f) ^ (~e & g);
    wire [31:0] maj = (a & b) ^ (a & c) ^ (b & c);
    wire [31:0] kt  = KROM[2047 - 32*t[5:0] -: 32];
    wire [31:0] T1  = h + S1 + ch + kt + w0;
    wire [31:0] T2  = S0 + maj;
    wire [31:0] na  = T1 + T2;
    wire [31:0] ne  = d + T1;

    initial begin
        busy = 1'b0; done = 1'b0; H = 256'd0; t = 7'd0;
    end

    always @(posedge clk) begin
        done <= 1'b0;
        if (wipe) begin
            H <= 256'd0; w <= 512'd0; busy <= 1'b0; t <= 7'd0;
            a <= 32'd0; b <= 32'd0; c <= 32'd0; d <= 32'd0;
            e <= 32'd0; f <= 32'd0; g <= 32'd0; h <= 32'd0;
        end else if (!busy) begin
            if (start) begin
                if (first) begin
                    H <= IV;
                    {a, b, c, d, e, f, g, h} <= IV;
                end else begin
                    {a, b, c, d, e, f, g, h} <= H;
                end
                w    <= block;
                t    <= 7'd0;
                busy <= 1'b1;
            end
        end else begin
            w <= {w[479:0], wnew};
            h <= g; g <= f; f <= e; e <= ne;
            d <= c; c <= b; b <= a; a <= na;
            t <= t + 7'd1;
            if (t == 7'd63) begin
                H <= {H[255:224] + na, H[223:192] + a, H[191:160] + b, H[159:128] + c,
                      H[127:96]  + ne, H[95:64]   + e, H[63:32]   + f, H[31:0]    + g};
                busy <= 1'b0;
                done <= 1'b1;
            end
        end
    end
endmodule
