`timescale 1ns/1ps
//------------------------------------------------------------------------------
// rfc6979_nonce : deterministic (optionally hedged) ECDSA nonce, RFC 6979
//                 with HMAC-SHA-256, for secp256k1 (qlen = hlen = 256)
//
//   k = HMAC-DRBG(x, h1 mod n [, extra])
//
//   * use_extra = 1 mixes 32 bytes of fresh entropy into the DRBG seed, as in
//     libsecp256k1 ("hedged" nonce).  The nonce then stays secret and unique
//     even if either the TRNG or the message hash is weak.
//   * use_extra = 0 gives pure RFC 6979, which is safe even if the TRNG is dead.
//   * Uses an external HMAC engine (shared with the key generator).
//------------------------------------------------------------------------------
module rfc6979_nonce (
    input  wire          clk,
    input  wire          wipe,
    input  wire          start,
    input  wire [255:0]  x,            // private key
    input  wire [255:0]  h1,           // message digest
    input  wire [255:0]  extra,        // 32 bytes of fresh entropy
    input  wire          use_extra,
    output reg           busy,
    output reg           done,         // 1-cycle pulse
    output reg  [255:0]  k,
    // HMAC engine master port
    output reg           hm_start,
    output reg  [255:0]  hm_key,
    output reg  [1535:0] hm_msg,
    output reg  [7:0]    hm_len,
    input  wire          hm_done,
    input  wire [255:0]  hm_mac
);
    localparam [255:0] N = 256'hFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    reg [255:0] K, V, xr, hr, er;
    reg         ue, waiting;
    reg [2:0]   step;

    initial begin
        busy = 1'b0; done = 1'b0; k = 256'd0; hm_start = 1'b0; hm_key = 256'd0;
        hm_msg = 1536'd0; hm_len = 8'd0; K = 256'd0; V = 256'd0; xr = 256'd0;
        hr = 256'd0; er = 256'd0; ue = 1'b0; waiting = 1'b0; step = 3'd0;
    end

    always @(posedge clk) begin
        done     <= 1'b0;
        hm_start <= 1'b0;
        if (wipe) begin
            K <= 256'd0; V <= 256'd0; xr <= 256'd0; hr <= 256'd0; er <= 256'd0;
            k <= 256'd0; hm_key <= 256'd0; hm_msg <= 1536'd0;
            busy <= 1'b0; waiting <= 1'b0;
        end else if (!busy) begin
            if (start) begin
                K  <= 256'd0;
                V  <= {32{8'h01}};
                xr <= x;
                hr <= (h1 >= N) ? (h1 - N) : h1;      // bits2octets: h1 mod n
                er <= extra;
                ue <= use_extra;
                step <= 3'd0; waiting <= 1'b0; busy <= 1'b1;
            end
        end else if (!waiting) begin
            hm_key <= K;
            case (step)
                3'd0: begin hm_msg <= {V, 8'h00, xr, hr, er, 504'd0}; hm_len <= ue ? 8'd129 : 8'd97; end
                3'd2: begin hm_msg <= {V, 8'h01, xr, hr, er, 504'd0}; hm_len <= ue ? 8'd129 : 8'd97; end
                3'd5: begin hm_msg <= {V, 8'h00, 1272'd0};            hm_len <= 8'd33; end
                default: begin hm_msg <= {V, 1280'd0};                hm_len <= 8'd32; end
            endcase
            hm_start <= 1'b1;
            waiting  <= 1'b1;
        end else if (hm_done) begin
            waiting <= 1'b0;
            case (step)
                3'd0: begin K <= hm_mac; step <= 3'd1; end
                3'd1: begin V <= hm_mac; step <= 3'd2; end
                3'd2: begin K <= hm_mac; step <= 3'd3; end
                3'd3: begin V <= hm_mac; step <= 3'd4; end
                3'd4: begin
                    V <= hm_mac;
                    if (hm_mac != 256'd0 && hm_mac < N) begin
                        k <= hm_mac; done <= 1'b1; busy <= 1'b0;
                        K <= 256'd0; V <= 256'd0; xr <= 256'd0; hr <= 256'd0; er <= 256'd0;
                    end else step <= 3'd5;
                end
                3'd5: begin K <= hm_mac; step <= 3'd6; end
                3'd6: begin V <= hm_mac; step <= 3'd4; end
                default: step <= 3'd0;
            endcase
        end
    end
endmodule
