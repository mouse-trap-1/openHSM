`timescale 1ns/1ps
//------------------------------------------------------------------------------
// aes_gcm32 : AES-256-GCM for one fixed record shape
//               96-bit IV, 16-byte AAD, 32-byte payload, 16-byte tag
//
//   Used to wrap/unwrap a 32-byte wallet private key under the cluster KEK
//   (AAD = wallet id).  On decrypt, if the tag does not verify, `dout` is
//   forced to zero and `auth_ok` is 0 -- unauthenticated plaintext is never
//   presented.
//
//   Hold `key`, `iv`, `aad`, `din`, `tag_in` stable from `start` until `done`.
//   `done` pulses once; `dout`, `tag_out`, `auth_ok` stay valid until the
//   next start (or wipe).  `dec` = 0 encrypt, 1 decrypt+verify.
//   ~52 (key) + 4*15 (AES) + 4*128 (GHASH) + overhead ~= 650 cycles.
//------------------------------------------------------------------------------
module aes_gcm32 (
    input  wire         clk,
    input  wire         wipe,
    input  wire         start,
    input  wire         dec,
    input  wire [255:0] key,
    input  wire [95:0]  iv,
    input  wire [127:0] aad,
    input  wire [255:0] din,
    input  wire [127:0] tag_in,
    output reg          busy,
    output reg          done,
    output reg  [255:0] dout,
    output reg  [127:0] tag_out,
    output reg          auth_ok
);
    localparam [3:0] ST_IDLE = 4'd0, ST_KEY = 4'd1, ST_KEYW = 4'd2, ST_AREQ = 4'd3,
                     ST_AWAIT = 4'd4, ST_GREQ = 4'd5, ST_GWAIT = 4'd6, ST_FIN = 4'd7;

    reg [3:0] st;
    reg [1:0] jstep, gstep;
    reg       dec_r;
    reg [95:0]  iv_r;
    reg [127:0] aad_r, tag_in_r;
    reg [255:0] din_r;

    reg [127:0] hkey, ekj0, ks0, ks1, acc;

    // AES instance
    reg          a_key_load, a_blk_start;
    reg  [127:0] a_blk_in;
    wire         a_key_ready, a_blk_done, a_busy;
    wire [127:0] a_blk_out;
    aes256_core u_aes (.clk(clk), .wipe(wipe), .key_load(a_key_load), .key(key),
                       .key_ready(a_key_ready), .blk_start(a_blk_start), .blk_in(a_blk_in),
                       .blk_done(a_blk_done), .blk_out(a_blk_out), .busy(a_busy));

    // GF(2^128) multiplier
    reg          g_start;
    reg  [127:0] g_x;
    wire         g_busy, g_done;
    wire [127:0] g_z;
    gf128_mul u_gf (.clk(clk), .wipe(wipe), .start(g_start), .x(g_x), .h(hkey),
                    .busy(g_busy), .done(g_done), .z(g_z));

    // ciphertext blocks (computed from keystream on encrypt, taken from input on decrypt)
    wire [127:0] c0 = dec_r ? din_r[255:128] : (din_r[255:128] ^ ks0);
    wire [127:0] c1 = dec_r ? din_r[127:0]   : (din_r[127:0]   ^ ks1);
    wire [127:0] lenblk = {64'd128, 64'd256};      // bit lengths of AAD and payload

    reg [127:0] gblk;
    always @(*) begin
        case (gstep)
            2'd0: gblk = aad_r;
            2'd1: gblk = c0;
            2'd2: gblk = c1;
            default: gblk = lenblk;
        endcase
    end

    reg [127:0] aes_in;
    always @(*) begin
        case (jstep)
            2'd0: aes_in = 128'd0;
            2'd1: aes_in = {iv_r, 32'd1};
            2'd2: aes_in = {iv_r, 32'd2};
            default: aes_in = {iv_r, 32'd3};
        endcase
    end

    wire [127:0] tag_calc = acc ^ ekj0;
    wire         tag_eq   = (tag_calc == tag_in_r);

    initial begin
        st = ST_IDLE; busy = 1'b0; done = 1'b0; dout = 256'd0; tag_out = 128'd0; auth_ok = 1'b0;
        jstep = 2'd0; gstep = 2'd0; dec_r = 1'b0; iv_r = 96'd0; aad_r = 128'd0; tag_in_r = 128'd0;
        din_r = 256'd0; hkey = 128'd0; ekj0 = 128'd0; ks0 = 128'd0; ks1 = 128'd0; acc = 128'd0;
        a_key_load = 1'b0; a_blk_start = 1'b0; a_blk_in = 128'd0; g_start = 1'b0; g_x = 128'd0;
    end

    always @(posedge clk) begin
        done        <= 1'b0;
        a_key_load  <= 1'b0;
        a_blk_start <= 1'b0;
        g_start     <= 1'b0;
        if (wipe) begin
            st <= ST_IDLE; busy <= 1'b0; dout <= 256'd0; tag_out <= 128'd0; auth_ok <= 1'b0;
            iv_r <= 96'd0; aad_r <= 128'd0; tag_in_r <= 128'd0; din_r <= 256'd0;
            hkey <= 128'd0; ekj0 <= 128'd0; ks0 <= 128'd0; ks1 <= 128'd0; acc <= 128'd0;
            a_blk_in <= 128'd0; g_x <= 128'd0; jstep <= 2'd0; gstep <= 2'd0;
        end else begin
            case (st)
                ST_IDLE: if (start) begin
                    dec_r <= dec; iv_r <= iv; aad_r <= aad; din_r <= din; tag_in_r <= tag_in;
                    acc <= 128'd0; jstep <= 2'd0; gstep <= 2'd0;
                    dout <= 256'd0; tag_out <= 128'd0; auth_ok <= 1'b0;
                    a_key_load <= 1'b1; busy <= 1'b1; st <= ST_KEY;
                end
                ST_KEY:  st <= ST_KEYW;                      // key_load is high this cycle
                ST_KEYW: if (a_key_ready) st <= ST_AREQ;
                ST_AREQ: begin
                    a_blk_in <= aes_in; a_blk_start <= 1'b1; st <= ST_AWAIT;
                end
                ST_AWAIT: if (a_blk_done) begin
                    case (jstep)
                        2'd0: hkey <= a_blk_out;
                        2'd1: ekj0 <= a_blk_out;
                        2'd2: ks0  <= a_blk_out;
                        default: ks1 <= a_blk_out;
                    endcase
                    if (jstep == 2'd3) st <= ST_GREQ;
                    else begin jstep <= jstep + 2'd1; st <= ST_AREQ; end
                end
                ST_GREQ: begin
                    g_x <= acc ^ gblk; g_start <= 1'b1; st <= ST_GWAIT;
                end
                ST_GWAIT: if (g_done) begin
                    acc <= g_z;
                    if (gstep == 2'd3) st <= ST_FIN;
                    else begin gstep <= gstep + 2'd1; st <= ST_GREQ; end
                end
                ST_FIN: begin
                    tag_out <= tag_calc;
                    auth_ok <= dec_r ? tag_eq : 1'b1;
                    if (dec_r)
                        dout <= tag_eq ? {din_r[255:128] ^ ks0, din_r[127:0] ^ ks1} : 256'd0;
                    else
                        dout <= {c0, c1};
                    // scrub secrets that are no longer needed
                    hkey <= 128'd0; ekj0 <= 128'd0; ks0 <= 128'd0; ks1 <= 128'd0; acc <= 128'd0;
                    busy <= 1'b0; done <= 1'b1; st <= ST_IDLE;
                end
                default: st <= ST_IDLE;
            endcase
        end
    end
endmodule
