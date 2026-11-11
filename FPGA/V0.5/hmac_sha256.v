`timescale 1ns/1ps
//------------------------------------------------------------------------------
// hmac_sha256 : HMAC-SHA-256 with a 32-byte key and a message of 0..183 bytes
//
//   msg is left-justified: byte 0 = msg[1535:1528].  Bytes at or beyond msg_len
//   are ignored.  `mac` is valid when `done` pulses.
//------------------------------------------------------------------------------
module hmac_sha256 (
    input  wire          clk,
    input  wire          wipe,
    input  wire          start,
    input  wire [255:0]  key,
    input  wire [1535:0] msg,
    input  wire [7:0]    msg_len,
    output reg           busy,
    output reg           done,
    output reg  [255:0]  mac
);
    reg [255:0]  key_r;
    reg [1535:0] msg_r;
    reg [7:0]    len_r;
    reg [255:0]  inner;

    // ---- padded message area (message || 0x80 || zeros || 64-bit bit length)
    reg [1535:0] pa;
    reg [63:0]   bitlen;
    integer i;
    always @(*) begin
        pa = 1536'd0;
        for (i = 0; i < 192; i = i + 1) begin
            if (i < len_r)       pa[1535 - 8*i -: 8] = msg_r[1535 - 8*i -: 8];
            else if (i == len_r) pa[1535 - 8*i -: 8] = 8'h80;
        end
        bitlen = ({56'd0, len_r} + 64'd64) << 3;       // (64 + len) * 8
        if (len_r <= 8'd55)       pa[1535 - 8*56  -: 64] = bitlen;
        else if (len_r <= 8'd119) pa[1535 - 8*120 -: 64] = bitlen;
        else                      pa[1535 - 8*184 -: 64] = bitlen;
    end
    wire [1:0] nblk = (len_r <= 8'd55) ? 2'd1 : (len_r <= 8'd119) ? 2'd2 : 2'd3;

    wire [511:0] kpad     = {key_r, 256'd0};
    wire [511:0] ipad_blk = kpad ^ {64{8'h36}};
    wire [511:0] opad_blk = kpad ^ {64{8'h5c}};

    // ---- SHA-256 engine
    reg          sha_start, sha_first;
    reg  [511:0] sha_blk;
    wire         sha_busy, sha_done;
    wire [255:0] sha_dig;
    sha256_core u_sha (.clk(clk), .wipe(wipe), .start(sha_start), .first(sha_first),
                       .block(sha_blk), .busy(sha_busy), .done(sha_done), .digest(sha_dig));

    localparam [2:0] S_IDLE = 3'd0, S_IPAD = 3'd1, S_MSG = 3'd2, S_OPAD = 3'd3,
                     S_OUT  = 3'd4, S_FIN  = 3'd5, S_WAIT = 3'd6;
    reg [2:0] st, nxt;
    reg [1:0] mi;

    initial begin
        busy = 1'b0; done = 1'b0; mac = 256'd0; st = S_IDLE; mi = 2'd0;
        sha_start = 1'b0; sha_first = 1'b0; sha_blk = 512'd0; nxt = S_IDLE;
        key_r = 256'd0; msg_r = 1536'd0; len_r = 8'd0; inner = 256'd0;
    end

    always @(posedge clk) begin
        done      <= 1'b0;
        sha_start <= 1'b0;
        if (wipe) begin
            key_r <= 256'd0; msg_r <= 1536'd0; len_r <= 8'd0; inner <= 256'd0;
            mac <= 256'd0; sha_blk <= 512'd0; busy <= 1'b0; st <= S_IDLE;
        end else case (st)
            S_IDLE: if (start) begin
                key_r <= key; msg_r <= msg; len_r <= msg_len;
                busy  <= 1'b1;
                st    <= S_IPAD;
            end
            S_IPAD: begin
                sha_blk <= ipad_blk; sha_first <= 1'b1; sha_start <= 1'b1;
                mi <= 2'd0; nxt <= S_MSG; st <= S_WAIT;
            end
            S_MSG: begin
                sha_blk   <= (mi == 2'd0) ? pa[1535:1024] :
                             (mi == 2'd1) ? pa[1023:512]  : pa[511:0];
                sha_first <= 1'b0; sha_start <= 1'b1;
                mi  <= mi + 2'd1;
                nxt <= (mi + 2'd1 == nblk) ? S_OPAD : S_MSG;
                st  <= S_WAIT;
            end
            S_OPAD: begin
                inner     <= sha_dig;
                sha_blk   <= opad_blk; sha_first <= 1'b1; sha_start <= 1'b1;
                nxt <= S_OUT; st <= S_WAIT;
            end
            S_OUT: begin
                sha_blk   <= {inner, 8'h80, 184'd0, 64'd768};
                sha_first <= 1'b0; sha_start <= 1'b1;
                nxt <= S_FIN; st <= S_WAIT;
            end
            S_FIN: begin
                mac  <= sha_dig;
                done <= 1'b1;
                busy <= 1'b0;
                inner <= 256'd0; key_r <= 256'd0; msg_r <= 1536'd0;
                st   <= S_IDLE;
            end
            S_WAIT: if (sha_done) st <= nxt;
            default: st <= S_IDLE;
        endcase
    end
endmodule
