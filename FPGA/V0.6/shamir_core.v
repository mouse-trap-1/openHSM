`timescale 1ns/1ps
//------------------------------------------------------------------------------
// shamir_core : (m, n) Shamir secret sharing of a 256-bit value, byte-wise over
//               GF(2^8) (AES polynomial 0x11B), 32 independent byte lanes
//
//   SPLIT   : load m-1 random 256-bit coefficient words (coef_ld), then for each
//             share point x (1..255) pulse ev_go -> ev_y = f(x), f(0) = secret.
//             Horner evaluation, m cycles.
//   COMBINE : load shares with sh_ld (rejects x = 0 and repeated x), then pulse
//             cb_go -> Lagrange interpolation at 0 over all loaded shares.
//             Plain Shamir has no error detection: the caller must check the result
//             (the top level compares a KEK fingerprint).
//   Everything is volatile.  `tamper` is ASYNCHRONOUS and clears every register.
//------------------------------------------------------------------------------
module shamir_core (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         tamper,
    input  wire         wipe,
    // split
    input  wire         coef_ld,
    input  wire [2:0]   coef_idx,       // 1..7 (coefficient of x^idx)
    input  wire [255:0] coef_d,
    input  wire         ev_go,
    input  wire [7:0]   ev_x,
    input  wire [3:0]   ev_m,           // threshold m (2..8)
    input  wire [255:0] secret_in,
    output reg          ev_done,
    output reg  [255:0] ev_y,
    // combine
    input  wire         sh_ld,
    input  wire [7:0]   sh_x,
    input  wire [255:0] sh_y,
    output reg  [3:0]   sh_cnt,
    output reg          sh_rej,         // pulse: share refused (x = 0, repeated, or store full)
    input  wire         cb_go,
    output reg          cb_done,
    output reg  [255:0] cb_secret,
    output wire         busy
);
    reg [255:0] coef [1:7];
    reg [7:0]   xs   [0:7];
    reg [255:0] ys   [0:7];
    reg [3:0]   st;
    localparam [3:0] S_IDLE = 4'd0, S_EV = 4'd1, S_CB_I = 4'd2, S_CB_J = 4'd3, S_CB_INV = 4'd4, S_CB_ACC = 4'd5;
    assign busy = (st != S_IDLE);

    reg [255:0] y;
    reg [7:0]   x_r;
    reg [3:0]   m_r, kk;
    reg [3:0]   i, j;
    reg [7:0]   num, den, r, lag;
    reg [7:0]   icnt;
    reg [255:0] acc;
    integer q;

    function [7:0] gmul8(input [7:0] a, input [7:0] b);
        integer n;
        reg [7:0] aa, bb, p;
        begin
            aa = a; bb = b; p = 8'd0;
            for (n = 0; n < 8; n = n + 1) begin
                if (bb[0]) p = p ^ aa;
                aa = {aa[6:0], 1'b0} ^ (aa[7] ? 8'h1b : 8'h00);
                bb = {1'b0, bb[7:1]};
            end
            gmul8 = p;
        end
    endfunction

    function [255:0] mulvec(input [255:0] v, input [7:0] s);
        integer n;
        begin
            for (n = 0; n < 32; n = n + 1) mulvec[8*n +: 8] = gmul8(v[8*n +: 8], s);
        end
    endfunction

    function dup_x(input [7:0] xv);
        integer n;
        begin
            dup_x = 1'b0;
            for (n = 0; n < 8; n = n + 1) if (n < sh_cnt && xs[n] == xv) dup_x = 1'b1;
        end
    endfunction

    task clear_all;
        begin
            for (q = 1; q < 8; q = q + 1) coef[q] <= 256'd0;
            for (q = 0; q < 8; q = q + 1) begin xs[q] <= 8'd0; ys[q] <= 256'd0; end
            st <= S_IDLE; sh_cnt <= 4'd0; ev_y <= 256'd0; cb_secret <= 256'd0;
            y <= 256'd0; acc <= 256'd0; num <= 8'd0; den <= 8'd0; r <= 8'd0; lag <= 8'd0;
        end
    endtask

    initial begin
        for (q = 1; q < 8; q = q + 1) coef[q] = 256'd0;
        for (q = 0; q < 8; q = q + 1) begin xs[q] = 8'd0; ys[q] = 256'd0; end
        st = S_IDLE; sh_cnt = 4'd0; ev_y = 256'd0; cb_secret = 256'd0; ev_done = 1'b0; cb_done = 1'b0;
        sh_rej = 1'b0; y = 256'd0; acc = 256'd0; num = 0; den = 0; r = 0; lag = 0; i = 0; j = 0; kk = 0;
        icnt = 0; x_r = 0; m_r = 0;
    end

    always @(posedge clk or posedge tamper) begin
        if (tamper) begin
            clear_all;
            ev_done <= 1'b0; cb_done <= 1'b0; sh_rej <= 1'b0;
        end else begin
            ev_done <= 1'b0; cb_done <= 1'b0; sh_rej <= 1'b0;
            if (wipe || !rst_n) begin
                clear_all;
            end else begin
                if (coef_ld && coef_idx != 3'd0) coef[coef_idx] <= coef_d;
                if (sh_ld && st == S_IDLE) begin
                    if (sh_x == 8'd0 || sh_cnt >= 4'd8 || dup_x(sh_x)) sh_rej <= 1'b1;
                    else begin xs[sh_cnt] <= sh_x; ys[sh_cnt] <= sh_y; sh_cnt <= sh_cnt + 4'd1; end
                end
                case (st)
                S_IDLE: begin
                    if (ev_go && ev_m >= 4'd2) begin
                        x_r <= ev_x; m_r <= ev_m; y <= coef[ev_m - 4'd1]; kk <= ev_m - 4'd2; st <= S_EV;
                    end else if (cb_go && sh_cnt >= 4'd2) begin
                        acc <= 256'd0; i <= 4'd0; st <= S_CB_I;
                    end
                end
                S_EV: begin
                    if (kk == 4'd0) begin
                        ev_y <= mulvec(y, x_r) ^ secret_in; y <= 256'd0; ev_done <= 1'b1; st <= S_IDLE;
                    end else begin
                        y <= mulvec(y, x_r) ^ coef[kk]; kk <= kk - 4'd1;
                    end
                end
                S_CB_I: begin num <= 8'd1; den <= 8'd1; j <= 4'd0; st <= S_CB_J; end
                S_CB_J: begin
                    if (j == sh_cnt) begin r <= 8'd1; icnt <= 8'd0; st <= S_CB_INV; end
                    else begin
                        if (j != i) begin
                            num <= gmul8(num, xs[j]);
                            den <= gmul8(den, xs[i] ^ xs[j]);
                        end
                        j <= j + 4'd1;
                    end
                end
                S_CB_INV: begin                       // r = den^254 = den^-1
                    if (icnt == 8'd254) begin lag <= gmul8(num, r); st <= S_CB_ACC; end
                    else begin r <= gmul8(r, den); icnt <= icnt + 8'd1; end
                end
                S_CB_ACC: begin
                    if (i == sh_cnt - 4'd1) begin
                        cb_secret <= acc ^ mulvec(ys[i], lag); acc <= 256'd0; cb_done <= 1'b1; st <= S_IDLE;
                    end else begin
                        acc <= acc ^ mulvec(ys[i], lag); i <= i + 4'd1; st <= S_CB_I;
                    end
                end
                default: st <= S_IDLE;
                endcase
            end
        end
    end
endmodule
