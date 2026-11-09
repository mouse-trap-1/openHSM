`timescale 1ns/1ps
//------------------------------------------------------------------------------
// Testbench: HMAC-SHA256 (various message lengths) and the RFC 6979 nonce engine
// Vectors come from Python hashlib/hmac (gen_tests.py).
//   iverilog -g2005 -o sim_hash tb_hash_nonce.v rfc6979_nonce.v hmac_sha256.v sha256_core.v
//------------------------------------------------------------------------------
module tb_hash_nonce;
    reg clk = 0;
    always #5 clk = ~clk;

    integer errors = 0, n = 0;

    // ---------------- HMAC under test ----------------
    reg          h_start = 0;
    reg  [255:0] h_key = 0;
    reg  [1535:0] h_msg = 0;
    reg  [7:0]   h_len = 0;
    wire         h_busy, h_done;
    wire [255:0] h_mac;
    hmac_sha256 u_hmac (.clk(clk), .wipe(1'b0), .start(h_start), .key(h_key),
                        .msg(h_msg), .msg_len(h_len), .busy(h_busy), .done(h_done), .mac(h_mac));

    task run_hmac(input [255:0] key, input [1535:0] msg, input [7:0] len, input [255:0] exp);
        integer cyc;
        begin
            @(posedge clk); h_key <= key; h_msg <= msg; h_len <= len; h_start <= 1;
            @(posedge clk); h_start <= 0;
            cyc = 0;
            while (!h_done && cyc < 5000) begin @(posedge clk); cyc = cyc + 1; end
            n = n + 1;
            if (!h_done || h_mac !== exp) begin
                errors = errors + 1;
                $display("FAIL hmac len=%0d\n  got %h\n  exp %h", len, h_mac, exp);
            end else $display("PASS hmac len=%0d (%0d cycles)", len, cyc);
        end
    endtask

    // ---------------- RFC 6979 under test (with its own HMAC) ----------------
    reg          r_start = 0, r_ue = 0;
    reg  [255:0] r_x = 0, r_h = 0, r_e = 0;
    wire         r_busy, r_done;
    wire [255:0] r_k;
    wire         m_start, m_busy, m_done;
    wire [255:0] m_key, m_mac;
    wire [1535:0] m_msg;
    wire [7:0]   m_len;
    rfc6979_nonce u_rfc (.clk(clk), .wipe(1'b0), .start(r_start), .x(r_x), .h1(r_h),
                         .extra(r_e), .use_extra(r_ue), .busy(r_busy), .done(r_done), .k(r_k),
                         .hm_start(m_start), .hm_key(m_key), .hm_msg(m_msg), .hm_len(m_len),
                         .hm_done(m_done), .hm_mac(m_mac));
    hmac_sha256 u_hmac2 (.clk(clk), .wipe(1'b0), .start(m_start), .key(m_key),
                         .msg(m_msg), .msg_len(m_len), .busy(m_busy), .done(m_done), .mac(m_mac));

    task run_rfc(input [255:0] x, input [255:0] h1, input [255:0] extra, input ue, input [255:0] exp);
        integer cyc;
        begin
            @(posedge clk); r_x <= x; r_h <= h1; r_e <= extra; r_ue <= ue; r_start <= 1;
            @(posedge clk); r_start <= 0;
            cyc = 0;
            while (!r_done && cyc < 50000) begin @(posedge clk); cyc = cyc + 1; end
            n = n + 1;
            if (!r_done || r_k !== exp) begin
                errors = errors + 1;
                $display("FAIL rfc6979 ue=%0d\n  got %h\n  exp %h", ue, r_k, exp);
            end else $display("PASS rfc6979 ue=%0d (%0d cycles) k=%h", ue, cyc, r_k);
        end
    endtask

    initial begin
        repeat (4) @(posedge clk);
        `include "tb_hmac_vecs.vh"
        `include "tb_rfc_vecs.vh"
        if (errors == 0) $display("ALL %0d HASH/NONCE TESTS PASSED", n);
        else             $display("%0d of %0d TESTS FAILED", errors, n);
        $finish;
    end
endmodule
