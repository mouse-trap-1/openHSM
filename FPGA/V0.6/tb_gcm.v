`timescale 1ns/1ps
module tb_gcm;
    reg clk = 0;
    always #5 clk = ~clk;

    reg wipe = 0;
    reg start = 0, dec = 0;
    reg [255:0] key = 0;
    reg [95:0]  iv = 0;
    reg [127:0] aad = 0;
    reg [255:0] din = 0;
    reg [127:0] tag_in = 0;
    wire busy, done, auth_ok;
    wire [255:0] dout;
    wire [127:0] tag_out;

    aes_gcm32 dut (.clk(clk), .wipe(wipe), .start(start), .dec(dec), .key(key), .iv(iv),
                   .aad(aad), .din(din), .tag_in(tag_in), .busy(busy), .done(done),
                   .dout(dout), .tag_out(tag_out), .auth_ok(auth_ok));

    // standalone AES check (FIPS-197 C.3)
    reg          k_load = 0, b_start = 0;
    reg  [255:0] k_aes = 256'h000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f;
    reg  [127:0] b_in  = 128'h00112233445566778899aabbccddeeff;
    wire         k_ready, b_done, b_busy;
    wire [127:0] b_out;
    aes256_core aes_t (.clk(clk), .wipe(1'b0), .key_load(k_load), .key(k_aes), .key_ready(k_ready),
                       .blk_start(b_start), .blk_in(b_in), .blk_done(b_done), .blk_out(b_out),
                       .busy(b_busy));

    integer errors = 0, tests = 0, to;

    task run_gcm(input d, input [255:0] k, input [95:0] i, input [127:0] a, input [255:0] di,
                 input [127:0] ti, input [255:0] exp_out, input [127:0] exp_tag, input exp_ok);
        begin
            @(negedge clk);
            dec = d; key = k; iv = i; aad = a; din = di; tag_in = ti;
            start = 1;
            @(negedge clk);
            start = 0;
            to = 0;
            while (!done && to < 5000) begin @(negedge clk); to = to + 1; end
            tests = tests + 1;
            if (to >= 5000) begin $display("FAIL test %0d: timeout", tests); errors = errors + 1; end
            else begin
                if (auth_ok !== exp_ok) begin
                    $display("FAIL test %0d: auth_ok=%b expected %b", tests, auth_ok, exp_ok); errors = errors + 1;
                end
                if (dout !== exp_out) begin
                    $display("FAIL test %0d: dout mismatch\n  got %h\n  exp %h", tests, dout, exp_out); errors = errors + 1;
                end
                if (exp_ok && tag_out !== exp_tag) begin
                    $display("FAIL test %0d: tag mismatch got %h exp %h", tests, tag_out, exp_tag); errors = errors + 1;
                end
            end
            @(negedge clk);
        end
    endtask

    initial begin
        // AES-256 block test
        repeat (3) @(negedge clk);
        k_load = 1; @(negedge clk); k_load = 0;
        while (!k_ready) @(negedge clk);
        b_start = 1; @(negedge clk); b_start = 0;
        while (!b_done) @(negedge clk);
        tests = tests + 1;
        if (b_out !== 128'h8ea2b7ca516745bfeafc49904b496089) begin
            $display("FAIL AES-256 FIPS-197: got %h", b_out); errors = errors + 1;
        end else $display("AES-256 FIPS-197 block: PASS");

        `include "tb_gcm_vecs.vh"

        // wipe mid-operation must stop the engine and clear outputs
        @(negedge clk);
        dec = 0; key = 256'h11; iv = 96'h22; aad = 128'h33; din = 256'h44; start = 1;
        @(negedge clk); start = 0;
        repeat (100) @(negedge clk);
        wipe = 1; @(negedge clk); wipe = 0;
        repeat (3) @(negedge clk);
        tests = tests + 1;
        if (busy !== 1'b0 || dout !== 256'd0) begin
            $display("FAIL wipe: busy=%b dout=%h", busy, dout); errors = errors + 1;
        end else $display("wipe mid-operation: PASS");

        if (errors == 0) $display("ALL GCM TESTS PASSED (%0d checks)", tests);
        else $display("GCM TESTS FAILED: %0d errors", errors);
        $finish;
    end
endmodule
