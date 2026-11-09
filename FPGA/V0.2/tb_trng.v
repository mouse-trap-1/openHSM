`timescale 1ns/1ps
//------------------------------------------------------------------------------
// Testbench for trng_ro in SIM_MODEL (checks plumbing and the health tests only,
// the sim model is not random).
//   iverilog -g2005 -o sim_trng tb_trng.v trng_ro.v
//------------------------------------------------------------------------------
module tb_trng;
    reg clk = 0, rst_n = 0, enable = 0, ack = 0;
    always #5 clk = ~clk;
    wire word_valid, health_fail;
    wire [255:0] word;
    trng_ro #(.SIM_MODEL(1), .SAMPLE_DIV(2)) dut (.clk(clk), .rst_n(rst_n), .enable(enable),
        .ack(ack), .word_valid(word_valid), .word(word), .health_fail(health_fail));

    integer errors = 0, cyc, ones, i;
    reg [255:0] w1, w2;

    function integer popcount(input [255:0] v);
        integer j;
        begin popcount = 0; for (j = 0; j < 256; j = j + 1) popcount = popcount + v[j]; end
    endfunction

    initial begin
        repeat (5) @(posedge clk); rst_n = 1;

        // output must stay empty until enabled (and after start-up test)
        repeat (6000) @(posedge clk);
        if (word_valid) begin errors = errors + 1; $display("FAIL: word produced while disabled"); end

        enable = 1; cyc = 0;
        while (!word_valid && cyc < 400000) begin @(posedge clk); cyc = cyc + 1; end
        if (!word_valid) begin errors = errors + 1; $display("FAIL: no word"); end
        w1 = word; @(posedge clk); ack <= 1; @(posedge clk); ack <= 0; @(posedge clk);
        if (word_valid) begin errors = errors + 1; $display("FAIL: word_valid not cleared by ack"); end

        cyc = 0;
        while (!word_valid && cyc < 400000) begin @(posedge clk); cyc = cyc + 1; end
        w2 = word; ack <= 1; @(posedge clk); ack <= 0;
        ones = popcount(w1);
        $display("word1 ones=%0d, word2 ones=%0d, equal=%0d", ones, popcount(w2), (w1 == w2));
        if (w1 == w2 || ones < 90 || ones > 166) begin errors = errors + 1; $display("FAIL: word statistics"); end
        else $display("PASS: words generated, differ, plausible popcount");
        if (health_fail) begin errors = errors + 1; $display("FAIL: spurious health failure"); end

        // stuck-at fault must trip the repetition-count test and block output
        force dut.raw_bit = 1'b0;
        repeat (300) @(posedge clk);
        release dut.raw_bit;
        if (!health_fail) begin errors = errors + 1; $display("FAIL: stuck source not detected"); end
        else $display("PASS: stuck-at fault detected, health_fail set");
        repeat (200000) @(posedge clk);
        if (word_valid) begin errors = errors + 1; $display("FAIL: output not blocked after health failure"); end
        else $display("PASS: output blocked after failure");

        // reset clears the sticky failure
        rst_n = 0; repeat (3) @(posedge clk); rst_n = 1; repeat (3) @(posedge clk);
        if (health_fail) begin errors = errors + 1; $display("FAIL: reset did not clear health_fail"); end

        if (errors == 0) $display("ALL TRNG TESTS PASSED"); else $display("%0d TRNG TESTS FAILED", errors);
        $finish;
    end
endmodule
