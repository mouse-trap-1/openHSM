`timescale 1ns/1ps
//------------------------------------------------------------------------------
// Unit test for keccak256_core against gen_keccak_vectors.py, plus wipe.
//
//   python3 gen_keccak_vectors.py .
//   iverilog -g2005 -o sim_keccak tb_keccak.v keccak256_core.v && vvp sim_keccak
//------------------------------------------------------------------------------
module tb_keccak;
    reg clk = 0;
    always #5 clk = ~clk;

    reg          wipe = 0, init = 0, start = 0;
    reg  [1087:0] block = 0;
    wire         busy, done;
    wire [255:0] digest;
    keccak256_core dut (.clk(clk), .wipe(wipe), .init(init), .start(start), .block(block),
                        .busy(busy), .done(done), .digest(digest));

    `include "tb_keccak_vecs.vh"

    integer v, b, errors = 0, cycles, t0;
    initial begin
        #20;
        for (v = 0; v < NVEC; v = v + 1) begin
            for (b = 0; b < vcount[v]; b = b + 1) begin
                @(negedge clk); block = vblk[vfirst[v] + b]; init = (b == 0); start = 1;
                @(negedge clk); start = 0; init = 0; t0 = $time;
                while (!done) @(negedge clk);
                cycles = ($time - t0) / 10;
            end
            if (digest !== vexp[v]) begin
                errors = errors + 1;
                $display("FAIL vector %0d: got %h want %h", v, digest, vexp[v]);
            end else
                $display("ok   vector %0d (%0d block%s) %h", v, vcount[v], vcount[v] == 1 ? "" : "s", digest);
        end
        $display("cycles per block: %0d", cycles);
        // wipe clears the state mid-permutation
        @(negedge clk); block = vblk[0]; init = 1; start = 1;
        @(negedge clk); start = 0; init = 0;
        repeat (5) @(negedge clk); wipe = 1;
        @(negedge clk); wipe = 0;
        if (busy !== 1'b0 || digest !== 256'd0) begin errors = errors + 1; $display("FAIL wipe"); end
        else $display("ok   wipe clears state and stops the permutation");

        $display("keccak256_core: %0d vectors, %0d errors", NVEC, errors);
        if (errors == 0) $display("PASS"); else $display("FAILED");
        $finish;
    end
endmodule
