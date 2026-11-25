`timescale 1ns/1ps
module tb_shamir;
    reg clk = 0; always #5 clk = ~clk;
    reg rst_n = 0, tamper = 0, wipe = 0;
    reg coef_ld = 0; reg [2:0] coef_idx = 0; reg [255:0] coef_d = 0;
    reg ev_go = 0; reg [7:0] ev_x = 0; reg [3:0] ev_m = 0; reg [255:0] secret_in = 0;
    wire ev_done; wire [255:0] ev_y;
    reg sh_ld = 0; reg [7:0] sh_x = 0; reg [255:0] sh_y = 0;
    wire [3:0] sh_cnt; wire sh_rej;
    reg cb_go = 0; wire cb_done; wire [255:0] cb_secret; wire busy;

    shamir_core dut (.clk(clk), .rst_n(rst_n), .tamper(tamper), .wipe(wipe),
        .coef_ld(coef_ld), .coef_idx(coef_idx), .coef_d(coef_d), .ev_go(ev_go), .ev_x(ev_x), .ev_m(ev_m),
        .secret_in(secret_in), .ev_done(ev_done), .ev_y(ev_y), .sh_ld(sh_ld), .sh_x(sh_x), .sh_y(sh_y),
        .sh_cnt(sh_cnt), .sh_rej(sh_rej), .cb_go(cb_go), .cb_done(cb_done), .cb_secret(cb_secret), .busy(busy));

    integer errors = 0, tests = 0;
    reg rej_seen = 0;
    always @(posedge clk) if (sh_rej) rej_seen <= 1'b1;

    task set_coef(input [2:0] k, input [255:0] v);
        begin @(negedge clk); coef_idx = k; coef_d = v; coef_ld = 1; @(negedge clk); coef_ld = 0; end
    endtask
    task run_eval(input [3:0] m, input [7:0] x, input [255:0] s, input [255:0] exp);
        begin
            @(negedge clk); ev_m = m; ev_x = x; secret_in = s; ev_go = 1; @(negedge clk); ev_go = 0;
            while (!ev_done) @(negedge clk);
            tests = tests + 1;
            if (ev_y !== exp) begin errors = errors + 1; $display("FAIL eval m=%0d x=%0d got %h exp %h", m, x, ev_y, exp); end
        end
    endtask
    task clr_shares;
        begin @(negedge clk); wipe = 1; @(negedge clk); wipe = 0; @(negedge clk); end
    endtask
    task put_share(input [7:0] x, input [255:0] y);
        begin rej_seen = 0; @(negedge clk); sh_x = x; sh_y = y; sh_ld = 1; @(negedge clk); sh_ld = 0; @(negedge clk); @(negedge clk); end
    endtask
    task expect_rej(input exp);
        begin tests = tests + 1; if (rej_seen !== exp) begin errors = errors + 1; $display("FAIL rejection expected=%b got=%b", exp, rej_seen); end end
    endtask
    task run_combine(input [255:0] exp, input ok);
        begin
            @(negedge clk); cb_go = 1; @(negedge clk); cb_go = 0;
            while (!cb_done) @(negedge clk);
            tests = tests + 1;
            if (cb_secret !== exp) begin errors = errors + 1; $display("FAIL combine got %h exp %h", cb_secret, exp); end
        end
    endtask

    initial begin
        repeat (4) @(negedge clk); rst_n = 1; repeat (2) @(negedge clk);
        `include "tb_shamir_vecs.vh"

        // tamper clears everything asynchronously
        set_coef(3'd1, 256'hDEAD);
        put_share(8'd5, 256'hBEEF);
        #3 tamper = 1; #7 tamper = 0;
        tests = tests + 1;
        if (dut.coef[1] !== 256'd0 || dut.ys[0] !== 256'd0 || sh_cnt !== 4'd0) begin
            errors = errors + 1; $display("FAIL tamper did not clear shamir state");
        end else $display("tamper clears coefficients and shares: PASS");

        if (errors == 0) $display("ALL SHAMIR TESTS PASSED (%0d checks)", tests);
        else $display("SHAMIR TESTS FAILED: %0d errors", errors);
        $finish;
    end
endmodule
