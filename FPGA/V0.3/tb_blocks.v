`timescale 1ns/1ps
// Tests spi_secret_rx, point_check and the generic-base-point ECDH mode of the core.
module tb_blocks;
    reg clk = 0; always #5 clk = ~clk;
    reg rst_n = 0;
    integer errors = 0, tests = 0;

    // ---------------- SPI ----------------
    reg sclk = 0, cs_n = 1, mosi = 0, spi_clear = 0;
    wire s_valid; wire [255:0] s_data;
    spi_secret_rx u_spi (.clk(clk), .rst_n(rst_n), .wipe(1'b0), .clear(spi_clear),
                         .sclk(sclk), .cs_n(cs_n), .mosi(mosi), .s_valid(s_valid), .s_data(s_data));
    reg got_valid = 0;
    always @(posedge clk) if (s_valid) got_valid <= 1'b1;

    task spi_frame(input [7:0] hdr, input [255:0] s, input integer nbits_override);
        reg [263:0] fr; integer i, n;
        begin
            fr = {hdr, s}; n = (nbits_override == 0) ? 264 : nbits_override;
            got_valid = 0;
            cs_n = 0; repeat (8) @(posedge clk);
            for (i = 0; i < n; i = i + 1) begin
                mosi = fr[263 - i]; repeat (4) @(posedge clk);
                sclk = 1; repeat (4) @(posedge clk);
                sclk = 0; repeat (2) @(posedge clk);
            end
            repeat (8) @(posedge clk);
            cs_n = 1; repeat (12) @(posedge clk);
        end
    endtask

    // ---------------- point check ----------------
    reg pc_start = 0; reg [255:0] pc_x = 0, pc_y = 0;
    wire pc_busy, pc_done, pc_valid;
    point_check u_pc (.clk(clk), .wipe(1'b0), .start(pc_start), .x(pc_x), .y(pc_y),
                      .busy(pc_busy), .done(pc_done), .valid(pc_valid));
    task run_pc(input [255:0] x, input [255:0] y, input exp);
        integer to;
        begin
            @(negedge clk); pc_x = x; pc_y = y; pc_start = 1; @(negedge clk); pc_start = 0;
            to = 0; while (!pc_done && to < 5000) begin @(negedge clk); to = to + 1; end
            tests = tests + 1;
            if (to >= 5000 || pc_valid !== exp) begin
                errors = errors + 1; $display("FAIL point_check #%0d: valid=%b expected %b", tests, pc_valid, exp);
            end
        end
    endtask

    // ---------------- ECDH via core ----------------
    reg c_start = 0; reg [255:0] c_d = 0, c_bx = 0, c_by = 0;
    wire c_busy, c_done, c_fail; wire [255:0] c_r, c_s, c_px, c_py;
    ecdsa_secp256k1_sign #(.LOW_S(1)) u_core (
        .clk(clk), .rst_n(rst_n), .wipe(1'b0), .start(c_start), .mode_pub(1'b1),
        .d_in(c_d), .k_in(c_d), .z_in(256'd0), .use_base(1'b1), .bx_in(c_bx), .by_in(c_by),
        .busy(c_busy), .done(c_done), .fail(c_fail), .r_out(c_r), .s_out(c_s), .px_out(c_px), .py_out(c_py));
    task run_ecdh(input [255:0] d, input [255:0] bx, input [255:0] by, input [255:0] ex, input [255:0] ey);
        begin
            @(negedge clk); c_d = d; c_bx = bx; c_by = by; c_start = 1; @(negedge clk); c_start = 0;
            while (!c_done) @(negedge clk);
            tests = tests + 1;
            if (c_fail || c_px !== ex || c_py !== ey) begin
                errors = errors + 1; $display("FAIL ecdh #%0d: got %h", tests, c_px);
            end
        end
    endtask

    reg [255:0] S1 = 256'h0123456789abcdef_fedcba9876543210_0f1e2d3c4b5a6978_8796a5b4c3d2e1f0;
    initial begin
        repeat (5) @(negedge clk); rst_n = 1; repeat (5) @(negedge clk);

        // good frame
        spi_frame(8'hA5, S1, 0);
        tests = tests + 1;
        if (!got_valid || s_data !== S1) begin errors = errors + 1; $display("FAIL spi good frame"); end
        else $display("spi good frame: PASS");
        @(negedge clk); spi_clear = 1; @(negedge clk); spi_clear = 0; @(negedge clk);
        tests = tests + 1;
        if (s_data !== 256'd0) begin errors = errors + 1; $display("FAIL spi clear: s_data=%h", s_data); end
        // wrong header
        spi_frame(8'h5A, S1, 0);
        tests = tests + 1;
        if (got_valid || s_data !== 256'd0) begin errors = errors + 1; $display("FAIL spi bad header"); end
        // short frame
        spi_frame(8'hA5, S1, 200);
        tests = tests + 1;
        if (got_valid) begin errors = errors + 1; $display("FAIL spi short frame"); end
        // good again after bad ones
        spi_frame(8'hA5, ~S1, 0);
        tests = tests + 1;
        if (!got_valid || s_data !== ~S1) begin errors = errors + 1; $display("FAIL spi recover"); end
        else $display("spi reject/recover: PASS");

        `include "tb_blocks_vecs.vh"

        if (errors == 0) $display("ALL BLOCK TESTS PASSED (%0d checks)", tests);
        else $display("BLOCK TESTS FAILED: %0d errors", errors);
        $finish;
    end
endmodule
