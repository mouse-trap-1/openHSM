`timescale 1ns/1ps
//------------------------------------------------------------------------------
// Unit test for spi_host_slave: a 256-byte register file behind the slave,
// driven by a mode-0 master at the fastest supported SCLK (clk / 8, 12.5 MHz
// with a 100 MHz clk) and at a slow, phase-shifted SCLK.
//
//   iverilog -g2005 -o sim_spih tb_spi_host_slave.v spi_host_slave.v && vvp sim_spih
//------------------------------------------------------------------------------
module tb_spi_host_slave;
    reg clk = 0, rst_n = 0;
    always #5 clk = ~clk;

    reg sclk = 0, cs_n = 1, mosi = 0;
    wire miso, miso_oe;
    wire rx_valid, rx_first, tx_next;
    wire [7:0] rx_data;
    reg  [7:0] mem [0:255];
    reg  [7:0] ptr = 0;
    wire [7:0] tx_data = mem[ptr];

    spi_host_slave dut (.clk(clk), .rst_n(rst_n), .sclk_i(sclk), .cs_n_i(cs_n), .mosi_i(mosi),
                        .miso_o(miso), .miso_oe(miso_oe), .rx_valid(rx_valid), .rx_data(rx_data),
                        .rx_first(rx_first), .tx_next(tx_next), .tx_data(tx_data));

    // register-file owner, as in sign_node_top
    always @(posedge clk) begin
        if (rx_valid) begin
            if (rx_first) ptr <= rx_data;
            else begin mem[ptr] <= rx_data; ptr <= ptr + 8'd1; end
        end
        if (tx_next) ptr <= ptr + 8'd1;
    end

    integer HALF = 40;                  // ns; 40 = 12.5 MHz
    integer errors = 0, checks = 0;
    task check(input cond, input [255:0] msg);
        begin checks = checks + 1; if (!cond) begin errors = errors + 1; $display("FAIL %0s", msg); end end
    endtask

    reg [7:0] rb;
    task xfer(input [7:0] b, output [7:0] r);
        integer i;
        begin
            for (i = 7; i >= 0; i = i - 1) begin
                mosi = b[i]; #(HALF); sclk = 1; r[i] = miso_oe ? miso : 1'bx; #(HALF); sclk = 0;
            end
        end
    endtask
    task cs_lo; begin cs_n = 0; #(2*HALF); end endtask
    task cs_hi; begin #(HALF); cs_n = 1; #(4*HALF); end endtask

    reg [255:0] rd_val;
    task wr(input [7:0] p, input [255:0] v, input integer n);
        integer i;
        begin
            cs_lo; xfer(8'h02, rb); xfer(p, rb);
            for (i = n - 1; i >= 0; i = i - 1) xfer(v[8*i +: 8], rb);
            cs_hi;
        end
    endtask
    task rd(input [7:0] p, input integer n);
        integer i;
        begin
            rd_val = 0;
            cs_lo; xfer(8'h03, rb); xfer(p, rb); xfer(8'h00, rb);
            for (i = n - 1; i >= 0; i = i - 1) begin xfer(8'h00, rb); rd_val = {rd_val[247:0], rb}; end
            cs_hi;
        end
    endtask

    integer k;
    initial begin
        for (k = 0; k < 256; k = k + 1) mem[k] = k[7:0] ^ 8'h5A;
        #100 rst_n = 1; #100;

        // 1. read back the preset pattern
        rd(8'h10, 4);
        check(rd_val[31:0] === {8'h10 ^ 8'h5A, 8'h11 ^ 8'h5A, 8'h12 ^ 8'h5A, 8'h13 ^ 8'h5A}, "read preset");
        // 2. write 32 bytes, read them back
        wr(8'h44, 256'h00112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210, 32);
        rd(8'h44, 32);
        check(rd_val === 256'h00112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210, "write/read 32");
        // 3. single-byte read and pointer wrap
        wr(8'hFF, 256'hA1B2, 2);
        rd(8'hFF, 2);
        check(rd_val[15:0] === 16'hA1B2 && mem[0] === 8'hB2, "pointer wraps 0xFF -> 0x00");
        // 4. unknown opcode writes nothing
        cs_lo; xfer(8'h9F, rb); xfer(8'h20, rb); xfer(8'hEE, rb); cs_hi;
        check(mem[8'h20] === (8'h20 ^ 8'h5A), "unknown opcode ignored");
        // 5. partial byte at CS rise is dropped
        cs_lo; xfer(8'h02, rb); xfer(8'h30, rb); xfer(8'h77, rb);
        mosi = 1; #(HALF); sclk = 1; #(HALF); sclk = 0; #(HALF); sclk = 1; #(HALF); sclk = 0;
        cs_hi;
        check(mem[8'h30] === 8'h77 && mem[8'h31] === (8'h31 ^ 8'h5A), "partial byte dropped");
        // 6. MISO released while deselected
        check(miso_oe === 1'b0, "MISO released with CS high");
        // 7. slow, odd SCLK
        HALF = 137;
        wr(8'h80, 256'hCAFEBABE, 4);
        rd(8'h80, 4);
        check(rd_val[31:0] === 32'hCAFEBABE, "slow SCLK write/read");
        // 8. back at the fastest rate: long read across buffers
        HALF = 40;
        rd(8'h44, 32);
        check(rd_val === 256'h00112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210, "repeat read at 12.5 MHz");

        $display("spi_host_slave: %0d checks, %0d errors", checks, errors);
        if (errors == 0) $display("PASS"); else $display("FAILED");
        $finish;
    end
endmodule
