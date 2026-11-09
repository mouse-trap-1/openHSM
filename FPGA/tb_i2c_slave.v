`timescale 1ns/1ps
//------------------------------------------------------------------------------
// Testbench for i2c_slave: bit-banged master (1 MHz SCL, 100 MHz system clock)
// against a small register-file model that mimics the pointer protocol.
//   iverilog -g2005 -o sim_i2c tb_i2c_slave.v i2c_slave.v
//------------------------------------------------------------------------------
module tb_i2c_slave;
    reg clk = 0, rst_n = 0;
    always #5 clk = ~clk;

    reg  m_scl = 1, m_sda_low = 0;
    wire sda_oe;
    wire sda = (m_sda_low | sda_oe) ? 1'b0 : 1'b1;      // open-drain bus with pull-up
    wire scl = m_scl;

    wire       rx_valid, rx_first, tx_next;
    wire [7:0] rx_data;
    reg  [7:0] tx_data;

    i2c_slave #(.ADDR(7'h42)) dut (.clk(clk), .rst_n(rst_n), .scl_i(scl), .sda_i(sda),
                                   .sda_oe(sda_oe), .rx_valid(rx_valid), .rx_data(rx_data),
                                   .rx_first(rx_first), .tx_next(tx_next), .tx_data(tx_data));

    // ---- register file model driven by the slave's byte interface
    reg [7:0] mem [0:255];
    reg [7:0] ptr = 0;
    integer k;
    initial for (k = 0; k < 256; k = k + 1) mem[k] = 8'h00;
    always @(posedge clk) begin
        if (rx_valid) begin
            if (rx_first) ptr <= rx_data;
            else begin mem[ptr] <= rx_data; ptr <= ptr + 8'd1; end
        end
        if (tx_next) ptr <= ptr + 8'd1;
    end
    always @(*) tx_data = mem[ptr];

    // ---- master primitives (SCL period 1 us)
    localparam Q = 250;
    task i2c_start; begin
        m_sda_low = 0; m_scl = 1; #Q; m_sda_low = 1; #Q; m_scl = 0; #Q;
    end endtask
    task i2c_rstart; begin
        m_sda_low = 0; #Q; m_scl = 1; #Q; m_sda_low = 1; #Q; m_scl = 0; #Q;
    end endtask
    task i2c_stop; begin
        m_sda_low = 1; #Q; m_scl = 1; #Q; m_sda_low = 0; #(2*Q);
    end endtask
    task wr_byte(input [7:0] b, output ack);
        integer i;
        begin
            for (i = 7; i >= 0; i = i - 1) begin
                m_sda_low = ~b[i]; #Q; m_scl = 1; #(2*Q); m_scl = 0; #Q;
            end
            m_sda_low = 0; #Q; m_scl = 1; #Q; ack = ~sda; #Q; m_scl = 0; #Q;
        end
    endtask
    task rd_byte(input send_ack, output [7:0] b);
        integer i;
        begin
            m_sda_low = 0;
            for (i = 7; i >= 0; i = i - 1) begin
                #Q; m_scl = 1; #Q; b[i] = sda; #Q; m_scl = 0; #Q;
            end
            m_sda_low = send_ack; #Q; m_scl = 1; #(2*Q); m_scl = 0; #Q; m_sda_low = 0;
        end
    endtask

    integer errors = 0;
    reg ack; reg [7:0] rb;

    initial begin
        repeat (10) @(posedge clk);
        rst_n = 1;
        repeat (10) @(posedge clk);

        // write 4 bytes starting at pointer 0x20
        i2c_start; wr_byte({7'h42, 1'b0}, ack);
        if (!ack) begin errors = errors + 1; $display("FAIL: address not ACKed"); end
        wr_byte(8'h20, ack); wr_byte(8'hDE, ack); wr_byte(8'hAD, ack); wr_byte(8'hBE, ack); wr_byte(8'hEF, ack);
        i2c_stop;
        if (mem[8'h20] !== 8'hDE || mem[8'h21] !== 8'hAD || mem[8'h22] !== 8'hBE || mem[8'h23] !== 8'hEF) begin
            errors = errors + 1; $display("FAIL: write data wrong %h %h %h %h", mem[8'h20], mem[8'h21], mem[8'h22], mem[8'h23]);
        end else $display("PASS: multi-byte write");

        // read them back with a repeated start
        i2c_start; wr_byte({7'h42, 1'b0}, ack); wr_byte(8'h20, ack);
        i2c_rstart; wr_byte({7'h42, 1'b1}, ack);
        if (!ack) begin errors = errors + 1; $display("FAIL: read address not ACKed"); end
        rd_byte(1, rb); if (rb !== 8'hDE) begin errors = errors + 1; $display("FAIL rb0=%h", rb); end
        rd_byte(1, rb); if (rb !== 8'hAD) begin errors = errors + 1; $display("FAIL rb1=%h", rb); end
        rd_byte(1, rb); if (rb !== 8'hBE) begin errors = errors + 1; $display("FAIL rb2=%h", rb); end
        rd_byte(0, rb); if (rb !== 8'hEF) begin errors = errors + 1; $display("FAIL rb3=%h", rb); end
        i2c_stop;
        $display("PASS: repeated-start multi-byte read (done)");

        // wrong address must be NACKed and ignored
        i2c_start; wr_byte({7'h43, 1'b0}, ack);
        if (ack) begin errors = errors + 1; $display("FAIL: wrong address ACKed"); end
        else $display("PASS: wrong address NACKed");
        i2c_stop;

        // bus must be free afterwards
        #2000;
        if (sda_oe) begin errors = errors + 1; $display("FAIL: slave holds SDA after stop"); end

        if (errors == 0) $display("ALL I2C TESTS PASSED"); else $display("%0d I2C TESTS FAILED", errors);
        $finish;
    end
endmodule
