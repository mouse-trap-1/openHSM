`timescale 1ns/1ps
//------------------------------------------------------------------------------
// spi_host_slave : SPI slave for the SoC host link (replaces i2c_slave in V0.6)
//
//   * SPI mode 0 (CPOL = 0, CPHA = 0), MSB first, one chip select per node.
//     SCLK, CS_N and MOSI are sampled by the system clock through a 2-flop
//     synchroniser; there is no separate SPI clock domain.  clk must be at
//     least 8x SCLK (100 MHz clk -> SCLK up to 12.5 MHz).
//   * MISO is driven only while CS_N is low (miso_oe = 1); map it to an OBUFT
//     so several devices can share the bus.  MISO changes right after the
//     SCLK rising edge on which the master sampled the previous bit, which
//     gives the master most of an SCLK period of setup time.
//   * Same register-pointer protocol and byte interface as i2c_slave, so the
//     register file of sign_node_top is unchanged:
//       write: CS_N low, 0x02, pointer, data, data, ...            CS_N high
//       read : CS_N low, 0x03, pointer, dummy, <data out>, ...      CS_N high
//     The pointer byte is flagged with rx_first.  In a write frame every
//     following complete byte pulses rx_valid.  In a read frame the dummy byte
//     gives the pointer owner time to present tx_data; tx_next pulses once per
//     data byte (on its 7th bit) so the next byte is ready at the boundary.
//     Any other opcode is ignored until CS_N rises.  A partial byte at CS_N
//     rise is discarded.
//   * Bus cost: (3 + n) bytes for a read of n, (2 + n) for a write, with no
//     address/ACK bits, against 9 bits per byte plus framing on I2C.
//------------------------------------------------------------------------------
module spi_host_slave (
    input  wire       clk,
    input  wire       rst_n,
    input  wire       sclk_i,
    input  wire       cs_n_i,
    input  wire       mosi_i,
    output reg        miso_o,
    output wire       miso_oe,
    output reg        rx_valid,
    output reg  [7:0] rx_data,
    output reg        rx_first,
    output reg        tx_next,
    input  wire [7:0] tx_data
);
    localparam [7:0] OP_WRITE = 8'h02, OP_READ = 8'h03;

    reg [2:0] sclk_sy, cs_sy, mosi_sy;
    wire sclk_s = sclk_sy[1], sclk_p = sclk_sy[2];
    wire cs_s   = cs_sy[1];
    wire mosi_s = mosi_sy[1];
    wire sclk_rise = sclk_s & ~sclk_p;

    reg [2:0] bitcnt;
    reg [1:0] bytecnt;                  // 0 opcode, 1 pointer, 2 first data / dummy, 3 later data (saturates)
    reg [6:0] sh;
    reg [7:0] op, txb;
    wire [7:0] byte_in = {sh, mosi_s};
    wire is_rd = (op == OP_READ), is_wr = (op == OP_WRITE);

    assign miso_oe = ~cs_s;

    initial begin
        sclk_sy = 3'b000; cs_sy = 3'b111; mosi_sy = 3'b000;
        miso_o = 1'b0; rx_valid = 1'b0; rx_data = 8'd0; rx_first = 1'b0; tx_next = 1'b0;
        bitcnt = 3'd0; bytecnt = 2'd0; sh = 7'd0; op = 8'd0; txb = 8'd0;
    end

    always @(posedge clk) begin
        sclk_sy  <= {sclk_sy[1:0], sclk_i};
        cs_sy    <= {cs_sy[1:0], cs_n_i};
        mosi_sy  <= {mosi_sy[1:0], mosi_i};
        rx_valid <= 1'b0;
        tx_next  <= 1'b0;

        if (!rst_n || cs_s) begin
            bitcnt <= 3'd0; bytecnt <= 2'd0; op <= 8'd0; miso_o <= 1'b0; sh <= 7'd0;
        end else if (sclk_rise) begin
            sh     <= byte_in[6:0];
            bitcnt <= bitcnt + 3'd1;
            if (bitcnt == 3'd7) begin
                // ---------------- byte complete ----------------
                if (bytecnt != 2'd3) bytecnt <= bytecnt + 2'd1;
                case (bytecnt)
                2'd0: op <= byte_in;
                2'd1: if (is_rd || is_wr) begin rx_valid <= 1'b1; rx_data <= byte_in; rx_first <= 1'b1; end
                default: begin
                    if (is_wr) begin rx_valid <= 1'b1; rx_data <= byte_in; rx_first <= 1'b0; end
                    if (is_rd) begin txb <= tx_data; miso_o <= tx_data[7]; end
                end
                endcase
            end else begin
                // ---------------- inside a byte ----------------
                if (is_rd && bytecnt == 2'd3) begin
                    miso_o <= txb[3'd6 - bitcnt];
                    if (bitcnt == 3'd6) tx_next <= 1'b1;    // advance the pointer before the boundary
                end else begin
                    miso_o <= 1'b0;
                end
            end
        end
    end
endmodule
