`timescale 1ns/1ps
//------------------------------------------------------------------------------
// i2c_slave : soft I2C slave (7-bit address), standard/fast mode
//
//   * SCL/SDA are sampled by the system clock (3-flop synchroniser); no
//     separate I2C clock domain.  clk should be >= 8x the SCL frequency.
//   * SDA is open-drain: `sda_oe` = 1 means "pull SDA low".  Map it to an
//     IOBUF/tri-state with the pin released (Hi-Z) when sda_oe = 0, and use an
//     external pull-up.  SCL is input-only (no clock stretching is needed).
//   * Register-pointer protocol, like most I2C peripherals:
//       write: [addr+W] [pointer] [data] [data] ...
//       read : [addr+W] [pointer] [Sr] [addr+R] <read bytes...>
//     The first byte after addr+W is flagged with rx_first (= pointer byte).
//   * tx_data must show the byte to send for the current pointer.  `tx_next`
//     pulses when the master ACKs a read byte, so the pointer owner can advance.
//------------------------------------------------------------------------------
module i2c_slave #(
    parameter [6:0] ADDR = 7'h42
) (
    input  wire       clk,
    input  wire       rst_n,
    input  wire       scl_i,
    input  wire       sda_i,
    output reg        sda_oe,
    output reg        rx_valid,
    output reg  [7:0] rx_data,
    output reg        rx_first,
    output reg        tx_next,
    input  wire [7:0] tx_data
);
    reg [2:0] sda_sy, scl_sy;
    wire sda_s = sda_sy[1], scl_s = scl_sy[1];
    wire sda_p = sda_sy[2], scl_p = scl_sy[2];
    wire scl_rise  =  scl_s & ~scl_p;
    wire scl_fall  = ~scl_s &  scl_p;
    wire start_det =  scl_s &  scl_p &  sda_p & ~sda_s;
    wire stop_det  =  scl_s &  scl_p & ~sda_p &  sda_s;

    localparam [2:0] ST_IDLE = 3'd0, ST_ADDR = 3'd1, ST_RX = 3'd2, ST_TX = 3'd3, ST_WAITSTOP = 3'd4;
    reg [2:0] st;
    reg [3:0] bitcnt;
    reg [7:0] sh, txb;
    reg       rw, ack_next, first_byte, m_ack;

    initial begin
        sda_sy = 3'b111; scl_sy = 3'b111; sda_oe = 1'b0; rx_valid = 1'b0; rx_data = 8'd0;
        rx_first = 1'b0; tx_next = 1'b0; st = ST_IDLE; bitcnt = 4'd0; sh = 8'd0; txb = 8'd0;
        rw = 1'b0; ack_next = 1'b0; first_byte = 1'b0; m_ack = 1'b0;
    end

    always @(posedge clk) begin
        sda_sy   <= {sda_sy[1:0], sda_i};
        scl_sy   <= {scl_sy[1:0], scl_i};
        rx_valid <= 1'b0;
        tx_next  <= 1'b0;

        if (!rst_n) begin
            st <= ST_IDLE; sda_oe <= 1'b0; bitcnt <= 4'd0;
        end else if (start_det) begin
            st <= ST_ADDR; bitcnt <= 4'd0; sda_oe <= 1'b0; sh <= 8'd0;
        end else if (stop_det) begin
            st <= ST_IDLE; bitcnt <= 4'd0; sda_oe <= 1'b0;
        end else begin
            case (st)
            // ------------------------------------------- receive a byte
            ST_ADDR, ST_RX: begin
                if (scl_rise) begin
                    if (bitcnt < 4'd8) begin
                        sh     <= {sh[6:0], sda_s};
                        bitcnt <= bitcnt + 4'd1;
                        if (bitcnt == 4'd7) begin
                            if (st == ST_ADDR) begin
                                ack_next <= (sh[6:0] == ADDR);
                                rw       <= sda_s;
                            end else begin
                                rx_valid   <= 1'b1;
                                rx_data    <= {sh[6:0], sda_s};
                                rx_first   <= first_byte;
                                first_byte <= 1'b0;
                                ack_next   <= 1'b1;
                            end
                        end
                    end else begin
                        bitcnt <= 4'd9;                         // 9th (ACK) clock
                    end
                end
                if (scl_fall) begin
                    if (bitcnt == 4'd8) begin
                        if (ack_next) sda_oe <= 1'b1;           // ACK: pull SDA low
                    end else if (bitcnt == 4'd9) begin
                        sda_oe <= 1'b0;
                        bitcnt <= 4'd0;
                        if (st == ST_ADDR) begin
                            if (!ack_next) st <= ST_WAITSTOP;
                            else if (rw) begin
                                txb    <= tx_data;
                                sda_oe <= ~tx_data[7];          // first data bit
                                bitcnt <= 4'd1;
                                st     <= ST_TX;
                            end else begin
                                first_byte <= 1'b1;
                                st <= ST_RX;
                            end
                        end
                    end
                end
            end
            // ------------------------------------------- transmit a byte
            ST_TX: begin
                if (scl_fall) begin
                    if (bitcnt < 4'd8) begin
                        sda_oe <= ~txb[3'd7 - bitcnt[2:0]];
                        bitcnt <= bitcnt + 4'd1;
                    end else if (bitcnt == 4'd8) begin
                        sda_oe <= 1'b0;                         // release for master ACK/NACK
                        bitcnt <= 4'd9;
                    end else if (bitcnt == 4'd10) begin
                        if (m_ack) begin
                            txb    <= tx_data;
                            sda_oe <= ~tx_data[7];
                            bitcnt <= 4'd1;
                        end else begin
                            sda_oe <= 1'b0;
                            st     <= ST_WAITSTOP;
                        end
                    end
                end
                if (scl_rise && bitcnt == 4'd9) begin
                    m_ack   <= ~sda_s;                          // master pulls low = ACK
                    tx_next <= ~sda_s;
                    bitcnt  <= 4'd10;
                end
            end
            default: ;                                          // IDLE / WAITSTOP
            endcase
        end
    end
endmodule
