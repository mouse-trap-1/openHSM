`timescale 1ns/1ps
//------------------------------------------------------------------------------
// spi_secret_rx : SPI mode-0 slave that receives one 33-byte frame from the
//                 tamper MCU:  0xA5 || S[255:0]   (MSB first)
//
//   * a frame with a wrong length or wrong header byte is discarded
//   * `s_valid` pulses for one cycle after chip-select rises on a good frame
//   * `s_data` holds S until `clear` or `wipe` (the consumer should pulse
//     `clear` as soon as it has taken S)
//   * clk must be at least 4x faster than sclk (inputs are 2-FF synchronised)
//   There is no MISO: the FPGA never talks back on this link.
//------------------------------------------------------------------------------
module spi_secret_rx (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         wipe,
    input  wire         clear,
    input  wire         sclk,
    input  wire         cs_n,
    input  wire         mosi,
    output reg          s_valid,
    output wire [255:0] s_data
);
    reg [2:0] sck_sy, cs_sy, mo_sy;
    reg [263:0] sh;
    reg [9:0]  cnt;
    reg        busy_frame;

    assign s_data = sh[255:0];

    initial begin
        sck_sy = 3'b000; cs_sy = 3'b111; mo_sy = 3'b000; sh = 264'd0; cnt = 10'd0;
        s_valid = 1'b0; busy_frame = 1'b0;
    end

    wire sck_rise = (sck_sy[2:1] == 2'b01);
    wire cs_fall  = (cs_sy[2:1]  == 2'b10);
    wire cs_rise  = (cs_sy[2:1]  == 2'b01);

    always @(posedge clk) begin
        sck_sy <= {sck_sy[1:0], sclk};
        cs_sy  <= {cs_sy[1:0],  cs_n};
        mo_sy  <= {mo_sy[1:0],  mosi};
        s_valid <= 1'b0;
        if (wipe || !rst_n || clear) begin
            sh <= 264'd0; cnt <= 10'd0; busy_frame <= 1'b0;
        end else begin
            if (cs_fall) begin cnt <= 10'd0; busy_frame <= 1'b1; end
            if (busy_frame && !cs_sy[1] && sck_rise) begin
                sh  <= {sh[262:0], mo_sy[1]};
                if (cnt != 10'h3FF) cnt <= cnt + 10'd1;
            end
            if (cs_rise && busy_frame) begin
                busy_frame <= 1'b0;
                if (cnt == 10'd264 && sh[263:256] == 8'hA5) s_valid <= 1'b1;
                else begin sh <= 264'd0; cnt <= 10'd0; end        // bad frame: discard
            end
        end
    end
endmodule
