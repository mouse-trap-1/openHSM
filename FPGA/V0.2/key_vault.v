`timescale 1ns/1ps
//------------------------------------------------------------------------------
// key_vault : holds the private key, zeroizes it on tamper, mirrors it to the
//             module's non-volatile key store
//
//   * `tamper` is ASYNCHRONOUS and active-high.  It clears the key register and
//     the valid flag immediately, even if the clock is stopped or glitched, and
//     asserts `nvm_erase` combinationally so the non-volatile store is wiped too.
//   * `tamper_latched` stays set until reset.  While it is set, loads and boot
//     restores are refused.  (Policy choice: if you want a *permanent* lock after
//     tamper, store a "tampered" flag in the NVM and gate the boot restore on it.)
//   * The key never leaves this module except to the signer core (d_q) and to the
//     NVM write bus for the single cycle `nvm_we` is high (the bus is forced to
//     zero otherwise).  There is no read-out path to the I2C interface.
//   * Non-volatile store interface (map this to your hardware):
//        nvm_we / nvm_wdata : store a new key (1-cycle write)
//        nvm_erase          : level; erase/zeroize the stored key while high
//        nvm_rvalid/rdata   : stored key, continuously presented (valid = key present)
//     Typical implementations: battery-backed SRAM that is zeroized by the tamper
//     circuit, FRAM/EEPROM inside a tamper-protected enclosure, or a secure element.
//------------------------------------------------------------------------------
module key_vault (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         tamper,
    input  wire         load,
    input  wire [255:0] d_new,
    input  wire         erase,
    output reg  [255:0] d_q,
    output reg          valid,
    output reg          tamper_latched,
    output reg          nvm_we,
    output wire [255:0] nvm_wdata,
    output wire         nvm_erase,
    input  wire         nvm_rvalid,
    input  wire [255:0] nvm_rdata
);
    reg [5:0] erase_cnt;
    reg       boot;

    assign nvm_wdata = nvm_we ? d_q : 256'd0;
    assign nvm_erase = tamper | tamper_latched | (erase_cnt != 6'd0);

    initial begin
        d_q = 256'd0; valid = 1'b0; tamper_latched = 1'b0; nvm_we = 1'b0;
        erase_cnt = 6'd0; boot = 1'b0;
    end

    always @(posedge clk or posedge tamper) begin
        if (tamper) begin
            d_q <= 256'd0; valid <= 1'b0; tamper_latched <= 1'b1;
            nvm_we <= 1'b0; erase_cnt <= 6'd0; boot <= 1'b0;
        end else if (!rst_n) begin
            d_q <= 256'd0; valid <= 1'b0; tamper_latched <= 1'b0;
            nvm_we <= 1'b0; erase_cnt <= 6'd0; boot <= 1'b1;
        end else begin
            nvm_we <= 1'b0;
            if (erase_cnt != 6'd0) erase_cnt <= erase_cnt - 6'd1;
            if (boot) begin                                   // restore after power-up
                boot <= 1'b0;
                if (!tamper_latched && nvm_rvalid) begin
                    d_q <= nvm_rdata; valid <= 1'b1;
                end
            end
            if (load && !tamper_latched) begin                // new key
                d_q <= d_new; valid <= 1'b1; nvm_we <= 1'b1;
            end
            if (erase) begin                                  // explicit erase
                d_q <= 256'd0; valid <= 1'b0; erase_cnt <= 6'd32;
            end
        end
    end
endmodule
