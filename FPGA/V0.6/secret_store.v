`timescale 1ns/1ps
//------------------------------------------------------------------------------
// secret_store : the only long-lived secrets in the stateless node, all volatile
//
//     chan_key  : command-channel MAC key   = HMAC(S, "SN-CHAN")
//     seal_key  : local KEK-sealing key     = HMAC(S, "SN-SEAL")
//     kek       : cluster key-encryption key (wraps every wallet key)
//     enrol_d   : ECIES enrolment private key (only during node enrolment)
//
//   `tamper` is ASYNCHRONOUS and active-high: it zeroes every register at once,
//   even with the clock stopped.  `tamper_latched` holds until reset and blocks
//   all loads.  Nothing here is ever written to non-volatile memory: a power cycle
//   or tamper event destroys the KEK, and only S (from the tamper MCU) + the sealed
//   blob kept by the SoC can rebuild it.
//------------------------------------------------------------------------------
module secret_store (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         tamper,
    input  wire         soft_clear,       // synchronous clear of everything (e.g. operator wipe)
    input  wire [255:0] d_in,
    input  wire         ld_chan, ld_seal, ld_kek, ld_enrol, ld_kek2,
    input  wire         clr_kek, clr_enrol, clr_kek2,
    output reg  [255:0] chan_key,
    output reg  [255:0] seal_key,
    output reg  [255:0] kek,
    output reg  [255:0] enrol_d,
    output reg  [255:0] kek2,             // incoming KEK during rotation
    output reg          keys_valid,       // chan_key + seal_key loaded
    output reg          kek_valid,
    output reg          kek2_valid,
    output reg          enrol_valid,
    output reg          tamper_latched
);
    initial begin
        chan_key = 256'd0; seal_key = 256'd0; kek = 256'd0; enrol_d = 256'd0; kek2 = 256'd0; kek2_valid = 1'b0;
        keys_valid = 1'b0; kek_valid = 1'b0; enrol_valid = 1'b0; tamper_latched = 1'b0;
    end

    always @(posedge clk or posedge tamper) begin
        if (tamper) begin
            chan_key <= 256'd0; seal_key <= 256'd0; kek <= 256'd0; enrol_d <= 256'd0; kek2 <= 256'd0; kek2_valid <= 1'b0;
            keys_valid <= 1'b0; kek_valid <= 1'b0; enrol_valid <= 1'b0; tamper_latched <= 1'b1;
        end else if (!rst_n) begin
            chan_key <= 256'd0; seal_key <= 256'd0; kek <= 256'd0; enrol_d <= 256'd0; kek2 <= 256'd0; kek2_valid <= 1'b0;
            keys_valid <= 1'b0; kek_valid <= 1'b0; enrol_valid <= 1'b0; tamper_latched <= 1'b0;
        end else if (soft_clear) begin
            chan_key <= 256'd0; seal_key <= 256'd0; kek <= 256'd0; enrol_d <= 256'd0; kek2 <= 256'd0; kek2_valid <= 1'b0;
            keys_valid <= 1'b0; kek_valid <= 1'b0; enrol_valid <= 1'b0;
        end else if (!tamper_latched) begin
            if (ld_chan)  chan_key <= d_in;
            if (ld_seal)  begin seal_key <= d_in; keys_valid <= 1'b1; end
            if (ld_kek)   begin kek <= d_in; kek_valid <= 1'b1; end
            if (ld_enrol) begin enrol_d <= d_in; enrol_valid <= 1'b1; end
            if (ld_kek2)  begin kek2 <= d_in; kek2_valid <= 1'b1; end
            if (clr_kek2) begin kek2 <= 256'd0; kek2_valid <= 1'b0; end
            if (clr_kek)   begin kek <= 256'd0; kek_valid <= 1'b0; end
            if (clr_enrol) begin enrol_d <= 256'd0; enrol_valid <= 1'b0; end
        end
    end
endmodule
