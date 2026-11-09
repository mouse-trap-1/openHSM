`timescale 1ns/1ps
//------------------------------------------------------------------------------
// secp256k1_hsm_top : secp256k1 signing module with on-chip key generation,
//                     key storage, tamper zeroization and an I2C slave interface
//
//   The private key is generated inside the module from the on-chip TRNG, stored
//   in the key vault (+ non-volatile store) and used only by the signer.  There is
//   no command and no register that reads it out.
//
//   I2C register map (7-bit slave address I2C_ADDR, pointer protocol, big-endian
//   multi-byte values, pointer auto-increments)
//
//     0x00  STATUS   R   b0 busy  b1 done  b2 error  b3 key_present  b4 tamper
//                        b5 trng_fail  b6 awaiting_confirm
//     0x01  CMD      W   0x01 GENKEY   generate a new key (only if none present)
//                        0x02 SIGN     sign the digest in HASH
//                        0x03 PUBKEY   compute public key into PUBX/PUBY
//                        0x04 CANCEL   abort the running command
//                        0x05 ERASE    erase the key (irreversible)
//     0x02  ERROR    R   0 ok, 2 no key, 3 key exists, 4 TRNG failure,
//                        5 confirm timeout, 6 signing failed, 7 tamper,
//                        8 bad command, 9 cancelled
//     0x10  HASH     W/R 32 bytes  message digest to sign (0x10..0x2F)
//     0x30  SIG_R    R   32 bytes  (0x30..0x4F)
//     0x50  SIG_S    R   32 bytes  (0x50..0x6F)  low-s normalised
//     0x70  PUB_X    R   32 bytes  (0x70..0x8F)
//     0x90  PUB_Y    R   32 bytes  (0x90..0xAF)
//     0xFF  VERSION  R   0xA1
//
//   Physical presence: when REQUIRE_CONFIRM = 1, GENKEY, SIGN and ERASE wait for the
//   `confirm` input (user button, active-high, debounced externally) and time out
//   after CONFIRM_TIMEOUT clocks.  This stops a compromised host from signing
//   silently.  The module signs the 32-byte digest it is given: it cannot show the
//   user what is being signed (see README notes on blind signing).
//
//   Tamper: `tamper` (async, active-high) zeroizes the key immediately, wipes every
//   datapath register and locks the module until reset.
//------------------------------------------------------------------------------
module secp256k1_hsm_top #(
    parameter [6:0]  I2C_ADDR        = 7'h42,
    parameter        REQUIRE_CONFIRM = 1,
    parameter [31:0] CONFIRM_TIMEOUT = 32'd3_000_000_000,   // ~30 s at 100 MHz
    parameter        SIM_TRNG        = 0,                   // 1 = NOT RANDOM, simulation only
    parameter        TRNG_DIV        = 32
) (
    input  wire         clk,
    input  wire         rst_n,
    // I2C (open drain: sda_oe = 1 pulls SDA low)
    input  wire         scl_i,
    input  wire         sda_i,
    output wire         sda_oe,
    // security
    input  wire         tamper,
    input  wire         confirm,
    // non-volatile key store (see key_vault.v)
    output wire         nvm_we,
    output wire [255:0] nvm_wdata,
    output wire         nvm_erase,
    input  wire         nvm_rvalid,
    input  wire [255:0] nvm_rdata,
    // indicators
    output wire         led_busy,
    output wire         led_key,
    output wire         led_tamper
);
    localparam [255:0] N = 256'hFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    localparam [7:0] CMD_GENKEY = 8'h01, CMD_SIGN = 8'h02, CMD_PUBKEY = 8'h03,
                     CMD_CANCEL = 8'h04, CMD_ERASE = 8'h05;
    localparam [3:0] E_OK = 4'd0, E_NO_KEY = 4'd2, E_KEY_EXISTS = 4'd3, E_TRNG = 4'd4,
                     E_CONFIRM = 4'd5, E_SIGN = 4'd6, E_TAMPER = 4'd7, E_BAD_CMD = 4'd8,
                     E_CANCEL = 4'd9;

    // ------------------------------------------------------ synchronisers --
    reg [1:0] tamper_sy;                       // async assert, synchronous release
    always @(posedge clk or posedge tamper) begin
        if (tamper) tamper_sy <= 2'b11; else tamper_sy <= {tamper_sy[0], 1'b0};
    end
    wire tamper_s = tamper_sy[1];
    reg [1:0] confirm_sy;
    always @(posedge clk) confirm_sy <= {confirm_sy[0], confirm};
    wire confirm_s = confirm_sy[1];

    // -------------------------------------------------------- state ---------
    localparam [4:0]
        C_IDLE = 5'd0,  C_CONFIRM = 5'd1,
        C_G_ENT0 = 5'd2, C_G_ENT1 = 5'd3, C_G_HM_GO = 5'd4, C_G_HM_WAIT = 5'd5,
        C_G_CHK = 5'd6,  C_G_CLR = 5'd7,
        C_S_ENT = 5'd8,  C_S_NONCE_GO = 5'd9,  C_S_NONCE_WAIT = 5'd10,
        C_S_CORE_GO = 5'd11, C_S_CORE_WAIT = 5'd12,
        C_P_CORE_GO = 5'd13, C_P_CORE_WAIT = 5'd14,
        C_ERASE = 5'd15;

    reg [4:0]   st;
    reg [7:0]   pend, cmd_b, ptr;
    reg         cmd_v;
    reg [31:0]  timer;
    reg         done_flag;
    reg [3:0]   err_code;
    reg         scrub;
    reg [255:0] hash_reg, r_reg, s_reg, px_reg, py_reg;
    reg [255:0] entA, entB, ent_extra, d_cand, k_reg;
    reg         use_extra, gen_hm_start, rfc_start, core_start, core_mode, v_load, v_erase;

    wire tamper_latched;
    wire wipe_dp = tamper_s | tamper_latched | scrub;

    // -------------------------------------------------------- key vault ----
    wire [255:0] vault_d;
    wire         key_valid;
    key_vault u_vault (
        .clk(clk), .rst_n(rst_n), .tamper(tamper),
        .load(v_load), .d_new(d_cand), .erase(v_erase),
        .d_q(vault_d), .valid(key_valid), .tamper_latched(tamper_latched),
        .nvm_we(nvm_we), .nvm_wdata(nvm_wdata), .nvm_erase(nvm_erase),
        .nvm_rvalid(nvm_rvalid), .nvm_rdata(nvm_rdata)
    );

    // ------------------------------------------------------------ TRNG -----
    wire        trng_en    = (st == C_G_ENT0) || (st == C_G_ENT1) || (st == C_S_ENT);
    wire        trng_valid, trng_fail;
    wire [255:0] trng_word;
    wire        trng_ack   = trng_valid && trng_en;       // combinational: consumes the word
    trng_ro #(.SIM_MODEL(SIM_TRNG), .SAMPLE_DIV(TRNG_DIV)) u_trng (
        .clk(clk), .rst_n(rst_n), .enable(trng_en), .ack(trng_ack),
        .word_valid(trng_valid), .word(trng_word), .health_fail(trng_fail)
    );

    // ------------------------------------- shared HMAC + nonce generator ---
    wire         rfc_hm_start;
    wire [255:0] rfc_hm_key;
    wire [1535:0] rfc_hm_msg;
    wire [7:0]   rfc_hm_len;
    wire         sel_gen = (st == C_G_HM_GO) || (st == C_G_HM_WAIT);
    wire         hm_start_w = sel_gen ? gen_hm_start : rfc_hm_start;
    wire [255:0] hm_key_w   = sel_gen ? entA : rfc_hm_key;
    wire [1535:0] hm_msg_w  = sel_gen ? {entB, 1280'd0} : rfc_hm_msg;
    wire [7:0]   hm_len_w   = sel_gen ? 8'd32 : rfc_hm_len;
    wire         hm_busy, hm_done;
    wire [255:0] hm_mac;
    hmac_sha256 u_hmac (.clk(clk), .wipe(wipe_dp), .start(hm_start_w), .key(hm_key_w),
                        .msg(hm_msg_w), .msg_len(hm_len_w), .busy(hm_busy), .done(hm_done), .mac(hm_mac));

    wire         rfc_busy, rfc_done;
    wire [255:0] rfc_k;
    rfc6979_nonce u_rfc (.clk(clk), .wipe(wipe_dp), .start(rfc_start), .x(vault_d), .h1(hash_reg),
                         .extra(ent_extra), .use_extra(use_extra), .busy(rfc_busy), .done(rfc_done),
                         .k(rfc_k), .hm_start(rfc_hm_start), .hm_key(rfc_hm_key), .hm_msg(rfc_hm_msg),
                         .hm_len(rfc_hm_len), .hm_done(hm_done), .hm_mac(hm_mac));

    // -------------------------------------------------------- signer core --
    wire         core_busy, core_done, core_fail;
    wire [255:0] core_r, core_s, core_px, core_py;
    ecdsa_secp256k1_sign #(.LOW_S(1)) u_core (
        .clk(clk), .rst_n(rst_n), .wipe(wipe_dp), .start(core_start), .mode_pub(core_mode),
        .d_in(vault_d), .k_in(core_mode ? vault_d : k_reg), .z_in(hash_reg),
        .busy(core_busy), .done(core_done), .fail(core_fail),
        .r_out(core_r), .s_out(core_s), .px_out(core_px), .py_out(core_py)
    );

    // ------------------------------------------------------------- I2C -----
    wire       rx_valid, rx_first, tx_next;
    wire [7:0] rx_data;
    reg  [7:0] tx_byte;
    i2c_slave #(.ADDR(I2C_ADDR)) u_i2c (
        .clk(clk), .rst_n(rst_n), .scl_i(scl_i), .sda_i(sda_i), .sda_oe(sda_oe),
        .rx_valid(rx_valid), .rx_data(rx_data), .rx_first(rx_first),
        .tx_next(tx_next), .tx_data(tx_byte)
    );

    wire [7:0] status = {1'b0, (st == C_CONFIRM), trng_fail, tamper_latched, key_valid,
                         (err_code != 4'd0), done_flag, (st != C_IDLE)};

    always @(*) begin
        tx_byte = 8'h00;
        if      (ptr == 8'h00) tx_byte = status;
        else if (ptr == 8'h02) tx_byte = {4'd0, err_code};
        else if (ptr == 8'hFF) tx_byte = 8'hA1;
        else if (ptr >= 8'h10 && ptr < 8'h30) tx_byte = hash_reg[255 - 8*(ptr - 8'h10) -: 8];
        else if (ptr >= 8'h30 && ptr < 8'h50) tx_byte = r_reg [255 - 8*(ptr - 8'h30) -: 8];
        else if (ptr >= 8'h50 && ptr < 8'h70) tx_byte = s_reg [255 - 8*(ptr - 8'h50) -: 8];
        else if (ptr >= 8'h70 && ptr < 8'h90) tx_byte = px_reg[255 - 8*(ptr - 8'h70) -: 8];
        else if (ptr >= 8'h90 && ptr < 8'hB0) tx_byte = py_reg[255 - 8*(ptr - 8'h90) -: 8];
    end

    assign led_busy   = (st != C_IDLE);
    assign led_key    = key_valid;
    assign led_tamper = tamper_latched;

    // ------------------------------------------------------ sequencer ------
    function [4:0] first_st(input [7:0] c);
        case (c)
            CMD_GENKEY: first_st = C_G_ENT0;
            CMD_SIGN:   first_st = C_S_ENT;
            default:    first_st = C_ERASE;
        endcase
    endfunction

    task fin(input [3:0] e);
        begin
            st <= C_IDLE; done_flag <= 1'b1; err_code <= e; scrub <= 1'b1;
            k_reg <= 256'd0; ent_extra <= 256'd0;
        end
    endtask

    initial begin
        st = C_IDLE; pend = 8'd0; cmd_b = 8'd0; ptr = 8'd0; cmd_v = 1'b0; timer = 32'd0;
        done_flag = 1'b0; err_code = 4'd0; scrub = 1'b0;
        hash_reg = 256'd0; r_reg = 256'd0; s_reg = 256'd0; px_reg = 256'd0; py_reg = 256'd0;
        entA = 256'd0; entB = 256'd0; ent_extra = 256'd0; d_cand = 256'd0; k_reg = 256'd0;
        use_extra = 1'b0; gen_hm_start = 1'b0; rfc_start = 1'b0; core_start = 1'b0;
        core_mode = 1'b0; v_load = 1'b0; v_erase = 1'b0; confirm_sy = 2'b00; tamper_sy = 2'b00;
    end

    always @(posedge clk) begin
        scrub <= 1'b0; gen_hm_start <= 1'b0; rfc_start <= 1'b0;
        core_start <= 1'b0; v_load <= 1'b0; v_erase <= 1'b0;

        if (!rst_n) begin
            st <= C_IDLE; cmd_v <= 1'b0; ptr <= 8'd0; done_flag <= 1'b0; err_code <= 4'd0;
            hash_reg <= 256'd0; r_reg <= 256'd0; s_reg <= 256'd0; px_reg <= 256'd0; py_reg <= 256'd0;
            entA <= 256'd0; entB <= 256'd0; ent_extra <= 256'd0; d_cand <= 256'd0; k_reg <= 256'd0;
        end else begin
            // ---------------- I2C register access ----------------
            if (rx_valid) begin
                if (rx_first) ptr <= rx_data;
                else begin
                    ptr <= ptr + 8'd1;
                    if (ptr == 8'h01) begin cmd_v <= 1'b1; cmd_b <= rx_data; end
                    else if (ptr >= 8'h10 && ptr < 8'h30 && st == C_IDLE && !tamper_latched)
                        hash_reg[255 - 8*(ptr - 8'h10) -: 8] <= rx_data;
                end
            end
            if (tx_next) ptr <= ptr + 8'd1;

            // ---------------- tamper: wipe everything, lock ----------------
            if (tamper_s || tamper_latched) begin
                st <= C_IDLE; cmd_v <= 1'b0;
                hash_reg <= 256'd0; r_reg <= 256'd0; s_reg <= 256'd0; px_reg <= 256'd0; py_reg <= 256'd0;
                entA <= 256'd0; entB <= 256'd0; ent_extra <= 256'd0; d_cand <= 256'd0; k_reg <= 256'd0;
                err_code <= E_TAMPER; done_flag <= 1'b1;
            end else begin
                // ---------------- command dispatch ----------------
                if (cmd_v) begin
                    cmd_v <= 1'b0;
                    if (st != C_IDLE) begin
                        if (cmd_b == CMD_CANCEL) fin(E_CANCEL);          // other commands ignored while busy
                    end else begin
                        done_flag <= 1'b0; err_code <= 4'd0;
                        pend <= cmd_b; timer <= 32'd0;
                        case (cmd_b)
                            CMD_GENKEY: begin
                                if (key_valid)      fin(E_KEY_EXISTS);
                                else if (trng_fail) fin(E_TRNG);
                                else st <= (REQUIRE_CONFIRM != 0) ? C_CONFIRM : first_st(cmd_b);
                            end
                            CMD_SIGN: begin
                                if (!key_valid) fin(E_NO_KEY);
                                else st <= (REQUIRE_CONFIRM != 0) ? C_CONFIRM : first_st(cmd_b);
                            end
                            CMD_PUBKEY: begin
                                if (!key_valid) fin(E_NO_KEY); else st <= C_P_CORE_GO;
                            end
                            CMD_ERASE: st <= (REQUIRE_CONFIRM != 0) ? C_CONFIRM : first_st(cmd_b);
                            CMD_CANCEL: ;                                 // nothing running
                            default: fin(E_BAD_CMD);
                        endcase
                    end
                end

                // ---------------- state machine ----------------
                case (st)
                C_CONFIRM: begin
                    if (confirm_s) st <= first_st(pend);
                    else if (timer >= CONFIRM_TIMEOUT) fin(E_CONFIRM);
                    else timer <= timer + 32'd1;
                end

                // --- key generation: 2 x 256 raw-conditioned bits -> HMAC extractor -> d
                C_G_ENT0: begin
                    if (trng_valid) begin entA <= trng_word; st <= C_G_ENT1; end
                    else if (trng_fail) fin(E_TRNG);
                end
                C_G_ENT1: begin
                    if (trng_valid) begin entB <= trng_word; st <= C_G_HM_GO; end
                    else if (trng_fail) fin(E_TRNG);
                end
                C_G_HM_GO:   begin gen_hm_start <= 1'b1; st <= C_G_HM_WAIT; end
                C_G_HM_WAIT: if (hm_done) begin d_cand <= hm_mac; st <= C_G_CHK; end
                C_G_CHK: begin
                    if (d_cand != 256'd0 && d_cand < N) begin v_load <= 1'b1; st <= C_G_CLR; end
                    else st <= C_G_ENT0;                                  // out of range: draw again
                end
                C_G_CLR: begin
                    entA <= 256'd0; entB <= 256'd0; d_cand <= 256'd0;
                    r_reg <= 256'd0; s_reg <= 256'd0; px_reg <= 256'd0; py_reg <= 256'd0;
                    fin(E_OK);
                end

                // --- signing: hedged RFC 6979 nonce, then the signer core
                C_S_ENT: begin
                    if (trng_valid)     begin ent_extra <= trng_word; use_extra <= 1'b1; st <= C_S_NONCE_GO; end
                    else if (trng_fail) begin ent_extra <= 256'd0;    use_extra <= 1'b0; st <= C_S_NONCE_GO; end
                end
                C_S_NONCE_GO:   begin rfc_start <= 1'b1; st <= C_S_NONCE_WAIT; end
                C_S_NONCE_WAIT: if (rfc_done) begin k_reg <= rfc_k; st <= C_S_CORE_GO; end
                C_S_CORE_GO:    begin core_mode <= 1'b0; core_start <= 1'b1; st <= C_S_CORE_WAIT; end
                C_S_CORE_WAIT:  if (core_done) begin
                    if (core_fail) fin(E_SIGN);
                    else begin r_reg <= core_r; s_reg <= core_s; fin(E_OK); end
                end

                // --- public key
                C_P_CORE_GO:   begin core_mode <= 1'b1; core_start <= 1'b1; st <= C_P_CORE_WAIT; end
                C_P_CORE_WAIT: if (core_done) begin
                    if (core_fail) fin(E_SIGN);
                    else begin px_reg <= core_px; py_reg <= core_py; fin(E_OK); end
                end

                // --- erase
                C_ERASE: begin
                    v_erase <= 1'b1;
                    r_reg <= 256'd0; s_reg <= 256'd0; px_reg <= 256'd0; py_reg <= 256'd0;
                    fin(E_OK);
                end
                default: ;
                endcase
            end
        end
    end
endmodule
