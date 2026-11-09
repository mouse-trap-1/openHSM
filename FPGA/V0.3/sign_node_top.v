`timescale 1ns/1ps
//------------------------------------------------------------------------------
// sign_node_top : stateless secp256k1 signing node (drop-in for the SE050 slot)
//
//   * No wallet key is stored.  Each wallet key lives outside as an AES-256-GCM
//     blob wrapped under the cluster KEK (AAD = wallet id).  The FPGA unwraps it,
//     signs, and wipes.  The KEK exists only in volatile registers (secret_store).
//   * S (256 bit) arrives from the tamper MCU over SPI after every boot and derives
//         chan_key = HMAC(S,"SN-CHAN")   (authenticates every I2C command)
//         seal_key = HMAC(S,"SN-SEAL")   (seals the KEK for the SoC to keep on NVMe)
//     No S => no session => no command is accepted.  Tamper wipes everything.
//   * Cluster KEK can be moved to a new node with ECIES (enrolment key + ECDH).
//
//   I2C register map (7-bit address I2C_ADDR, 8-bit pointer, big-endian, auto-increment)
//     0x00 STATUS  R  b0 busy b1 done b2 error b3 kek b4 tamper b5 trng_fail b6 session b7 enrol_key
//     0x01 CMD     W  (writing it starts the command)
//     0x02 ERROR   R
//     0x04 CTR     W  4 bytes, must strictly increase within a session
//     0x08 NONCE   R  16 bytes, fresh random per session (bind into every MAC)
//     0x18 WID     W  16 bytes wallet id (AAD of the wrapped key)
//     0x28 IV      R/W 12 bytes
//     0x34 TAG     R/W 16 bytes
//     0x44 BUF_A   R/W 32 bytes   wrapped key / ciphertext / sig r / pub x
//     0x64 BUF_B   R/W 32 bytes   digest / sig s / pub y / point x
//     0x84 BUF_C   R/W 32 bytes   point y
//     0xA4 MAC     W  32 bytes   HMAC-SHA256(chan_key, nonce||ctr||cmd||wid||iv||tag||A||B||C)
//     0xFF VERSION R  0xB1
//   Registers may only be written while idle.
//
//   Commands (all MAC-authenticated)
//     0x10 KEK_GEN     new random KEK (only if none loaded)
//     0x11 KEK_SEAL    out: IV, TAG, A = KEK sealed under seal_key
//     0x12 KEK_UNSEAL  in : IV, TAG, A (sealed blob)  -> loads KEK
//     0x13 KEK_ERASE   wipe KEK and enrolment key
//     0x20 GEN_WALLET  in : WID   out: IV, TAG, A = wrapped key, B/C = public key
//     0x21 SIGN        in : WID, IV, TAG, A = wrapped key, B = digest   out: A = r, B = s
//     0x22 PUBKEY      in : WID, IV, TAG, A                                out: A = x, B = y
//     0x40 ENROL_GEN   out: B/C = enrolment public key
//     0x41 KEK_EXPORT  in : B/C = recipient enrolment public key
//                      out: IV, TAG, A = ciphertext, B/C = ephemeral public key T
//     0x42 KEK_IMPORT  in : IV, TAG, A = ciphertext, B/C = T  -> loads KEK
//------------------------------------------------------------------------------
module sign_node_top #(
    parameter [6:0] I2C_ADDR = 7'h48,
    parameter       SIM_TRNG = 0,           // 1 = NOT RANDOM, simulation only
    parameter       TRNG_DIV = 32
) (
    input  wire clk,
    input  wire rst_n,
    // I2C (open drain)
    input  wire scl_i,
    input  wire sda_i,
    output wire sda_oe,
    // SPI from the tamper MCU (receive only)
    input  wire spi_sclk,
    input  wire spi_cs_n,
    input  wire spi_mosi,
    // tamper (async, active high)
    input  wire tamper,
    output wire led_busy,
    output wire led_kek,
    output wire led_tamper
);
    localparam [255:0] N = 256'hFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    localparam [127:0] SEAL_AAD  = 128'h4b454b2d5345414c2d763100_00000000;   // "KEK-SEAL-v1"
    localparam [127:0] ECIES_AAD = 128'h4b454b2d45434945532d7631_00000000;   // "KEK-ECIES-v1"
    localparam [95:0]  ECIES_LBL = 96'h45434945532d4b454b2d7631;             // "ECIES-KEK-v1"
    localparam [55:0]  LBL_CHAN  = 56'h534e2d4348414e;                        // "SN-CHAN"
    localparam [55:0]  LBL_SEAL  = 56'h534e2d5345414c;                        // "SN-SEAL"

    localparam [7:0] CMD_KEK_GEN = 8'h10, CMD_KEK_SEAL = 8'h11, CMD_KEK_UNSEAL = 8'h12,
                     CMD_KEK_ERASE = 8'h13, CMD_GEN_WALLET = 8'h20, CMD_SIGN = 8'h21,
                     CMD_PUBKEY = 8'h22, CMD_ENROL_GEN = 8'h40, CMD_KEK_EXPORT = 8'h41,
                     CMD_KEK_IMPORT = 8'h42, CMD_SESSION = 8'hF0, CMD_AUTH = 8'hFE;
    localparam [3:0] E_OK = 4'd0, E_NOSESS = 4'd1, E_NOKEK = 4'd2, E_KEK_EXISTS = 4'd3,
                     E_TRNG = 4'd4, E_AUTH = 4'd5, E_SIGN = 4'd6, E_TAMPER = 4'd7,
                     E_BAD_CMD = 4'd8, E_UNWRAP = 4'd10, E_POINT = 4'd11, E_NOENROL = 4'd12;

    // ------------------------------------------------------ synchronisers --
    reg [1:0] tamper_sy;
    always @(posedge clk or posedge tamper) begin
        if (tamper) tamper_sy <= 2'b11; else tamper_sy <= {tamper_sy[0], 1'b0};
    end
    wire tamper_s = tamper_sy[1];

    // ---------------------------------------------------------- states ------
    localparam [5:0]
        ST_IDLE = 6'd0, ST_RUN = 6'd1,
        SB_RAND_E0 = 6'd2, SB_RAND_E1 = 6'd3, SB_RAND_CHK = 6'd4,
        SB_IVRAND = 6'd5, SB_TRNG1 = 6'd6,
        SB_HM_GO = 6'd7, SB_HM_WAIT = 6'd8,
        SB_GCM_GO = 6'd9, SB_GCM_WAIT = 6'd10,
        SB_CORE_GO = 6'd11, SB_CORE_WAIT = 6'd12,
        SB_NONCE_GO = 6'd13, SB_NONCE_WAIT = 6'd14,
        SB_PC_GO = 6'd15, SB_PC_WAIT = 6'd16;

    reg [5:0]  st;
    reg [7:0]  cmd, cmd_b, ptr;
    reg [4:0]  step;
    reg        cmd_v, done_flag, scrub, s_pending;
    reg [3:0]  err_code;

    // host-visible buffers
    reg [31:0]  ctr_in, last_ctr;
    reg [127:0] nonce, wid, tag_reg;
    reg [95:0]  iv_reg;
    reg [255:0] regA, regB, regC, mac_in;
    // working registers (scrubbed at the end of every command)
    reg [255:0] d_reg, k_reg, ent_extra, entA, cand, aux, kenc, hm_res, hm_key_r;
    reg [1535:0] hm_msg_r;
    reg [7:0]   hm_len_r;
    reg [255:0] ex_reg, ey_reg;                 // own enrolment public key (public data)
    reg         use_extra, hm_to_rand;
    // sub-engine control
    reg         hm_go, gcm_go, core_go, rfc_go, pc_go, core_mode, core_base, gdec;
    reg [1:0]   gsel_key, gsel_aad, gsel_din;
    reg [255:0] ss_din;
    reg         ld_chan, ld_seal, ld_kek, ld_enrol, clr_kek, clr_enrol;
    reg [255:0] pc_x, pc_y;

    wire tamper_latched;
    wire wipe_dp = tamper_s | tamper_latched | scrub;

    // --------------------------------------------------- secret store --------
    wire [255:0] chan_key, seal_key, kek, enrol_d;
    wire keys_valid, kek_valid, enrol_valid;
    secret_store u_ss (
        .clk(clk), .rst_n(rst_n), .tamper(tamper), .soft_clear(1'b0), .d_in(ss_din),
        .ld_chan(ld_chan), .ld_seal(ld_seal), .ld_kek(ld_kek), .ld_enrol(ld_enrol),
        .clr_kek(clr_kek), .clr_enrol(clr_enrol),
        .chan_key(chan_key), .seal_key(seal_key), .kek(kek), .enrol_d(enrol_d),
        .keys_valid(keys_valid), .kek_valid(kek_valid), .enrol_valid(enrol_valid),
        .tamper_latched(tamper_latched)
    );

    // --------------------------------------------------------- SPI ----------
    wire         spi_s_valid;
    wire [255:0] spi_s_data;
    reg          spi_clear;
    spi_secret_rx u_spi (.clk(clk), .rst_n(rst_n), .wipe(tamper_s | tamper_latched), .clear(spi_clear),
                         .sclk(spi_sclk), .cs_n(spi_cs_n), .mosi(spi_mosi),
                         .s_valid(spi_s_valid), .s_data(spi_s_data));

    // --------------------------------------------------------- TRNG ---------
    wire trng_en = (st == SB_RAND_E0) || (st == SB_RAND_E1) || (st == SB_IVRAND) || (st == SB_TRNG1);
    wire trng_valid, trng_fail;
    wire [255:0] trng_word;
    wire trng_ack = trng_valid && trng_en;
    trng_ro #(.SIM_MODEL(SIM_TRNG), .SAMPLE_DIV(TRNG_DIV)) u_trng (
        .clk(clk), .rst_n(rst_n), .enable(trng_en), .ack(trng_ack),
        .word_valid(trng_valid), .word(trng_word), .health_fail(trng_fail));

    // ------------------------------------------- shared HMAC + RFC 6979 ------
    wire          rfc_hm_start;
    wire [255:0]  rfc_hm_key;
    wire [1535:0] rfc_hm_msg;
    wire [7:0]    rfc_hm_len;
    wire sel_rfc = (st == SB_NONCE_GO) || (st == SB_NONCE_WAIT);
    wire          hm_start_w = sel_rfc ? rfc_hm_start : hm_go;
    wire [255:0]  hm_key_w   = sel_rfc ? rfc_hm_key : hm_key_r;
    wire [1535:0] hm_msg_w   = sel_rfc ? rfc_hm_msg : hm_msg_r;
    wire [7:0]    hm_len_w   = sel_rfc ? rfc_hm_len : hm_len_r;
    wire hm_busy, hm_done;
    wire [255:0] hm_mac;
    hmac_sha256 u_hmac (.clk(clk), .wipe(wipe_dp), .start(hm_start_w), .key(hm_key_w), .msg(hm_msg_w),
                        .msg_len(hm_len_w), .busy(hm_busy), .done(hm_done), .mac(hm_mac));

    wire rfc_busy, rfc_done;
    wire [255:0] rfc_k;
    rfc6979_nonce u_rfc (.clk(clk), .wipe(wipe_dp), .start(rfc_go), .x(d_reg), .h1(regB),
                         .extra(ent_extra), .use_extra(use_extra), .busy(rfc_busy), .done(rfc_done),
                         .k(rfc_k), .hm_start(rfc_hm_start), .hm_key(rfc_hm_key), .hm_msg(rfc_hm_msg),
                         .hm_len(rfc_hm_len), .hm_done(hm_done), .hm_mac(hm_mac));

    // ------------------------------------------------------ AES-GCM ----------
    wire [255:0] g_key = (gsel_key == 2'd0) ? kek : (gsel_key == 2'd1) ? seal_key : kenc;
    wire [127:0] g_aad = (gsel_aad == 2'd0) ? wid : (gsel_aad == 2'd1) ? SEAL_AAD : ECIES_AAD;
    wire [255:0] g_din = (gsel_din == 2'd0) ? d_reg : (gsel_din == 2'd1) ? kek : regA;
    wire gcm_busy, gcm_done, gcm_ok;
    wire [255:0] gcm_dout;
    wire [127:0] gcm_tag;
    aes_gcm32 u_gcm (.clk(clk), .wipe(wipe_dp), .start(gcm_go), .dec(gdec), .key(g_key), .iv(iv_reg),
                     .aad(g_aad), .din(g_din), .tag_in(tag_reg), .busy(gcm_busy), .done(gcm_done),
                     .dout(gcm_dout), .tag_out(gcm_tag), .auth_ok(gcm_ok));

    // ----------------------------------------------------- signer core -------
    wire core_busy, core_done, core_fail;
    wire [255:0] core_r, core_s, core_px, core_py;
    ecdsa_secp256k1_sign #(.LOW_S(1)) u_core (
        .clk(clk), .rst_n(rst_n), .wipe(wipe_dp), .start(core_go), .mode_pub(core_mode),
        .d_in(d_reg), .k_in(core_mode ? d_reg : k_reg), .z_in(regB),
        .use_base(core_base), .bx_in(regB), .by_in(regC),
        .busy(core_busy), .done(core_done), .fail(core_fail),
        .r_out(core_r), .s_out(core_s), .px_out(core_px), .py_out(core_py));

    // -------------------------------------------------- point validation -----
    wire pc_busy, pc_done, pc_valid;
    point_check u_pc (.clk(clk), .wipe(wipe_dp), .start(pc_go), .x(pc_x), .y(pc_y),
                      .busy(pc_busy), .done(pc_done), .valid(pc_valid));

    // ------------------------------------------------------------- I2C -------
    wire rx_valid, rx_first, tx_next;
    wire [7:0] rx_data;
    reg  [7:0] tx_byte;
    i2c_slave #(.ADDR(I2C_ADDR)) u_i2c (
        .clk(clk), .rst_n(rst_n), .scl_i(scl_i), .sda_i(sda_i), .sda_oe(sda_oe),
        .rx_valid(rx_valid), .rx_data(rx_data), .rx_first(rx_first),
        .tx_next(tx_next), .tx_data(tx_byte));

    wire [7:0] status = {enrol_valid, keys_valid, trng_fail, tamper_latched, kek_valid,
                         (err_code != 4'd0), done_flag, (st != ST_IDLE)};

    always @(*) begin
        tx_byte = 8'h00;
        if      (ptr == 8'h00) tx_byte = status;
        else if (ptr == 8'h02) tx_byte = {4'd0, err_code};
        else if (ptr == 8'hFF) tx_byte = 8'hB1;
        else if (ptr >= 8'h04 && ptr < 8'h08) tx_byte = ctr_in[31 - 8*(ptr - 8'h04) -: 8];
        else if (ptr >= 8'h08 && ptr < 8'h18) tx_byte = nonce  [127 - 8*(ptr - 8'h08) -: 8];
        else if (ptr >= 8'h18 && ptr < 8'h28) tx_byte = wid    [127 - 8*(ptr - 8'h18) -: 8];
        else if (ptr >= 8'h28 && ptr < 8'h34) tx_byte = iv_reg [95  - 8*(ptr - 8'h28) -: 8];
        else if (ptr >= 8'h34 && ptr < 8'h44) tx_byte = tag_reg[127 - 8*(ptr - 8'h34) -: 8];
        else if (ptr >= 8'h44 && ptr < 8'h64) tx_byte = regA   [255 - 8*(ptr - 8'h44) -: 8];
        else if (ptr >= 8'h64 && ptr < 8'h84) tx_byte = regB   [255 - 8*(ptr - 8'h64) -: 8];
        else if (ptr >= 8'h84 && ptr < 8'hA4) tx_byte = regC   [255 - 8*(ptr - 8'h84) -: 8];
    end

    assign led_busy   = (st != ST_IDLE);
    assign led_kek    = kek_valid;
    assign led_tamper = tamper_latched;

    // ---------------------------------------------------------- helpers -----
    task call(input [5:0] sub, input [4:0] nxt);
        begin st <= sub; step <= nxt; end
    endtask

    task fin(input [3:0] e);
        begin
            st <= ST_IDLE; done_flag <= 1'b1; err_code <= e; scrub <= 1'b1;
            d_reg <= 256'd0; k_reg <= 256'd0; ent_extra <= 256'd0; entA <= 256'd0; cand <= 256'd0;
            aux <= 256'd0; kenc <= 256'd0; hm_res <= 256'd0; hm_key_r <= 256'd0; hm_msg_r <= 1536'd0;
            hm_to_rand <= 1'b0; use_extra <= 1'b0;      // ss_din is cleared after the store has taken it
        end
    endtask

    task gcm_cfg(input [1:0] ks, input [1:0] as, input [1:0] ds, input dc);
        begin gsel_key <= ks; gsel_aad <= as; gsel_din <= ds; gdec <= dc; end
    endtask

    task hm_job(input [255:0] key, input [1535:0] msg, input [7:0] len);
        begin hm_key_r <= key; hm_msg_r <= msg; hm_len_r <= len; end
    endtask

    initial begin
        st = ST_IDLE; cmd = 8'd0; cmd_b = 8'd0; ptr = 8'd0; step = 5'd0; cmd_v = 1'b0; done_flag = 1'b0;
        scrub = 1'b0; s_pending = 1'b0; err_code = 4'd0; ctr_in = 32'd0; last_ctr = 32'd0; nonce = 128'd0;
        wid = 128'd0; tag_reg = 128'd0; iv_reg = 96'd0; regA = 256'd0; regB = 256'd0; regC = 256'd0;
        mac_in = 256'd0; d_reg = 256'd0; k_reg = 256'd0; ent_extra = 256'd0; entA = 256'd0; cand = 256'd0;
        aux = 256'd0; kenc = 256'd0; hm_res = 256'd0; hm_key_r = 256'd0; hm_msg_r = 1536'd0; hm_len_r = 8'd0;
        ex_reg = 256'd0; ey_reg = 256'd0; use_extra = 1'b0; hm_to_rand = 1'b0; hm_go = 1'b0; gcm_go = 1'b0;
        core_go = 1'b0; rfc_go = 1'b0; pc_go = 1'b0; core_mode = 1'b0; core_base = 1'b0; gdec = 1'b0;
        gsel_key = 2'd0; gsel_aad = 2'd0; gsel_din = 2'd0; ss_din = 256'd0; ld_chan = 1'b0; ld_seal = 1'b0;
        ld_kek = 1'b0; ld_enrol = 1'b0; clr_kek = 1'b0; clr_enrol = 1'b0; pc_x = 256'd0; pc_y = 256'd0;
        spi_clear = 1'b0; tamper_sy = 2'b00;
    end

    // -------------------------------------------------------- sequencer ------
    always @(posedge clk) begin
        scrub <= 1'b0; hm_go <= 1'b0; gcm_go <= 1'b0; core_go <= 1'b0; rfc_go <= 1'b0; pc_go <= 1'b0;
        ld_chan <= 1'b0; ld_seal <= 1'b0; ld_kek <= 1'b0; ld_enrol <= 1'b0; clr_kek <= 1'b0;
        clr_enrol <= 1'b0; spi_clear <= 1'b0;
        if (spi_s_valid) s_pending <= 1'b1;
        if (ld_chan | ld_seal | ld_kek | ld_enrol) ss_din <= 256'd0;   // store samples the old value this edge

        if (!rst_n) begin
            st <= ST_IDLE; cmd_v <= 1'b0; ptr <= 8'd0; done_flag <= 1'b0; err_code <= 4'd0; s_pending <= 1'b0;
            ctr_in <= 32'd0; last_ctr <= 32'd0; nonce <= 128'd0; wid <= 128'd0; tag_reg <= 128'd0;
            iv_reg <= 96'd0; regA <= 256'd0; regB <= 256'd0; regC <= 256'd0; mac_in <= 256'd0;
            d_reg <= 256'd0; k_reg <= 256'd0; ent_extra <= 256'd0; entA <= 256'd0; cand <= 256'd0;
            aux <= 256'd0; kenc <= 256'd0; hm_res <= 256'd0; hm_key_r <= 256'd0; hm_msg_r <= 1536'd0;
            ex_reg <= 256'd0; ey_reg <= 256'd0; ss_din <= 256'd0; spi_clear <= 1'b1;
        end else begin
            // ---------------- I2C register access ----------------
            if (rx_valid) begin
                if (rx_first) ptr <= rx_data;
                else begin
                    ptr <= ptr + 8'd1;
                    if (ptr == 8'h01) begin if (st == ST_IDLE) begin cmd_v <= 1'b1; cmd_b <= rx_data; end end
                    else if (st == ST_IDLE && !tamper_latched) begin
                        if      (ptr >= 8'h04 && ptr < 8'h08) ctr_in[31 - 8*(ptr - 8'h04) -: 8] <= rx_data;
                        else if (ptr >= 8'h18 && ptr < 8'h28) wid    [127 - 8*(ptr - 8'h18) -: 8] <= rx_data;
                        else if (ptr >= 8'h28 && ptr < 8'h34) iv_reg [95  - 8*(ptr - 8'h28) -: 8] <= rx_data;
                        else if (ptr >= 8'h34 && ptr < 8'h44) tag_reg[127 - 8*(ptr - 8'h34) -: 8] <= rx_data;
                        else if (ptr >= 8'h44 && ptr < 8'h64) regA   [255 - 8*(ptr - 8'h44) -: 8] <= rx_data;
                        else if (ptr >= 8'h64 && ptr < 8'h84) regB   [255 - 8*(ptr - 8'h64) -: 8] <= rx_data;
                        else if (ptr >= 8'h84 && ptr < 8'hA4) regC   [255 - 8*(ptr - 8'h84) -: 8] <= rx_data;
                        else if (ptr >= 8'hA4 && ptr < 8'hC4) mac_in [255 - 8*(ptr - 8'hA4) -: 8] <= rx_data;
                    end
                end
            end
            if (tx_next) ptr <= ptr + 8'd1;

            // ---------------- tamper: wipe and lock ----------------
            if (tamper_s || tamper_latched) begin
                st <= ST_IDLE; cmd_v <= 1'b0; s_pending <= 1'b0;
                wid <= 128'd0; tag_reg <= 128'd0; iv_reg <= 96'd0; regA <= 256'd0; regB <= 256'd0;
                regC <= 256'd0; mac_in <= 256'd0; nonce <= 128'd0;
                d_reg <= 256'd0; k_reg <= 256'd0; ent_extra <= 256'd0; entA <= 256'd0; cand <= 256'd0;
                aux <= 256'd0; kenc <= 256'd0; hm_res <= 256'd0; hm_key_r <= 256'd0; hm_msg_r <= 1536'd0;
                ss_din <= 256'd0; spi_clear <= 1'b1;
                err_code <= E_TAMPER; done_flag <= 1'b1;
            end else begin
                case (st)
                // ------------------------------------------------ idle ------
                ST_IDLE: begin
                    if (cmd_v) begin
                        cmd_v <= 1'b0; done_flag <= 1'b0; err_code <= 4'd0;
                        if (!keys_valid) begin
                            done_flag <= 1'b1; err_code <= E_NOSESS;
                        end else begin
                            cmd <= CMD_AUTH; step <= 5'd0; st <= ST_RUN;
                        end
                    end else if (s_pending) begin
                        s_pending <= 1'b0;
                        if (keys_valid) spi_clear <= 1'b1;           // session already up: ignore
                        else begin
                            done_flag <= 1'b0; err_code <= 4'd0;
                            cmd <= CMD_SESSION; step <= 5'd0; st <= ST_RUN;
                        end
                    end
                end

                // --------------------------------------------- subroutines ---
                SB_RAND_E0: begin
                    if (trng_valid) begin entA <= trng_word; st <= SB_RAND_E1; end
                    else if (trng_fail) fin(E_TRNG);
                end
                SB_RAND_E1: begin
                    if (trng_valid) begin
                        hm_job(entA, {trng_word, 1280'd0}, 8'd32);
                        hm_to_rand <= 1'b1; st <= SB_HM_GO;
                    end else if (trng_fail) fin(E_TRNG);
                end
                SB_RAND_CHK: begin
                    hm_to_rand <= 1'b0;
                    if (hm_res != 256'd0 && hm_res < N) begin
                        cand <= hm_res; hm_res <= 256'd0; entA <= 256'd0; st <= ST_RUN;
                    end else st <= SB_RAND_E0;                          // out of range: draw again
                end
                SB_IVRAND: begin
                    if (trng_valid) begin iv_reg <= trng_word[95:0]; st <= ST_RUN; end
                    else if (trng_fail) fin(E_TRNG);
                end
                SB_TRNG1: begin
                    if (trng_valid) begin ent_extra <= trng_word; use_extra <= 1'b1; st <= ST_RUN; end
                    else if (trng_fail) begin ent_extra <= 256'd0; use_extra <= 1'b0; st <= ST_RUN; end
                end
                SB_HM_GO:   begin hm_go <= 1'b1; st <= SB_HM_WAIT; end
                SB_HM_WAIT: if (hm_done) begin hm_res <= hm_mac; st <= hm_to_rand ? SB_RAND_CHK : ST_RUN; end
                SB_GCM_GO:   begin gcm_go <= 1'b1; st <= SB_GCM_WAIT; end
                SB_GCM_WAIT: if (gcm_done) st <= ST_RUN;
                SB_CORE_GO:   begin core_go <= 1'b1; st <= SB_CORE_WAIT; end
                SB_CORE_WAIT: if (core_done) st <= ST_RUN;
                SB_NONCE_GO:   begin rfc_go <= 1'b1; st <= SB_NONCE_WAIT; end
                SB_NONCE_WAIT: if (rfc_done) st <= ST_RUN;
                SB_PC_GO:   begin pc_go <= 1'b1; st <= SB_PC_WAIT; end
                SB_PC_WAIT: if (pc_done) st <= ST_RUN;

                // ----------------------------------------- command steps -----
                ST_RUN: case (cmd)
                // internal: authenticate the host command
                CMD_AUTH: case (step)
                    5'd0: begin
                        hm_job(chan_key, {nonce, ctr_in, cmd_b, wid, iv_reg, tag_reg, regA, regB, regC, 248'd0}, 8'd161);
                        call(SB_HM_GO, 5'd1);
                    end
                    5'd1: begin
                        if (hm_res == mac_in && ctr_in > last_ctr && cmd_b[7:4] != 4'hF) begin
                            last_ctr <= ctr_in; cmd <= cmd_b; step <= 5'd0; hm_res <= 256'd0;
                        end else if (hm_res == mac_in && ctr_in > last_ctr) begin
                            last_ctr <= ctr_in; fin(E_BAD_CMD);
                        end else fin(E_AUTH);
                    end
                    default: fin(E_BAD_CMD);
                endcase

                // internal: session set-up after S arrives over SPI
                CMD_SESSION: case (step)
                    5'd0: call(SB_TRNG1, 5'd1);
                    5'd1: begin
                        if (!use_extra) begin spi_clear <= 1'b1; fin(E_TRNG); end
                        else begin
                            nonce <= ent_extra[127:0];
                            hm_job(spi_s_data, {LBL_CHAN, 1480'd0}, 8'd7);
                            call(SB_HM_GO, 5'd2);
                        end
                    end
                    5'd2: begin
                        ss_din <= hm_res; ld_chan <= 1'b1;
                        hm_job(spi_s_data, {LBL_SEAL, 1480'd0}, 8'd7);
                        call(SB_HM_GO, 5'd3);
                    end
                    5'd3: begin
                        ss_din <= hm_res; ld_seal <= 1'b1; spi_clear <= 1'b1;
                        last_ctr <= 32'd0;
                        fin(E_OK);
                    end
                    default: fin(E_BAD_CMD);
                endcase

                CMD_KEK_GEN: case (step)
                    5'd0: if (kek_valid) fin(E_KEK_EXISTS); else call(SB_RAND_E0, 5'd1);
                    5'd1: begin ss_din <= cand; ld_kek <= 1'b1; fin(E_OK); end
                    default: fin(E_BAD_CMD);
                endcase

                CMD_KEK_SEAL: case (step)
                    5'd0: if (!kek_valid) fin(E_NOKEK); else call(SB_IVRAND, 5'd1);
                    5'd1: begin gcm_cfg(2'd1, 2'd1, 2'd1, 1'b0); call(SB_GCM_GO, 5'd2); end
                    5'd2: begin regA <= gcm_dout; tag_reg <= gcm_tag; fin(E_OK); end
                    default: fin(E_BAD_CMD);
                endcase

                CMD_KEK_UNSEAL: case (step)
                    5'd0: if (kek_valid) fin(E_KEK_EXISTS);
                          else begin gcm_cfg(2'd1, 2'd1, 2'd2, 1'b1); call(SB_GCM_GO, 5'd1); end
                    5'd1: begin
                        if (!gcm_ok) fin(E_UNWRAP);
                        else begin ss_din <= gcm_dout; ld_kek <= 1'b1; fin(E_OK); end
                    end
                    default: fin(E_BAD_CMD);
                endcase

                CMD_KEK_ERASE: begin clr_kek <= 1'b1; clr_enrol <= 1'b1; fin(E_OK); end

                CMD_GEN_WALLET: case (step)
                    5'd0: if (!kek_valid) fin(E_NOKEK); else call(SB_RAND_E0, 5'd1);
                    5'd1: begin d_reg <= cand; cand <= 256'd0; call(SB_IVRAND, 5'd2); end
                    5'd2: begin gcm_cfg(2'd0, 2'd0, 2'd0, 1'b0); call(SB_GCM_GO, 5'd3); end
                    5'd3: begin
                        regA <= gcm_dout; tag_reg <= gcm_tag;
                        core_mode <= 1'b1; core_base <= 1'b0; call(SB_CORE_GO, 5'd4);
                    end
                    5'd4: begin
                        if (core_fail) fin(E_SIGN);
                        else begin regB <= core_px; regC <= core_py; fin(E_OK); end
                    end
                    default: fin(E_BAD_CMD);
                endcase

                CMD_SIGN: case (step)
                    5'd0: if (!kek_valid) fin(E_NOKEK);
                          else begin gcm_cfg(2'd0, 2'd0, 2'd2, 1'b1); call(SB_GCM_GO, 5'd1); end
                    5'd1: begin
                        if (!gcm_ok) fin(E_UNWRAP);
                        else begin d_reg <= gcm_dout; call(SB_TRNG1, 5'd2); end
                    end
                    5'd2: call(SB_NONCE_GO, 5'd3);
                    5'd3: begin
                        k_reg <= rfc_k; core_mode <= 1'b0; core_base <= 1'b0; call(SB_CORE_GO, 5'd4);
                    end
                    5'd4: begin
                        if (core_fail) fin(E_SIGN);
                        else begin regA <= core_r; regB <= core_s; fin(E_OK); end
                    end
                    default: fin(E_BAD_CMD);
                endcase

                CMD_PUBKEY: case (step)
                    5'd0: if (!kek_valid) fin(E_NOKEK);
                          else begin gcm_cfg(2'd0, 2'd0, 2'd2, 1'b1); call(SB_GCM_GO, 5'd1); end
                    5'd1: begin
                        if (!gcm_ok) fin(E_UNWRAP);
                        else begin
                            d_reg <= gcm_dout; core_mode <= 1'b1; core_base <= 1'b0; call(SB_CORE_GO, 5'd2);
                        end
                    end
                    5'd2: begin
                        if (core_fail) fin(E_SIGN);
                        else begin regA <= core_px; regB <= core_py; fin(E_OK); end
                    end
                    default: fin(E_BAD_CMD);
                endcase

                CMD_ENROL_GEN: case (step)
                    5'd0: call(SB_RAND_E0, 5'd1);
                    5'd1: begin
                        d_reg <= cand; ss_din <= cand; ld_enrol <= 1'b1; cand <= 256'd0;
                        core_mode <= 1'b1; core_base <= 1'b0; call(SB_CORE_GO, 5'd2);
                    end
                    5'd2: begin
                        if (core_fail) begin clr_enrol <= 1'b1; fin(E_SIGN); end
                        else begin
                            ex_reg <= core_px; ey_reg <= core_py; regB <= core_px; regC <= core_py; fin(E_OK);
                        end
                    end
                    default: fin(E_BAD_CMD);
                endcase

                CMD_KEK_EXPORT: case (step)
                    5'd0: if (!kek_valid) fin(E_NOKEK);
                          else begin pc_x <= regB; pc_y <= regC; call(SB_PC_GO, 5'd1); end
                    5'd1: if (!pc_valid) fin(E_POINT); else call(SB_RAND_E0, 5'd2);
                    5'd2: begin                                            // ECDH: t * E
                        d_reg <= cand; cand <= 256'd0; core_mode <= 1'b1; core_base <= 1'b1;
                        call(SB_CORE_GO, 5'd3);
                    end
                    5'd3: begin
                        aux <= core_px; core_base <= 1'b0;                 // T = t * G
                        call(SB_CORE_GO, 5'd4);
                    end
                    5'd4: begin
                        hm_job(aux, {ECIES_LBL, core_px, core_py, regB, regC, 416'd0}, 8'd140);
                        pc_x <= core_px; pc_y <= core_py;                 // park T
                        call(SB_HM_GO, 5'd5);
                    end
                    5'd5: begin kenc <= hm_res; call(SB_IVRAND, 5'd6); end
                    5'd6: begin gcm_cfg(2'd2, 2'd2, 2'd1, 1'b0); call(SB_GCM_GO, 5'd7); end
                    5'd7: begin
                        regA <= gcm_dout; tag_reg <= gcm_tag; regB <= pc_x; regC <= pc_y; fin(E_OK);
                    end
                    default: fin(E_BAD_CMD);
                endcase

                CMD_KEK_IMPORT: case (step)
                    5'd0: begin
                        if (kek_valid) fin(E_KEK_EXISTS);
                        else if (!enrol_valid) fin(E_NOENROL);
                        else begin pc_x <= regB; pc_y <= regC; call(SB_PC_GO, 5'd1); end
                    end
                    5'd1: begin
                        if (!pc_valid) fin(E_POINT);
                        else begin d_reg <= enrol_d; core_mode <= 1'b1; core_base <= 1'b1; call(SB_CORE_GO, 5'd2); end
                    end
                    5'd2: begin
                        hm_job(core_px, {ECIES_LBL, regB, regC, ex_reg, ey_reg, 416'd0}, 8'd140);
                        call(SB_HM_GO, 5'd3);
                    end
                    5'd3: begin kenc <= hm_res; gcm_cfg(2'd2, 2'd2, 2'd2, 1'b1); call(SB_GCM_GO, 5'd4); end
                    5'd4: begin
                        if (!gcm_ok) fin(E_UNWRAP);
                        else begin ss_din <= gcm_dout; ld_kek <= 1'b1; clr_enrol <= 1'b1; fin(E_OK); end
                    end
                    default: fin(E_BAD_CMD);
                endcase

                default: fin(E_BAD_CMD);
                endcase
                default: st <= ST_IDLE;
                endcase
            end
        end
    end
endmodule
