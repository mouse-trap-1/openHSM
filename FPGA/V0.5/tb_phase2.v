`timescale 1ns/1ps
//------------------------------------------------------------------------------
// Phase 2 system testbench (shares, break-glass restore, rotation): TWO sign_node_top instances
// (addresses 0x48 / 0x49), each with its own SPI link from a "tamper MCU".
//
//   iverilog -g2005 -o sim_node tb_phase2.v sign_node_top.v shamir_core.v secret_store.v spi_secret_rx.v \
//        point_check.v aes_gcm32.v aes256_core.v gf128_mul.v trng_ro.v i2c_slave.v hmac_sha256.v \
//        sha256_core.v rfc6979_nonce.v ecdsa_secp256k1_sign.v modmul_serial.v ecdsa_ucode_rom.v
//   vvp sim_p2 | tee p2.log ; python3 verify_phase2.py p2.log
//
// A separate hmac_sha256 instance plays the role of the SoC secure-world driver and
// computes the command MACs.  The simulation TRNG is deterministic and NOT random.
//------------------------------------------------------------------------------
module tb_phase2;
    reg clk = 0, rst_a = 0, rst_b = 0, tamper_a = 0, tamper_b = 0;
    always #5 clk = ~clk;

    // ---------------- shared open-drain I2C bus ----------------
    reg  m_scl = 1, m_sda_low = 0;
    wire sda_oe_a, sda_oe_b;
    wire sda = (m_sda_low | sda_oe_a | sda_oe_b) ? 1'b0 : 1'b1;

    // ---------------- SPI links ----------------
    reg sclk_a = 0, cs_a = 1, mosi_a = 0, sclk_b = 0, cs_b = 1, mosi_b = 0;

    wire busy_a, kek_a, tam_a, busy_b, kek_b, tam_b;
    sign_node_top #(.I2C_ADDR(7'h48), .SIM_TRNG(1), .TRNG_DIV(2)) dutA (
        .clk(clk), .rst_n(rst_a), .scl_i(m_scl), .sda_i(sda), .sda_oe(sda_oe_a),
        .spi_sclk(sclk_a), .spi_cs_n(cs_a), .spi_mosi(mosi_a), .tamper(tamper_a), .ceremony(1'b1),
        .led_busy(busy_a), .led_kek(kek_a), .led_tamper(tam_a));
    sign_node_top #(.I2C_ADDR(7'h49), .SIM_TRNG(1), .TRNG_DIV(3)) dutB (
        .clk(clk), .rst_n(rst_b), .scl_i(m_scl), .sda_i(sda), .sda_oe(sda_oe_b),
        .spi_sclk(sclk_b), .spi_cs_n(cs_b), .spi_mosi(mosi_b), .tamper(tamper_b), .ceremony(1'b1),
        .led_busy(busy_b), .led_kek(kek_b), .led_tamper(tam_b));

    // ---------------- host-side HMAC (MAC computation) ----------------
    reg          h_start = 0;
    reg  [255:0] h_key = 0;
    reg  [1535:0] h_msg = 0;
    reg  [7:0]   h_len = 0;
    wire         h_busy, h_done;
    wire [255:0] h_mac;
    hmac_sha256 host_hm (.clk(clk), .wipe(1'b0), .start(h_start), .key(h_key), .msg(h_msg),
                         .msg_len(h_len), .busy(h_busy), .done(h_done), .mac(h_mac));
    reg [255:0] hm_out;
    task host_hmac(input [255:0] key, input [1535:0] msg, input [7:0] len);
        begin
            @(negedge clk); h_key = key; h_msg = msg; h_len = len; h_start = 1;
            @(negedge clk); h_start = 0;
            while (!h_done) @(negedge clk);
            hm_out = h_mac;
        end
    endtask

    // ---------------- I2C master primitives (1 MHz) ----------------
    localparam Q = 250;
    task i2c_start;  begin m_sda_low = 0; m_scl = 1; #Q; m_sda_low = 1; #Q; m_scl = 0; #Q; end endtask
    task i2c_rstart; begin m_sda_low = 0; #Q; m_scl = 1; #Q; m_sda_low = 1; #Q; m_scl = 0; #Q; end endtask
    task i2c_stop;   begin m_sda_low = 1; #Q; m_scl = 1; #Q; m_sda_low = 0; #(2*Q); end endtask
    reg ack_dummy;
    task wr_byte(input [7:0] b, output ack);
        integer i;
        begin
            for (i = 7; i >= 0; i = i - 1) begin m_sda_low = ~b[i]; #Q; m_scl = 1; #(2*Q); m_scl = 0; #Q; end
            m_sda_low = 0; #Q; m_scl = 1; #Q; ack = ~sda; #Q; m_scl = 0; #Q;
        end
    endtask
    task rd_byte(input send_ack, output [7:0] b);
        integer i;
        begin
            m_sda_low = 0;
            for (i = 7; i >= 0; i = i - 1) begin #Q; m_scl = 1; #Q; b[i] = sda; #Q; m_scl = 0; #Q; end
            m_sda_low = send_ack; #Q; m_scl = 1; #(2*Q); m_scl = 0; #Q; m_sda_low = 0;
        end
    endtask

    // node n: 0 = A (0x48), 1 = B (0x49)
    function [7:0] aw(input n); aw = n ? 8'h92 : 8'h90; endfunction

    task wrN(input n, input [7:0] ptr, input [255:0] val, input integer nb);
        integer i;
        begin
            i2c_start; wr_byte(aw(n), ack_dummy); wr_byte(ptr, ack_dummy);
            for (i = nb - 1; i >= 0; i = i - 1) wr_byte(val[8*i +: 8], ack_dummy);
            i2c_stop;
        end
    endtask
    reg [255:0] rd_val;
    task rdN(input n, input [7:0] ptr, input integer nb);
        integer i; reg [7:0] b;
        begin
            rd_val = 256'd0;
            i2c_start; wr_byte(aw(n), ack_dummy); wr_byte(ptr, ack_dummy);
            i2c_rstart; wr_byte(aw(n) | 8'h01, ack_dummy);
            for (i = nb - 1; i >= 0; i = i - 1) begin rd_byte(i != 0, b); rd_val = {rd_val[247:0], b}; end
            i2c_stop;
        end
    endtask

    // ---------------- SPI sender (tamper-MCU model) ----------------
    task spi_send(input n, input [255:0] s);
        reg [263:0] fr; integer i;
        begin
            fr = {8'hA5, s};
            if (n) cs_b = 0; else cs_a = 0;
            repeat (8) @(posedge clk);
            for (i = 263; i >= 0; i = i - 1) begin
                if (n) mosi_b = fr[i]; else mosi_a = fr[i];
                repeat (4) @(posedge clk);
                if (n) sclk_b = 1; else sclk_a = 1;
                repeat (4) @(posedge clk);
                if (n) sclk_b = 0; else sclk_a = 0;
                repeat (2) @(posedge clk);
            end
            repeat (8) @(posedge clk);
            if (n) cs_b = 1; else cs_a = 1;
            repeat (10) @(posedge clk);
        end
    endtask

    // ---------------- shadows of the host-visible buffers ----------------
    reg [127:0] s_wid = 0, s_tag = 0;
    reg [95:0]  s_iv = 0;
    reg [255:0] s_A = 0, s_B = 0, s_C = 0;
    reg [255:0] chan [0:1];
    reg [127:0] nonce_n [0:1];
    reg [31:0]  ctr_n [0:1];
    reg [7:0]   v8;
    integer errors = 0;

    task poll_done(input n);
        integer t;
        begin
            v8 = 8'h00; t = 0;
            while (!(v8 & 8'h02) && t < 3000) begin #100000; rdN(n, 8'h00, 1); v8 = rd_val[7:0]; t = t + 1; end
            if (!(v8 & 8'h02)) begin errors = errors + 1; $display("FAIL: timeout waiting for done"); end
        end
    endtask

    task check(input cond, input [8*48-1:0] name);
        begin
            if (!cond) begin errors = errors + 1; $display("FAIL: %0s", name); end
            else $display("PASS: %0s", name);
        end
    endtask

    // write every input buffer from the shadows, authenticate and start a command
    task issue(input n, input [7:0] cmd, input corrupt_mac);
        reg [31:0] c; reg [255:0] mac;
        begin
            ctr_n[n] = ctr_n[n] + 1; c = ctr_n[n];
            wrN(n, 8'h18, s_wid, 16);  wrN(n, 8'h28, s_iv, 12);   wrN(n, 8'h34, s_tag, 16);
            wrN(n, 8'h44, s_A, 32);    wrN(n, 8'h64, s_B, 32);    wrN(n, 8'h84, s_C, 32);
            wrN(n, 8'h04, c, 4);
            host_hmac(chan[n], {nonce_n[n], c, cmd, s_wid, s_iv, s_tag, s_A, s_B, s_C, 248'd0}, 8'd161);
            mac = corrupt_mac ? (hm_out ^ 256'h1) : hm_out;
            wrN(n, 8'hA4, mac, 32);
            wrN(n, 8'h01, {248'd0, cmd}, 1);
            poll_done(n);
        end
    endtask

    task fetch(input n);
        begin
            rdN(n, 8'h28, 12); s_iv  = rd_val[95:0];
            rdN(n, 8'h34, 16); s_tag = rd_val[127:0];
            rdN(n, 8'h44, 32); s_A = rd_val;
            rdN(n, 8'h64, 32); s_B = rd_val;
            rdN(n, 8'h84, 32); s_C = rd_val;
        end
    endtask

    task expect_err(input n, input [3:0] code);
        begin
            rdN(n, 8'h02, 1);
            if (rd_val[3:0] !== code) begin errors = errors + 1; $display("FAIL: error code %0d, expected %0d", rd_val[3:0], code); end
            else $display("PASS: error code %0d as expected", code);
        end
    endtask

    // session bring-up: SPI secret -> keys + nonce
    task bring_up(input n, input [255:0] s);
        begin
            spi_send(n, s);
            poll_done(n);
            rdN(n, 8'h08, 16); nonce_n[n] = rd_val[127:0];
            host_hmac(s, {56'h534e2d4348414e, 1480'd0}, 8'd7); chan[n] = hm_out;
            ctr_n[n] = 32'd0;
        end
    endtask


    localparam [255:0] SA  = 256'h1111111111111111_2222222222222222_3333333333333333_4444444444444444;
    localparam [255:0] SA2 = 256'h5555555555555555_6666666666666666_7777777777777777_8888888888888888;
    localparam [255:0] SB  = 256'hA0A0A0A0A0A0A0A0_B1B1B1B1B1B1B1B1_C2C2C2C2C2C2C2C2_D3D3D3D3D3D3D3D3;
    localparam [255:0] DIGEST = 256'h2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824;

    function [255:0] rcard(input [7:0] x); rcard = {32{x}}; endfunction     // stand-in for the card-derived secret r_x

    reg [255:0] keyA, k2, wrapA, ex, ey, sh_ct [1:5], fpA, fpB;
    reg [95:0]  sh_iv [1:5], wiv;
    reg [127:0] sh_tag [1:5], tmpl, wid1, wtag;
    reg [95:0]  eiv; reg [127:0] etag; reg [255:0] ect, tx, ty;
    reg [255:0] nb_ct; reg [95:0] nb_iv; reg [127:0] nb_tag;
    integer x;

    task put_share(input n, input [7:0] xx, input [255:0] r, input flip);
        begin
            s_wid = {xx, tmpl[119:0]}; s_B = r; s_C = 0;
            s_iv = sh_iv[xx]; s_tag = sh_tag[xx]; s_A = flip ? (sh_ct[xx] ^ 256'h1) : sh_ct[xx];
            issue(n, 8'h53, 1'b0);
        end
    endtask
    task shares_held(input n, output [3:0] c);
        begin rdN(n, 8'h03, 1); c = rd_val[3:0]; end
    endtask
    reg [3:0] cnt_h;

    initial begin
        chan[0] = 0; chan[1] = 0; nonce_n[0] = 0; nonce_n[1] = 0; ctr_n[0] = 0; ctr_n[1] = 0;
        wid1 = 128'h00112233445566778899aabbccddeeff;
        repeat (10) @(posedge clk); rst_a = 1; rst_b = 1; repeat (20) @(posedge clk);
        bring_up(0, SA); bring_up(1, SB);
        $display("S0=%h", SA); $display("S0B=%h", SA2); $display("S1=%h", SB);

        // ---------- cluster KEK and a wallet ----------
        s_A = 0; s_B = 0; s_C = 0; s_wid = wid1;
        issue(0, 8'h10, 1'b0); expect_err(0, 4'd0);
        keyA = dutA.u_ss.kek;  $display("KEK=%h", keyA);
        issue(0, 8'h17, 1'b0); expect_err(0, 4'd0); fetch(0); fpA = s_B; $display("FP=%h", fpA);
        s_A = 0; s_B = 0; s_C = 0; s_wid = wid1;
        issue(0, 8'h20, 1'b0); expect_err(0, 4'd0); fetch(0);
        wiv = s_iv; wtag = s_tag; wrapA = s_A;
        $display("WALLET wid=%h iv=%h tag=%h ct=%h", wid1, wiv, wtag, wrapA);
        $display("PUBX=%h", s_B); $display("PUBY=%h", s_C);

        // ---------- split the KEK 3-of-5 and wrap each share to a card ----------
        s_A = 0; s_C = 0; s_wid = 0; s_B = {8'd3, 8'd5, 240'd0};
        issue(0, 8'h50, 1'b0); expect_err(0, 4'd0);
        rdN(0, 8'h03, 1); check(rd_val[5] === 1'b1, "SPLIT_BEGIN: sharing polynomial active");
        rdN(0, 8'h18, 16); tmpl = rd_val[127:0];
        $display("TEMPLATE=%h", tmpl);
        for (x = 1; x <= 5; x = x + 1) begin
            s_wid = {x[7:0], tmpl[119:0]}; s_B = rcard(x[7:0]); s_A = 0; s_iv = 0; s_tag = 0;
            issue(0, 8'h51, 1'b0); expect_err(0, 4'd0); fetch(0);
            sh_iv[x] = s_iv; sh_tag[x] = s_tag; sh_ct[x] = s_A;
            $display("SHARE x=%0d hdr=%h iv=%h tag=%h ct=%h", x, s_wid, s_iv, s_tag, s_A);
        end
        s_wid = {8'd6, tmpl[119:0]}; s_B = rcard(8'd6); issue(0, 8'h51, 1'b0); expect_err(0, 4'd13);          // x beyond n
        s_wid = {8'd1, tmpl[119:1], ~tmpl[0]}; s_B = rcard(8'd1); issue(0, 8'h51, 1'b0); expect_err(0, 4'd13);   // wrong fingerprint
        s_B = 0; s_wid = 0; issue(0, 8'h52, 1'b0); expect_err(0, 4'd0);
        s_wid = {8'd1, tmpl[119:0]}; s_B = rcard(8'd1); issue(0, 8'h51, 1'b0); expect_err(0, 4'd14);            // no active split
        s_B = {8'd2, 8'd2, 240'd0}; s_wid = 0;
        issue(0, 8'h50, 1'b0); expect_err(0, 4'd0);                                                              // leave a split open ...

        // ---------- total loss: tamper wipes the KEK AND the sharing state ----------
        #13 tamper_a = 1; #37 tamper_a = 0;
        check(dutA.u_ss.kek === 256'd0 && dutA.u_ss.chan_key === 256'd0, "tamper: KEK and channel key zeroized");
        check(dutA.u_shamir.coef[1] === 256'd0 && dutA.split_active === 1'b0, "tamper: sharing polynomial wiped");
        #5000;
        rst_a = 0; repeat (6) @(posedge clk); rst_a = 1; repeat (20) @(posedge clk);
        bring_up(0, SA2);
        rdN(0, 8'h00, 1); check(rd_val[3] === 1'b0 && rd_val[6] === 1'b1, "after reset: no KEK, new session from a fresh secret");

        // ---------- break-glass restore on node A ----------
        s_A = 0; s_B = 0; s_C = 0; s_wid = 0;
        issue(0, 8'h54, 1'b0); expect_err(0, 4'd14);                                                             // nothing to combine
        put_share(0, 8'd2, rcard(8'd3), 1'b0); expect_err(0, 4'd10);                                            // wrong card secret
        put_share(0, 8'd2, rcard(8'd2), 1'b1); expect_err(0, 4'd10);                                            // corrupted share blob
        put_share(0, 8'd2, rcard(8'd2), 1'b0); expect_err(0, 4'd0);
        put_share(0, 8'd2, rcard(8'd2), 1'b0); expect_err(0, 4'd13);                                            // same share twice
        shares_held(0, cnt_h); check(cnt_h === 4'd1, "one share held; the duplicate was refused");
        s_A = 0; s_B = 0; s_wid = 0;
        issue(0, 8'h54, 1'b0); expect_err(0, 4'd14);                                                             // 1 < m
        issue(0, 8'h55, 1'b0); expect_err(0, 4'd0);
        shares_held(0, cnt_h); check(cnt_h === 4'd0, "RESTORE_ABORT discards the shares");
        put_share(0, 8'd2, rcard(8'd2), 1'b0); expect_err(0, 4'd0);
        put_share(0, 8'd4, rcard(8'd4), 1'b0); expect_err(0, 4'd0);
        put_share(0, 8'd5, rcard(8'd5), 1'b0); expect_err(0, 4'd0);
        s_A = 0; s_B = 0; s_wid = 0;
        issue(0, 8'h54, 1'b0); expect_err(0, 4'd0);
        check(dutA.u_ss.kek === keyA && dutA.u_ss.kek_valid === 1'b1, "3 of 5 cards rebuild the identical cluster KEK on node A");
        shares_held(0, cnt_h); check(cnt_h === 4'd0, "shares scrubbed after restore");

        // the recovered KEK opens the wallet blob created before the disaster
        s_wid = wid1; s_iv = wiv; s_tag = wtag; s_A = wrapA; s_B = DIGEST; s_C = 0;
        issue(0, 8'h21, 1'b0); expect_err(0, 4'd0); fetch(0);
        $display("HASH=%h", DIGEST); $display("SIG1 r=%h", s_A); $display("SIG1 s=%h", s_B);

        // ---------- a different node restores from a different 3 cards ----------
        s_A = 0; s_B = 0; s_C = 0; s_wid = 0;
        put_share(1, 8'd1, rcard(8'd1), 1'b0); expect_err(1, 4'd0);
        put_share(1, 8'd3, rcard(8'd3), 1'b0); expect_err(1, 4'd0);
        put_share(1, 8'd5, rcard(8'd5), 1'b0); expect_err(1, 4'd0);
        s_A = 0; s_B = 0; s_wid = 0;
        issue(1, 8'h54, 1'b0); expect_err(1, 4'd0);
        check(dutB.u_ss.kek === keyA, "node B restores the same KEK from a different subset of cards");
        issue(0, 8'h17, 1'b0); fetch(0); fpA = s_B;
        issue(1, 8'h17, 1'b0); fetch(1); fpB = s_B;
        check(fpA === fpB && fpA !== 256'd0, "KEK fingerprints agree between nodes");

        // ---------- KEK rotation ----------
        s_A = 0; s_B = 0; s_C = 0; s_wid = 0;
        issue(1, 8'h40, 1'b0); expect_err(1, 4'd0); fetch(1);
        ex = s_B; ey = s_C; $display("ENROL ex=%h ey=%h", ex, ey); $display("ENROLD=%h", dutB.u_ss.enrol_d);
        s_A = 0; s_B = 0; s_C = 0;
        issue(0, 8'h14, 1'b0); expect_err(0, 4'd0);
        k2 = dutA.u_ss.kek2; $display("KEK2=%h", k2);
        check(k2 !== 256'd0 && k2 !== keyA, "KEK_NEW_GEN: slot 2 holds a fresh KEK");
        s_B = ex; s_C = ey;
        issue(0, 8'h45, 1'b0); expect_err(0, 4'd0); fetch(0);
        eiv = s_iv; etag = s_tag; ect = s_A; tx = s_B; ty = s_C;
        $display("ECIES T.x=%h", tx); $display("ECIES T.y=%h", ty); $display("ECIES iv=%h ct=%h tag=%h", eiv, ect, etag);
        issue(1, 8'h46, 1'b0); expect_err(1, 4'd0);
        check(dutB.u_ss.kek2 === k2 && dutB.u_ss.kek === keyA, "KEK_NEW_IMPORT: node B holds the new KEK in slot 2, old KEK intact");

        s_wid = wid1; s_iv = wiv; s_tag = wtag; s_A = wrapA; s_B = 0; s_C = 0;
        issue(0, 8'h15, 1'b0); expect_err(0, 4'd0); fetch(0);
        nb_iv = s_iv; nb_tag = s_tag; nb_ct = s_A;
        $display("REWRAP wid=%h iv=%h tag=%h ct=%h", wid1, nb_iv, nb_tag, nb_ct);
        check(nb_ct !== wrapA, "REWRAP produced a different blob");

        s_A = 0; s_B = 0; s_C = 0; s_wid = 0;
        issue(0, 8'h16, 1'b0); expect_err(0, 4'd0);
        issue(1, 8'h16, 1'b0); expect_err(1, 4'd0);
        check(dutA.u_ss.kek === k2 && dutA.u_ss.kek2_valid === 1'b0 && dutB.u_ss.kek === k2, "PROMOTE: both nodes now use the new KEK");
        s_wid = wid1; s_iv = wiv; s_tag = wtag; s_A = wrapA; s_B = DIGEST; s_C = 0;
        issue(0, 8'h21, 1'b0); expect_err(0, 4'd10);                                                             // old blob is dead on the new KEK
        s_wid = wid1; s_iv = nb_iv; s_tag = nb_tag; s_A = nb_ct; s_B = DIGEST; s_C = 0;
        issue(1, 8'h21, 1'b0); expect_err(1, 4'd0); fetch(1);
        $display("SIGB r=%h", s_A); $display("SIGB s=%h", s_B);

        if (errors == 0) $display("ALL PHASE 2 SYSTEM TESTS PASSED");
        else             $display("%0d PHASE 2 SYSTEM TESTS FAILED", errors);
        $finish;
    end
endmodule
