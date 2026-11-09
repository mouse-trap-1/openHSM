`timescale 1ns/1ps
//------------------------------------------------------------------------------
// System testbench: TWO sign_node_top instances (A, B) on one shared I2C bus
// (addresses 0x48 / 0x49), each with its own SPI link from a "tamper MCU".
//
//   iverilog -g2005 -o sim_node tb_node_system.v sign_node_top.v secret_store.v spi_secret_rx.v \
//        point_check.v aes_gcm32.v aes256_core.v gf128_mul.v trng_ro.v i2c_slave.v hmac_sha256.v \
//        sha256_core.v rfc6979_nonce.v ecdsa_secp256k1_sign.v modmul_serial.v ecdsa_ucode_rom.v
//   vvp sim_node | tee node.log ; python3 verify_node.py node.log
//
// A separate hmac_sha256 instance plays the role of the SoC secure-world driver and
// computes the command MACs.  The simulation TRNG is deterministic and NOT random.
//------------------------------------------------------------------------------
module tb_node_system;
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
        .spi_sclk(sclk_a), .spi_cs_n(cs_a), .spi_mosi(mosi_a), .tamper(tamper_a),
        .led_busy(busy_a), .led_kek(kek_a), .led_tamper(tam_a));
    sign_node_top #(.I2C_ADDR(7'h49), .SIM_TRNG(1), .TRNG_DIV(3)) dutB (
        .clk(clk), .rst_n(rst_b), .scl_i(m_scl), .sda_i(sda), .sda_oe(sda_oe_b),
        .spi_sclk(sclk_b), .spi_cs_n(cs_b), .spi_mosi(mosi_b), .tamper(tamper_b),
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

    localparam [255:0] SA = 256'h1111111111111111_2222222222222222_3333333333333333_4444444444444444;
    localparam [255:0] SB = 256'hA0A0A0A0A0A0A0A0_B1B1B1B1B1B1B1B1_C2C2C2C2C2C2C2C2_D3D3D3D3D3D3D3D3;
    localparam [255:0] DIGEST = 256'h2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824;
    reg [255:0] keyA, wrapA, pubx, puby, r1, s1, r2, s2, ex, ey, tx, ty, ect;
    reg [95:0]  wiv; reg [127:0] wtag, eiv_t, etag;
    reg [95:0]  eiv;
    reg [127:0] wid1;

    initial begin
        chan[0] = 0; chan[1] = 0; nonce_n[0] = 0; nonce_n[1] = 0; ctr_n[0] = 0; ctr_n[1] = 0;
        wid1 = 128'h00112233445566778899aabbccddeeff;
        repeat (10) @(posedge clk); rst_a = 1; rst_b = 1; repeat (20) @(posedge clk);

        // ---------- no session: every command refused ----------
        s_A = 0; s_B = 0; s_C = 0; s_wid = wid1;
        wrN(0, 8'h01, 256'h10, 1); #200000; expect_err(0, 4'd1);
        rdN(0, 8'h00, 1); check(rd_val[6] === 1'b0, "no session after power-up");

        // ---------- sessions ----------
        bring_up(0, SA); bring_up(1, SB);
        $display("S0=%h", SA); $display("S1=%h", SB);
        $display("NONCE0=%h", nonce_n[0]);
        rdN(0, 8'h00, 1); check(rd_val[6] === 1'b1, "node A session established from SPI secret");
        check(dutA.u_ss.chan_key === chan[0], "chan_key matches HMAC(S, SN-CHAN)");
        check(nonce_n[0] !== 128'd0, "per-session nonce generated");
        check(dutA.u_spi.s_data === 256'd0, "S cleared from the SPI receiver after use");

        // ---------- command authentication ----------
        s_A = 0; s_B = 0; s_C = 0;
        issue(0, 8'h10, 1'b1); expect_err(0, 4'd5);
        check(dutA.u_ss.kek_valid === 1'b0, "bad MAC: command not executed");
        // replay: same counter as an earlier accepted command must be refused (accept one first)
        issue(0, 8'h10, 1'b0); expect_err(0, 4'd0);
        rdN(0, 8'h00, 1); check(rd_val[3] === 1'b1, "KEK_GEN: cluster KEK created on node A");
        keyA = dutA.u_ss.kek;                                                       // testbench-only peek
        $display("KEK=%h", keyA);
        begin : replay
            reg [31:0] c0;
            c0 = ctr_n[0];                                                          // ctr of the accepted frame
            ctr_n[0] = c0 - 1;                                                      // reuse a stale counter
            issue(0, 8'h13, 1'b0); expect_err(0, 4'd5);
            ctr_n[0] = c0;
            check(dutA.u_ss.kek_valid === 1'b1, "replayed command rejected, KEK intact");
        end
        issue(0, 8'h10, 1'b0); expect_err(0, 4'd3);                                 // KEK exists

        // ---------- seal ----------
        issue(0, 8'h11, 1'b0); expect_err(0, 4'd0); fetch(0);
        $display("SEAL iv=%h tag=%h ct=%h", s_iv, s_tag, s_A);

        // ---------- wallet generation, signing ----------
        s_A = 0; s_B = 0; s_C = 0; s_wid = wid1;
        issue(0, 8'h20, 1'b0); expect_err(0, 4'd0); fetch(0);
        wiv = s_iv; wtag = s_tag; wrapA = s_A; pubx = s_B; puby = s_C;
        $display("WALLET wid=%h iv=%h tag=%h ct=%h", wid1, wiv, wtag, wrapA);
        $display("PUBX=%h", pubx); $display("PUBY=%h", puby);

        s_wid = wid1; s_iv = wiv; s_tag = wtag; s_A = wrapA; s_B = DIGEST; s_C = 0;
        issue(0, 8'h21, 1'b0); expect_err(0, 4'd0); fetch(0);
        r1 = s_A; s1 = s_B;
        $display("HASH=%h", DIGEST); $display("SIG1 r=%h", r1); $display("SIG1 s=%h", s1);
        s_A = wrapA; s_B = DIGEST;
        issue(0, 8'h21, 1'b0); expect_err(0, 4'd0); fetch(0);
        r2 = s_A; s2 = s_B;
        $display("SIG2 r=%h", r2); $display("SIG2 s=%h", s2);
        check(r1 !== r2, "hedged nonce: two signatures of one digest differ");

        // ---------- wrapped-key binding: wrong wallet id / corrupted blob / corrupted tag ----------
        s_wid = wid1 ^ 128'h1; s_iv = wiv; s_tag = wtag; s_A = wrapA; s_B = DIGEST;
        issue(0, 8'h21, 1'b0); expect_err(0, 4'd10);
        s_wid = wid1; s_A = wrapA ^ (256'h1 << 200);
        issue(0, 8'h21, 1'b0); expect_err(0, 4'd10);
        s_A = wrapA; s_tag = wtag ^ 128'h1;
        issue(0, 8'h21, 1'b0); expect_err(0, 4'd10);
        check(dutA.d_reg === 256'd0 && dutA.k_reg === 256'd0, "failed unwrap leaves no key material behind");
        s_tag = wtag;

        // ---------- ECIES: move the KEK from A to B ----------
        s_A = 0; s_B = 0; s_C = 0;
        issue(1, 8'h41, 1'b0); expect_err(1, 4'd2);                                 // B has no KEK to export
        issue(1, 8'h42, 1'b0); expect_err(1, 4'd12);                                // import without enrolment key
        issue(1, 8'h40, 1'b0); expect_err(1, 4'd0); fetch(1);
        ex = s_B; ey = s_C;
        $display("ENROL ex=%h ey=%h", ex, ey);
        $display("ENROLD=%h", dutB.u_ss.enrol_d);
        rdN(1, 8'h00, 1); check(rd_val[7] === 1'b1, "node B holds an enrolment key");

        // export to an invalid point must be refused
        s_B = ex; s_C = ey ^ 256'h1;
        issue(0, 8'h41, 1'b0); expect_err(0, 4'd11);
        // export to the real enrolment key
        s_B = ex; s_C = ey;
        issue(0, 8'h41, 1'b0); expect_err(0, 4'd0); fetch(0);
        eiv = s_iv; etag = s_tag; ect = s_A; tx = s_B; ty = s_C;
        $display("ECIES T.x=%h", tx); $display("ECIES T.y=%h", ty);
        $display("ECIES iv=%h ct=%h tag=%h", eiv, ect, etag);

        // import on B: tampered ciphertext first (must fail), then the real blob
        s_iv = eiv; s_tag = etag; s_A = ect ^ 256'h1; s_B = tx; s_C = ty;
        issue(1, 8'h42, 1'b0); expect_err(1, 4'd10);
        check(dutB.u_ss.kek_valid === 1'b0, "corrupted ECIES blob rejected, no KEK loaded");
        s_A = ect;
        issue(1, 8'h42, 1'b0); expect_err(1, 4'd0);
        check(dutB.u_ss.kek === keyA && dutB.u_ss.kek_valid === 1'b1, "ECIES: node B received the identical cluster KEK");
        check(dutB.u_ss.enrol_valid === 1'b0 && dutB.u_ss.enrol_d === 256'd0, "enrolment key destroyed after import");

        // B can now sign with a wallet key that A created and wrapped
        s_wid = wid1; s_iv = wiv; s_tag = wtag; s_A = wrapA; s_B = DIGEST; s_C = 0;
        issue(1, 8'h21, 1'b0); expect_err(1, 4'd0); fetch(1);
        $display("SIGB r=%h", s_A); $display("SIGB s=%h", s_B);

        // ---------- seal on B, reboot B, restore from the sealed blob ----------
        s_A = 0; s_B = 0; s_C = 0;
        issue(1, 8'h11, 1'b0); expect_err(1, 4'd0); fetch(1);
        wiv = s_iv; wtag = s_tag; wrapA = s_A;
        $display("SEALB iv=%h tag=%h ct=%h", wiv, wtag, wrapA);
        rst_b = 0; repeat (6) @(posedge clk); rst_b = 1; repeat (20) @(posedge clk);
        check(dutB.u_ss.kek === 256'd0 && dutB.u_ss.kek_valid === 1'b0, "power cycle: KEK gone from node B");
        bring_up(1, SB);
        s_iv = wiv; s_tag = wtag; s_A = wrapA; s_B = 0; s_C = 0;
        issue(1, 8'h12, 1'b0); expect_err(1, 4'd0);
        check(dutB.u_ss.kek === keyA, "sealed KEK restored after reboot (same S)");
        // wrong S after reboot must not unseal
        rst_b = 0; repeat (6) @(posedge clk); rst_b = 1; repeat (20) @(posedge clk);
        bring_up(1, SB ^ 256'h1);
        s_iv = wiv; s_tag = wtag; s_A = wrapA;
        issue(1, 8'h12, 1'b0); expect_err(1, 4'd10);
        check(dutB.u_ss.kek_valid === 1'b0, "different S cannot unseal the KEK");

        // ---------- tamper in the middle of a signing operation on A ----------
        s_wid = wid1; s_iv = 96'd0; s_tag = 128'd0; s_A = 256'd0; s_B = 256'd0; s_C = 256'd0;
        begin : tamper_test
            reg [31:0] c; reg [255:0] mac;
            // re-issue a sign request but do not wait for completion
            s_iv = 96'h0; // stale blob values are irrelevant: GCM auth fails fast, so use KEK_SEAL-less path
        end
        s_wid = wid1; s_iv = eiv; s_tag = etag; s_A = ect; s_B = DIGEST; s_C = 0;
        // use the genuine wallet blob for a real long-running sign
        s_iv = 96'd0;
        // (re-fetch the wallet blob captured earlier is not kept; generate a fresh wallet instead)
        s_A = 0; s_B = 0; s_C = 0;
        issue(0, 8'h20, 1'b0); expect_err(0, 4'd0); fetch(0);
        wiv = s_iv; wtag = s_tag; wrapA = s_A;
        s_wid = wid1; s_iv = wiv; s_tag = wtag; s_A = wrapA; s_B = DIGEST; s_C = 0;
        begin : tamper_run
            reg [31:0] c; reg [255:0] mac;
            ctr_n[0] = ctr_n[0] + 1; c = ctr_n[0];
            wrN(0, 8'h18, s_wid, 16); wrN(0, 8'h28, s_iv, 12); wrN(0, 8'h34, s_tag, 16);
            wrN(0, 8'h44, s_A, 32);   wrN(0, 8'h64, s_B, 32);  wrN(0, 8'h84, s_C, 32);
            wrN(0, 8'h04, c, 4);
            host_hmac(chan[0], {nonce_n[0], c, 8'h21, s_wid, s_iv, s_tag, s_A, s_B, s_C, 248'd0}, 8'd161);
            mac = hm_out;
            wrN(0, 8'hA4, mac, 32); wrN(0, 8'h01, 256'h21, 1);
            #400000;
            check(dutA.u_core.busy === 1'b1, "signing in progress before tamper");
            #13 tamper_a = 1; #37 tamper_a = 0;
            check(dutA.u_ss.kek === 256'd0 && dutA.u_ss.chan_key === 256'd0 && dutA.u_ss.seal_key === 256'd0,
                  "tamper: KEK and channel keys zeroized immediately");
            #5000;
            check(dutA.u_core.busy === 1'b0, "tamper: signer aborted");
            check(dutA.d_reg === 256'd0 && dutA.k_reg === 256'd0 && dutA.u_gcm.hkey === 128'd0 && dutA.u_hmac.key_r === 256'd0,
                  "tamper: unwrapped key, nonce, GCM and HMAC state wiped");
        end
        rdN(0, 8'h00, 1); check(rd_val[4] === 1'b1 && rd_val[3] === 1'b0, "tamper flag set, KEK not present");
        s_A = 0; s_B = 0; s_C = 0;
        issue(0, 8'h10, 1'b0); expect_err(0, 4'd7);
        check(dutA.u_ss.kek_valid === 1'b0, "module stays locked after tamper");

        if (errors == 0) $display("ALL NODE SYSTEM TESTS PASSED");
        else             $display("%0d NODE SYSTEM TESTS FAILED", errors);
        $finish;
    end
endmodule
