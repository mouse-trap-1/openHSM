`timescale 1ns/1ps
//------------------------------------------------------------------------------
// System testbench for secp256k1_hsm_top, driven entirely over a bit-banged I2C bus
//
//   iverilog -g2005 -o sim_sys tb_hsm_system.v secp256k1_hsm_top.v key_vault.v trng_ro.v \
//            i2c_slave.v hmac_sha256.v sha256_core.v rfc6979_nonce.v \
//            ecdsa_secp256k1_sign.v modmul_serial.v ecdsa_ucode_rom.v
//   vvp sim_sys | tee sys.log ;  python3 verify_system.py sys.log
//
// The simulation TRNG (SIM_TRNG=1) is deterministic and NOT random.
//------------------------------------------------------------------------------
module tb_hsm_system;
    reg clk = 0, rst_n = 0, tamper = 0, confirm = 1;
    always #5 clk = ~clk;

    // ---------------- I2C bus (open-drain, pull-up) ----------------
    reg  m_scl = 1, m_sda_low = 0;
    wire sda_oe;
    wire sda = (m_sda_low | sda_oe) ? 1'b0 : 1'b1;

    // ---------------- behavioural non-volatile key store ----------------
    reg  [255:0] nvm_mem = 256'd0;
    reg          nvm_ok  = 1'b0;
    wire         nvm_we, nvm_erase;
    wire [255:0] nvm_wdata;
    always @(posedge clk or posedge nvm_erase) begin
        if (nvm_erase)   begin nvm_mem <= 256'd0; nvm_ok <= 1'b0; end
        else if (nvm_we) begin nvm_mem <= nvm_wdata; nvm_ok <= 1'b1; end
    end

    wire led_busy, led_key, led_tamper;
    secp256k1_hsm_top #(.I2C_ADDR(7'h42), .REQUIRE_CONFIRM(1), .CONFIRM_TIMEOUT(32'd30000),
                        .SIM_TRNG(1), .TRNG_DIV(2)) dut (
        .clk(clk), .rst_n(rst_n), .scl_i(m_scl), .sda_i(sda), .sda_oe(sda_oe),
        .tamper(tamper), .confirm(confirm),
        .nvm_we(nvm_we), .nvm_wdata(nvm_wdata), .nvm_erase(nvm_erase),
        .nvm_rvalid(nvm_ok), .nvm_rdata(nvm_mem),
        .led_busy(led_busy), .led_key(led_key), .led_tamper(led_tamper)
    );

    // ---------------- I2C master primitives (1 MHz) ----------------
    localparam Q = 250;
    task i2c_start;  begin m_sda_low = 0; m_scl = 1; #Q; m_sda_low = 1; #Q; m_scl = 0; #Q; end endtask
    task i2c_rstart; begin m_sda_low = 0; #Q; m_scl = 1; #Q; m_sda_low = 1; #Q; m_scl = 0; #Q; end endtask
    task i2c_stop;   begin m_sda_low = 1; #Q; m_scl = 1; #Q; m_sda_low = 0; #(2*Q); end endtask
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

    // ---------------- register-level helpers ----------------
    reg ack_dummy;
    reg [7:0]   v8;
    reg [255:0] v256;
    integer errors = 0;

    task wr1(input [7:0] ptr, input [7:0] val);
        begin i2c_start; wr_byte(8'h84, ack_dummy); wr_byte(ptr, ack_dummy); wr_byte(val, ack_dummy); i2c_stop; end
    endtask
    task wr32(input [7:0] ptr, input [255:0] val);
        integer i;
        begin
            i2c_start; wr_byte(8'h84, ack_dummy); wr_byte(ptr, ack_dummy);
            for (i = 31; i >= 0; i = i - 1) wr_byte(val[8*i +: 8], ack_dummy);
            i2c_stop;
        end
    endtask
    task rd1(input [7:0] ptr, output [7:0] val);
        begin
            i2c_start; wr_byte(8'h84, ack_dummy); wr_byte(ptr, ack_dummy);
            i2c_rstart; wr_byte(8'h85, ack_dummy); rd_byte(0, val); i2c_stop;
        end
    endtask
    task rd32(input [7:0] ptr, output [255:0] val);
        integer i; reg [7:0] b;
        begin
            i2c_start; wr_byte(8'h84, ack_dummy); wr_byte(ptr, ack_dummy);
            i2c_rstart; wr_byte(8'h85, ack_dummy);
            for (i = 31; i >= 0; i = i - 1) begin rd_byte(i != 0, b); val[8*i +: 8] = b; end
            i2c_stop;
        end
    endtask

    task poll_done;
        integer n;
        begin
            v8 = 8'h00; n = 0;
            while (!(v8 & 8'h02) && n < 800) begin #100000; rd1(8'h00, v8); n = n + 1; end
            if (!(v8 & 8'h02)) begin errors = errors + 1; $display("FAIL: timeout waiting for done"); end
        end
    endtask

    task expect_err(input [7:0] code, input [255:0] what_id);
        reg [7:0] e;
        begin
            rd1(8'h02, e);
            if (e !== code) begin errors = errors + 1; $display("FAIL: error code %0d, expected %0d", e, code); end
            else $display("PASS: error code %0d as expected", e);
        end
    endtask

    task check(input cond, input [8*40-1:0] name);
        begin
            if (!cond) begin errors = errors + 1; $display("FAIL: %0s", name); end
            else $display("PASS: %0s", name);
        end
    endtask

    reg [255:0] z_hash, saved_d, px, py, r1, s1, r2, s2;
    integer k;

    initial begin
        z_hash = 256'h2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824;   // SHA-256("hello")
        repeat (10) @(posedge clk); rst_n = 1; repeat (20) @(posedge clk);

        // ---- basic identification / initial state ----
        rd1(8'hFF, v8);        check(v8 === 8'hA1, "version register reads 0xA1");
        rd1(8'h00, v8);        check(v8[3] === 1'b0, "no key present after power-up");

        // ---- commands that need a key must refuse ----
        wr1(8'h01, 8'h03); #200000; expect_err(8'd2, 0);
        wr1(8'h01, 8'h02); #200000; expect_err(8'd2, 0);
        wr1(8'h01, 8'hEE); #200000; expect_err(8'd8, 0);

        // ---- generate key on the module ----
        wr1(8'h01, 8'h01); poll_done;
        expect_err(8'd0, 0);
        rd1(8'h00, v8);        check(v8[3] === 1'b1, "key present after GENKEY");
        check(nvm_ok === 1'b1 && nvm_mem === dut.u_vault.d_q, "key mirrored to non-volatile store");
        check(dut.u_vault.d_q !== 256'd0 && dut.u_vault.d_q < 256'hFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
              "generated key is in [1, n-1]");
        saved_d = dut.u_vault.d_q;                                   // testbench-only peek

        // ---- second GENKEY must not overwrite ----
        wr1(8'h01, 8'h01); #200000; expect_err(8'd3, 0);
        check(dut.u_vault.d_q === saved_d, "existing key not overwritten");

        // ---- public key ----
        wr1(8'h01, 8'h03); poll_done; expect_err(8'd0, 0);
        rd32(8'h70, px); rd32(8'h90, py);
        $display("PUBX=%h", px);
        $display("PUBY=%h", py);

        // ---- sign (twice, same digest: hedged nonce => different signatures) ----
        wr32(8'h10, z_hash);
        rd32(8'h10, v256);     check(v256 === z_hash, "digest register read-back");
        $display("HASH=%h", z_hash);
        wr1(8'h01, 8'h02); poll_done; expect_err(8'd0, 0);
        rd32(8'h30, r1); rd32(8'h50, s1);
        $display("SIG1 r=%h", r1); $display("SIG1 s=%h", s1);
        wr1(8'h01, 8'h02); poll_done; expect_err(8'd0, 0);
        rd32(8'h30, r2); rd32(8'h50, s2);
        $display("SIG2 r=%h", r2); $display("SIG2 s=%h", s2);
        check(r1 !== r2, "hedged nonce: two signatures of one digest differ");

        // ---- physical presence: no button => erase must time out, key must survive ----
        confirm = 0;
        wr1(8'h01, 8'h05); #700000;
        rd1(8'h00, v8);        check(v8[1] === 1'b1 && v8[2] === 1'b1, "erase without confirm ends with error");
        expect_err(8'd5, 0);
        check(dut.u_vault.d_q === saved_d && nvm_ok === 1'b1, "key survives unconfirmed erase");
        confirm = 1;

        // ---- persistence across power cycle ----
        rst_n = 0; repeat (6) @(posedge clk); rst_n = 1; repeat (20) @(posedge clk);
        rd1(8'h00, v8);        check(v8[3] === 1'b1, "key restored from non-volatile store after reset");
        check(dut.u_vault.d_q === saved_d, "restored key identical");

        // ---- tamper in the middle of a signing operation ----
        wr32(8'h10, z_hash);
        wr1(8'h01, 8'h02);
        #300000;
        check(dut.u_core.busy === 1'b1, "signing in progress before tamper");
        #13 tamper = 1; #37 tamper = 0;                              // short, asynchronous pulse
        check(dut.u_vault.d_q === 256'd0, "tamper: key register zeroized immediately");
        check(nvm_mem === 256'd0 && nvm_ok === 1'b0, "tamper: non-volatile key erased");
        #5000;
        check(dut.u_core.busy === 1'b0, "tamper: signer aborted");
        begin : chk_regs
            reg allzero;
            allzero = 1'b1;
            for (k = 0; k < 32; k = k + 1) if (dut.u_core.rf[k] !== 256'd0) allzero = 0;
            check(allzero, "tamper: signer register file wiped");
        end
        check(dut.u_hmac.key_r === 256'd0 && dut.u_hmac.msg_r === 1536'd0, "tamper: HMAC key/message wiped");
        check(dut.k_reg === 256'd0 && dut.ent_extra === 256'd0, "tamper: nonce and entropy wiped");
        rd1(8'h00, v8);        check(v8[4] === 1'b1 && v8[3] === 1'b0, "tamper flag set, key not present");
        expect_err(8'd7, 0);
        rd32(8'h10, v256);     check(v256 === 256'd0, "tamper: digest register wiped");
        wr1(8'h01, 8'h02); #200000; expect_err(8'd7, 0);
        wr1(8'h01, 8'h01); #200000; expect_err(8'd7, 0);
        check(dut.u_vault.d_q === 256'd0, "module stays locked after tamper");

        // ---- recover with a reset: key gone, fresh key can be generated ----
        rst_n = 0; repeat (6) @(posedge clk); rst_n = 1; repeat (20) @(posedge clk);
        rd1(8'h00, v8);        check(v8[3] === 1'b0 && v8[4] === 1'b0, "after reset: no key, tamper flag cleared");
        wr1(8'h01, 8'h01); poll_done; expect_err(8'd0, 0);
        check(dut.u_vault.d_q !== 256'd0 && dut.u_vault.d_q !== saved_d, "new key differs from the destroyed key");

        // ---- erase with button ----
        wr1(8'h01, 8'h05); poll_done; expect_err(8'd0, 0);
        check(dut.u_vault.d_q === 256'd0 && nvm_ok === 1'b0, "confirmed ERASE zeroizes key and NVM");

        if (errors == 0) $display("ALL SYSTEM TESTS PASSED");
        else             $display("%0d SYSTEM TESTS FAILED", errors);
        $finish;
    end
endmodule
