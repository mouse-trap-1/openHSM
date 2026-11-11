`timescale 1ns/1ps
//------------------------------------------------------------------------------
// Protocol 0xB2 testbench (V0.5): response MAC, lockout, verify-before-release with injected
// faults, buffer hygiene, confidential card secrets, ceremony pin.  One sign_node_top (0x48).
//
//   iverilog -g2005 -o sim_v05 tb_v05.v $SRC        (SRC as in the README)
//   vvp sim_v05 | tee v05.log ; python3 verify_v05.py v05.log
//
// A separate hmac_sha256 instance plays the role of the SoC secure-world driver and
// computes the command MACs.  The simulation TRNG is deterministic and NOT random.
//------------------------------------------------------------------------------
module tb_v05;
    reg clk = 0, rst_a = 0, rst_b = 0, tamper_a = 0, tamper_b = 0;
    always #5 clk = ~clk;

    // ---------------- shared open-drain I2C bus ----------------
    reg  m_scl = 1, m_sda_low = 0;
    wire sda_oe_a;
    wire sda = (m_sda_low | sda_oe_a | sda_oe_b) ? 1'b0 : 1'b1;

    // ---------------- SPI links ----------------
    reg sclk_a = 0, cs_a = 1, mosi_a = 0, sclk_b = 0, cs_b = 1, mosi_b = 0;

    reg ceremony_a = 0;
    wire busy_a, kek_a, tam_a;
    wire sda_oe_b = 1'b0;
    sign_node_top #(.I2C_ADDR(7'h48), .SIM_TRNG(1), .TRNG_DIV(2)) dutA (
        .clk(clk), .rst_n(rst_a), .scl_i(m_scl), .sda_i(sda), .sda_oe(sda_oe_a),
        .spi_sclk(sclk_a), .spi_cs_n(cs_a), .spi_mosi(mosi_a), .tamper(tamper_a), .ceremony(ceremony_a),
        .led_busy(busy_a), .led_kek(kek_a), .led_tamper(tam_a));

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



    localparam [79:0] LBL_RESP = 80'h534e2d524553502d7631;      // "SN-RESP-v1"
    localparam [79:0] LBL_CONF = 80'h534e2d434f4e462d7631;      // "SN-CONF-v1"
    localparam [255:0] SA  = 256'h1111111111111111_2222222222222222_3333333333333333_4444444444444444;
    localparam [255:0] SA2 = 256'h5555555555555555_6666666666666666_7777777777777777_8888888888888888;
    localparam [255:0] DIGEST  = 256'h2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824;
    localparam [255:0] DIGEST2 = 256'hfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0;   // >= n: exercises z mod n

    function [255:0] rcard(input [7:0] x); rcard = {32{x}}; endfunction

    // read back every buffer, the error code and RMAC; check RMAC against the host's own HMAC (X1)
    reg [127:0] f_wid; reg [3:0] f_err; reg [255:0] f_rmac;
    task check_resp(input [7:0] cmd, input [8*40-1:0] name);
        begin
            rdN(0, 8'h02, 1);  f_err = rd_val[3:0];
            rdN(0, 8'h18, 16); f_wid = rd_val[127:0];
            fetch(0);
            rdN(0, 8'hC4, 32); f_rmac = rd_val;
            host_hmac(chan[0], {LBL_RESP, nonce_n[0], ctr_n[0], cmd, 4'd0, f_err, f_wid, s_iv, s_tag, s_A, s_B, s_C, 160'd0}, 8'd172);
            $display("RESP cmd=%h ctr=%h err=%h wid=%h iv=%h tag=%h A=%h B=%h C=%h rmac=%h",
                     cmd, ctr_n[0], {4'd0, f_err}, f_wid, s_iv, s_tag, s_A, s_B, s_C, f_rmac);
            check(f_rmac === hm_out && f_rmac !== 256'd0, name);
        end
    endtask

    // a command with a wrong MAC, without rewriting the data buffers
    task issue_bad;
        begin
            ctr_n[0] = ctr_n[0] + 1;
            wrN(0, 8'h04, ctr_n[0], 4);
            wrN(0, 8'hA4, 256'hBAD0BAD0BAD0BAD0BAD0BAD0BAD0BAD0BAD0BAD0BAD0BAD0BAD0BAD0BAD0BAD0, 32);
            wrN(0, 8'h01, 256'h17, 1);
            poll_done(0);
        end
    endtask

    // SHARE_GET_C / SHARE_PUT_C: mask the card secret with HMAC(chan, "SN-CONF-v1"||nonce||ctr) (X5)
    reg [255:0] pad, busB;
    task issue_conf(input [7:0] cmd, input [255:0] r);
        reg [31:0] c;
        begin
            c = ctr_n[0] + 1;
            host_hmac(chan[0], {LBL_CONF, nonce_n[0], c, 1296'd0}, 8'd30); pad = hm_out;
            s_B = r ^ pad; busB = s_B;
            issue(0, cmd, 1'b0);
        end
    endtask

    reg [255:0] keyA, wrapA, sh_ct [1:3];
    reg [95:0]  sh_iv [1:3], wiv;
    reg [127:0] sh_tag [1:3], tmpl, wid1, wtag;
    integer x, k;
    // clock cycles each command keeps the module busy (for the performance table)
    integer cyc = 0; reg busy_d = 0;
    always @(posedge clk) begin
        busy_d <= busy_a;
        if (busy_a) cyc <= cyc + 1;
        if (busy_d && !busy_a) begin $display("CYCLES cmd=%h err=%0d n=%0d", dutA.cmd_b, dutA.err_code, cyc); cyc <= 0; end
    end
    reg [4:0] sign_step = 0;                     // last step of CMD_SIGN that executed (8 = scalar check, 9 = ladder check)
    always @(posedge clk) if (dutA.cmd == 8'h21 && dutA.st == 6'd1) sign_step <= dutA.step;

    initial begin
        chan[0] = 0; chan[1] = 0; nonce_n[0] = 0; nonce_n[1] = 0; ctr_n[0] = 0; ctr_n[1] = 0;
        wid1 = 128'h00112233445566778899aabbccddeeff;
        repeat (10) @(posedge clk); rst_a = 1; repeat (20) @(posedge clk);
        bring_up(0, SA);
        $display("S0=%h", SA); $display("NONCE0=%h", nonce_n[0]);
        rdN(0, 8'hFF, 1); check(rd_val[7:0] === 8'hB2, "VERSION reads 0xB2");
        rdN(0, 8'h03, 1); check(rd_val[4] === 1'b0 && rd_val[7] === 1'b0, "STATUS2: ceremony off, channel not locked");

        // ---------- X1: response MAC on success ----------
        s_A = 0; s_B = 0; s_C = 0; s_wid = wid1; s_iv = 0; s_tag = 0;
        issue(0, 8'h10, 1'b0); expect_err(0, 4'd0);
        keyA = dutA.u_ss.kek; $display("KEK=%h", keyA);
        check_resp(8'h10, "X1 KEK_GEN response MAC verifies");
        check(dutA.mac_in === 256'd0, "X4 command MAC register cleared after the command");
        s_A = 0; s_B = 0; s_C = 0; s_wid = wid1; s_iv = 0; s_tag = 0;
        issue(0, 8'h20, 1'b0); expect_err(0, 4'd0);
        check_resp(8'h20, "X1 GEN_WALLET response MAC verifies");
        wiv = s_iv; wtag = s_tag; wrapA = s_A;
        $display("WALLET wid=%h iv=%h tag=%h ct=%h", wid1, wiv, wtag, wrapA);
        $display("PUBX=%h", s_B); $display("PUBY=%h", s_C);

        // ---------- X3: a good signature passes its own verification ----------
        s_wid = wid1; s_iv = wiv; s_tag = wtag; s_A = wrapA; s_B = DIGEST; s_C = 0;
        issue(0, 8'h21, 1'b0); expect_err(0, 4'd0);
        check_resp(8'h21, "X1/X3 SIGN verified and response MAC ok");
        $display("HASH1=%h", DIGEST); $display("SIG1 r=%h", s_A); $display("SIG1 s=%h", s_B);

        // ---------- X3: fault in the scalar arithmetic (s corrupted) ----------
        s_wid = wid1; s_iv = wiv; s_tag = wtag; s_A = wrapA; s_B = DIGEST; s_C = 0;
        fork
            issue(0, 8'h21, 1'b0);
            begin
                wait (dutA.cmd == 8'h21 && dutA.step == 5'd4);
                force dutA.core_s = 256'h0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef;
                wait (dutA.cmd != 8'h21 || dutA.step != 5'd4);
                release dutA.core_s;
            end
        join
        expect_err(0, 4'd6);
        $display("X3 fault in s caught at SIGN step %0d", sign_step);
        check(sign_step == 5'd8, "X3 scalar check (s*k == +-(z + r*d)) caught the fault");
        check_resp(8'h21, "X3 faulted s withheld; error response MACed");
        check(s_A === 256'd0 && s_B === 256'd0 && s_iv === 96'd0 && s_tag === 128'd0, "X4 buffers are zero after the failed SIGN");

        // ---------- X3: fault inside the ladder (r and s consistent with a wrong point) ----------
        s_wid = wid1; s_iv = wiv; s_tag = wtag; s_A = wrapA; s_B = DIGEST; s_C = 0;
        fork
            issue(0, 8'h21, 1'b0);
            begin
                wait (dutA.cmd == 8'h21 && dutA.step == 5'd4 && dutA.core_busy);
                repeat (600000) @(posedge clk);                      // mid-ladder
                dutA.u_core.rf[0] = dutA.u_core.rf[0] ^ 256'h8;      // X of the ladder's R0
                $display("FAULT: flipped one bit of the ladder point R0.X mid-ladder");
            end
        join
        expect_err(0, 4'd6);
        $display("X3 ladder fault caught at SIGN step %0d", sign_step);
        check(sign_step == 5'd9, "X3 second ladder (x(k*G) == r) caught the fault");
        check_resp(8'h21, "X3 ladder fault withheld; error response MACed");
        check(s_A === 256'd0 && s_B === 256'd0, "X4 no signature bytes left after the ladder fault");

        // ---------- the next signature is good again (digest >= n) ----------
        s_wid = wid1; s_iv = wiv; s_tag = wtag; s_A = wrapA; s_B = DIGEST2; s_C = 0;
        issue(0, 8'h21, 1'b0); expect_err(0, 4'd0);
        check_resp(8'h21, "X3 signing recovers after faults");
        $display("HASH2=%h", DIGEST2); $display("SIG2 r=%h", s_A); $display("SIG2 s=%h", s_B);

        // ---------- X4: any error clears the data buffers ----------
        s_wid = wid1; s_iv = wiv; s_tag = wtag ^ 128'h1; s_A = wrapA; s_B = DIGEST; s_C = {32{8'h5a}};
        issue(0, 8'h21, 1'b0); expect_err(0, 4'd10);
        check_resp(8'h21, "X1 unwrap failure response MACed");
        check(s_A === 256'd0 && s_B === 256'd0 && s_C === 256'd0 && s_iv === 96'd0 && s_tag === 128'd0,
              "X4 IV, TAG, A, B, C cleared after an error");

        // ---------- X6: ceremony switch off -> KEK-moving commands do not exist ----------
        s_A = 0; s_C = 0; s_wid = 0; s_iv = 0; s_tag = 0; s_B = {8'd2, 8'd3, 240'd0};
        issue(0, 8'h50, 1'b0); expect_err(0, 4'd8); check_resp(8'h50, "X6 SPLIT_BEGIN refused, switch off");
        s_B = {8'd2, 8'd3, 240'd0}; issue(0, 8'h41, 1'b0); expect_err(0, 4'd8);
        s_B = 0; issue(0, 8'h42, 1'b0); expect_err(0, 4'd8);
        issue(0, 8'h45, 1'b0); expect_err(0, 4'd8);
        issue(0, 8'h46, 1'b0); expect_err(0, 4'd8);
        issue(0, 8'h51, 1'b0); expect_err(0, 4'd8);
        issue(0, 8'h53, 1'b0); expect_err(0, 4'd8);
        issue(0, 8'h54, 1'b0); expect_err(0, 4'd8);
        issue(0, 8'h56, 1'b0); expect_err(0, 4'd8);
        issue(0, 8'h57, 1'b0); expect_err(0, 4'd8);
        check(dutA.u_ss.kek === keyA && dutA.split_active === 1'b0, "X6 KEK untouched, no split started");
        issue(0, 8'h17, 1'b0); expect_err(0, 4'd0);                 // not gated
        check_resp(8'h17, "X6 KEK_FP still works with the switch off");
        $display("FP=%h", s_B);

        ceremony_a = 1; repeat (4) @(posedge clk);
        rdN(0, 8'h03, 1); check(rd_val[4] === 1'b1, "STATUS2 b4 follows the ceremony pin");

        // ---------- X5: split 2-of-3 with the card secret masked on the bus ----------
        s_A = 0; s_C = 0; s_wid = 0; s_iv = 0; s_tag = 0; s_B = {8'd2, 8'd3, 240'd0};
        issue(0, 8'h50, 1'b0); expect_err(0, 4'd0);
        rdN(0, 8'h18, 16); tmpl = rd_val[127:0]; $display("TEMPLATE=%h", tmpl);
        for (x = 1; x <= 3; x = x + 1) begin
            s_wid = {x[7:0], tmpl[119:0]}; s_A = 0; s_C = 0; s_iv = 0; s_tag = 0;
            if (x == 3) begin s_B = rcard(x[7:0]); issue(0, 8'h51, 1'b0); end      // plain form still works
            else begin
                issue_conf(8'h56, rcard(x[7:0]));
                check(busB !== rcard(x[7:0]), "X5 card secret is masked on the bus");
                $display("BUSB x=%0d ctr=%h masked=%h", x, ctr_n[0], busB);
            end
            expect_err(0, 4'd0);
            check_resp(x == 3 ? 8'h51 : 8'h56, "X1 share response MAC verifies");
            sh_iv[x] = s_iv; sh_tag[x] = s_tag; sh_ct[x] = s_A;
            check(s_B === 256'd0, "card secret not left in BUF_B");
            $display("SHARE x=%0d hdr=%h iv=%h tag=%h ct=%h", x, s_wid, s_iv, s_tag, s_A);
        end
        s_A = 0; s_B = 0; s_C = 0; s_wid = 0; s_iv = 0; s_tag = 0;
        issue(0, 8'h52, 1'b0); expect_err(0, 4'd0);
        issue(0, 8'h13, 1'b0); expect_err(0, 4'd0);
        check(dutA.u_ss.kek_valid === 1'b0, "KEK erased before the restore");

        // an unmasked secret sent to SHARE_PUT_C is unmasked into garbage and the share does not open
        s_wid = {8'd1, tmpl[119:0]}; s_iv = sh_iv[1]; s_tag = sh_tag[1]; s_A = sh_ct[1]; s_C = 0; s_B = rcard(8'd1);
        issue(0, 8'h57, 1'b0); expect_err(0, 4'd10);
        s_wid = {8'd1, tmpl[119:0]}; s_iv = sh_iv[1]; s_tag = sh_tag[1]; s_A = sh_ct[1]; s_C = 0;
        issue_conf(8'h57, rcard(8'd1)); expect_err(0, 4'd0);
        s_wid = {8'd3, tmpl[119:0]}; s_iv = sh_iv[3]; s_tag = sh_tag[3]; s_A = sh_ct[3]; s_C = 0;
        issue_conf(8'h57, rcard(8'd3)); expect_err(0, 4'd0);
        check_resp(8'h57, "X1 SHARE_PUT_C response MAC verifies");
        s_A = 0; s_B = 0; s_C = 0; s_wid = 0; s_iv = 0; s_tag = 0;
        issue(0, 8'h54, 1'b0); expect_err(0, 4'd0);
        check(dutA.u_ss.kek === keyA, "X5 KEK restored from masked shares equals the original");
        ceremony_a = 0; repeat (4) @(posedge clk);

        // ---------- X2: lockout ----------
        for (k = 0; k < 7; k = k + 1) begin issue_bad; end
        expect_err(0, 4'd5);
        rdN(0, 8'hC4, 32); check(rd_val === 256'd0, "X1 no response MAC after an authentication failure");
        rdN(0, 8'h03, 1); check(rd_val[7] === 1'b0, "X2 seven failures do not lock");
        s_A = 0; s_B = 0; s_C = 0; s_wid = 0; s_iv = 0; s_tag = 0;
        issue(0, 8'h17, 1'b0); expect_err(0, 4'd0);                 // success resets the count
        for (k = 0; k < 7; k = k + 1) begin issue_bad; end
        rdN(0, 8'h03, 1); check(rd_val[7] === 1'b0, "X2 the failure count restarted after a success");
        issue_bad;
        rdN(0, 8'h03, 1); check(rd_val[7] === 1'b1, "X2 eight consecutive failures lock the channel");
        s_A = 0; s_B = 0; s_C = 0; s_wid = 0; s_iv = 0; s_tag = 0;
        issue(0, 8'h17, 1'b0); expect_err(0, 4'd5);
        rdN(0, 8'h64, 32); check(rd_val === 256'd0, "X2 a correctly MACed command is refused while locked");
        check(dutA.u_ss.kek === keyA, "X2 lockout does not destroy the KEK");

        // reset clears the lock (and, being volatile, the KEK)
        rst_a = 0; repeat (6) @(posedge clk); rst_a = 1; repeat (20) @(posedge clk);
        bring_up(0, SA2);
        rdN(0, 8'h03, 1); check(rd_val[7] === 1'b0, "X2 reset unlocks the channel");
        s_A = 0; s_B = 0; s_C = 0; s_wid = 0; s_iv = 0; s_tag = 0;
        issue(0, 8'h10, 1'b0); expect_err(0, 4'd0);
        rdN(0, 8'hC4, 32); check(rd_val !== 256'd0, "new session answers with a response MAC");

        // ---------- tamper clears the response MAC too ----------
        #13 tamper_a = 1; #37 tamper_a = 0; repeat (4) @(posedge clk);
        check(dutA.rmac === 256'd0 && dutA.u_ss.kek === 256'd0 && dutA.u_ss.chan_key === 256'd0, "tamper zeroizes KEK, channel key and RMAC");

        if (errors == 0) $display("ALL V0.5 PROTOCOL TESTS PASSED");
        else             $display("%0d V0.5 PROTOCOL TESTS FAILED", errors);
        $finish;
    end
endmodule
