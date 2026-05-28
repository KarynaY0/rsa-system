package rsa.ui;

import rsa.core.RSACore;
import rsa.storage.RSAStorage;

import javax.swing.*;
import javax.swing.border.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.*;
import java.io.File;
import java.math.BigInteger;
import java.util.List;

/**
 * Main application window — RSA Encryption & Decryption System.
 * Dark industrial aesthetic, tabbed step-by-step workflow.
 */
public class MainWindow extends JFrame {

    // ── Palette ──────────────────────────────────────
    static final Color BG       = new Color(0x0D0D0D);
    static final Color PANEL    = new Color(0x161616);
    static final Color CARD     = new Color(0x1E1E1E);
    static final Color BORDER   = new Color(0x2A2A2A);
    static final Color ACCENT   = new Color(0xE8C547);   // amber
    static final Color ACCENT2  = new Color(0x4FC3F7);   // ice blue
    static final Color TEXT     = new Color(0xEEEEEE);
    static final Color DIM      = new Color(0x888888);
    static final Color SUCCESS  = new Color(0x66BB6A);
    static final Color ERROR    = new Color(0xEF5350);
    static final Color RED_DIM  = new Color(0x3E1515);

    // ── State ─────────────────────────────────────────
    RSACore.RSAParams params;
    List<BigInteger>  currentCipher;

    // ── Widgets (shared) ──────────────────────────────
    JLabel statusBar;

    public MainWindow() {
        super("RSA Encryption System — Level B");
        applyLookAndFeel();
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setSize(1000, 760);
        setLocationRelativeTo(null);
        setBackground(BG);

        JPanel root = new JPanel(new BorderLayout(0, 0));
        root.setBackground(BG);
        root.add(buildHeader(), BorderLayout.NORTH);
        root.add(buildTabs(),   BorderLayout.CENTER);
        root.add(buildStatus(), BorderLayout.SOUTH);
        setContentPane(root);
    }

    // ─────────────────────────────────────────────────
    //  HEADER
    // ─────────────────────────────────────────────────
    private JPanel buildHeader() {
        JPanel p = new JPanel(new BorderLayout());
        p.setBackground(PANEL);
        p.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, BORDER));
        p.setPreferredSize(new Dimension(0, 64));

        JLabel title = new JLabel("  ⬡  RSA ENCRYPTION SYSTEM");
        title.setFont(new Font("Monospaced", Font.BOLD, 18));
        title.setForeground(ACCENT);
        p.add(title, BorderLayout.WEST);

        JLabel sub = new JLabel("Level B — Manual Implementation  ");
        sub.setFont(new Font("Monospaced", Font.PLAIN, 12));
        sub.setForeground(DIM);
        p.add(sub, BorderLayout.EAST);
        return p;
    }

    // ─────────────────────────────────────────────────
    //  TABS
    // ─────────────────────────────────────────────────
    private JTabbedPane buildTabs() {
        JTabbedPane tabs = new JTabbedPane();
        tabs.setBackground(BG);
        tabs.setForeground(TEXT);
        tabs.setFont(new Font("Monospaced", Font.BOLD, 13));
        UIManager.put("TabbedPane.selected",    CARD);
        UIManager.put("TabbedPane.background",  PANEL);
        UIManager.put("TabbedPane.foreground",  TEXT);

        tabs.addTab("① Key Generation", buildKeyTab());
        tabs.addTab("② Encrypt",        buildEncryptTab());
        tabs.addTab("③ Decrypt",        buildDecryptTab());
        tabs.addTab("④ Math Attack",    buildAttackTab());
        tabs.addTab("  Algorithm",      buildInfoTab());
        return tabs;
    }

    // ─────────────────────────────────────────────────
    //  TAB 1 — KEY GENERATION
    // ─────────────────────────────────────────────────
    private JPanel buildKeyTab() {
        JPanel root = card();
        root.setLayout(new BorderLayout(16, 16));
        root.setBorder(pad(20));

        // ── Inputs row ───────────────────────────────
        JPanel inputs = new JPanel(new GridLayout(1, 2, 20, 0));
        inputs.setOpaque(false);

        JTextField pField = styledField("e.g.  61");
        JTextField qField = styledField("e.g.  53");
        inputs.add(labeledField("Prime  p", pField));
        inputs.add(labeledField("Prime  q", qField));

        // ── Results area ─────────────────────────────
        JTextArea results = styledArea();
        results.setEditable(false);
        results.setFont(new Font("Monospaced", Font.PLAIN, 13));

        // ── Button ───────────────────────────────────
        JButton btn = accentButton("GENERATE KEYS");
        btn.addActionListener(e -> {
            try {
                long p = Long.parseLong(pField.getText().trim());
                long q = Long.parseLong(qField.getText().trim());
                params = RSACore.generateParams(p, q);

                results.setText(String.format(
                    "═══════════════════════════════════════\n" +
                    "  RSA PARAMETERS\n" +
                    "═══════════════════════════════════════\n\n" +
                    "  p   =  %d\n" +
                    "  q   =  %d\n\n" +
                    "  n   =  p × q  =  %s\n" +
                    "  φ   =  (p−1)(q−1)  =  %s\n\n" +
                    "───────────────────────────────────────\n" +
                    "  PUBLIC KEY\n" +
                    "    e =  %s\n" +
                    "    n =  %s\n\n" +
                    "  PRIVATE KEY\n" +
                    "    d =  %s  (e⁻¹ mod φ)\n" +
                    "    n =  %s\n" +
                    "───────────────────────────────────────\n" +
                    "  GCD(e, φ) = %s  ✓\n",
                    params.p.longValueExact(), params.q.longValueExact(),
                    params.n, params.phi,
                    params.e, params.n,
                    params.d, params.n,
                    RSACore.gcd(params.e, params.phi)
                ));
                status("Keys generated — n=" + params.n + "  e=" + params.e, SUCCESS);
            } catch (NumberFormatException ex) {
                error("Enter valid integer values for p and q.");
            } catch (Exception ex) {
                error(ex.getMessage());
            }
        });

        JPanel top = new JPanel(new BorderLayout(0, 12));
        top.setOpaque(false);
        top.add(inputs, BorderLayout.CENTER);
        top.add(btn, BorderLayout.SOUTH);

        root.add(sectionLabel("① INPUT PRIME NUMBERS p AND q"), BorderLayout.NORTH);
        root.add(top, BorderLayout.NORTH);

        JPanel center = new JPanel(new BorderLayout(0, 8));
        center.setOpaque(false);
        center.add(sectionLabel("CALCULATED PARAMETERS"), BorderLayout.NORTH);
        center.add(new JScrollPane(results), BorderLayout.CENTER);

        // Stack top + center
        JPanel main = new JPanel(new BorderLayout(0, 16));
        main.setOpaque(false);
        main.add(top, BorderLayout.NORTH);
        main.add(center, BorderLayout.CENTER);

        root.add(main, BorderLayout.CENTER);
        return root;
    }

    // ─────────────────────────────────────────────────
    //  TAB 2 — ENCRYPT
    // ─────────────────────────────────────────────────
    private JPanel buildEncryptTab() {
        JPanel root = card();
        root.setLayout(new BorderLayout(0, 16));
        root.setBorder(pad(20));

        JTextArea plainInput = styledArea();
        plainInput.setFont(new Font("Serif", Font.PLAIN, 15));
        plainInput.setLineWrap(true);

        JTextArea cipherOutput = styledArea();
        cipherOutput.setEditable(false);
        cipherOutput.setFont(new Font("Monospaced", Font.PLAIN, 11));

        JButton encryptBtn = accentButton("ENCRYPT  →");
        JButton saveBtn    = dimButton("SAVE TO FILE");
        saveBtn.setEnabled(false);

        encryptBtn.addActionListener(e -> {
            if (params == null) { error("Generate keys first (tab ①)."); return; }
            String text = plainInput.getText();
            if (text.isEmpty()) { error("Enter plaintext to encrypt."); return; }
            try {
                currentCipher = RSACore.encrypt(text, params.publicKey());
                cipherOutput.setText(RSACore.cipherToString(currentCipher));
                saveBtn.setEnabled(true);
                status("Encrypted " + text.length() + " character(s).", SUCCESS);
            } catch (Exception ex) {
                error(ex.getMessage());
            }
        });

        saveBtn.addActionListener(e -> {
            JFileChooser fc = fileChooser();
            if (fc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
                File f = ensureExt(fc.getSelectedFile());
                try {
                    RSAStorage.save(f, currentCipher, params.publicKey(), plainInput.getText());
                    status("Saved: " + f.getAbsolutePath(), SUCCESS);
                } catch (Exception ex) {
                    error("Save failed: " + ex.getMessage());
                }
            }
        });

        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 0));
        btnRow.setOpaque(false);
        btnRow.add(encryptBtn);
        btnRow.add(saveBtn);

        JPanel main = new JPanel(new GridLayout(2, 1, 0, 16));
        main.setOpaque(false);
        main.add(labeledScrollArea("PLAINTEXT  (enter text to encrypt)", plainInput));
        main.add(labeledScrollArea("CIPHERTEXT  (space-separated BigInteger values)", cipherOutput));

        root.add(main, BorderLayout.CENTER);
        root.add(btnRow, BorderLayout.SOUTH);
        return root;
    }

    // ─────────────────────────────────────────────────
    //  TAB 3 — DECRYPT
    // ─────────────────────────────────────────────────
    private JPanel buildDecryptTab() {
        JPanel root = card();
        root.setLayout(new BorderLayout(0, 16));
        root.setBorder(pad(20));

        JTextArea cipherInput = styledArea();
        cipherInput.setFont(new Font("Monospaced", Font.PLAIN, 11));

        JTextArea plainOutput = styledArea();
        plainOutput.setEditable(false);
        plainOutput.setFont(new Font("Serif", Font.PLAIN, 15));

        JButton loadBtn    = dimButton("LOAD FROM FILE");
        JButton decryptBtn = accentButton("← DECRYPT");

        loadBtn.addActionListener(e -> {
            JFileChooser fc = fileChooser();
            if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                try {
                    RSAStorage.LoadResult lr = RSAStorage.load(fc.getSelectedFile());
                    cipherInput.setText(RSACore.cipherToString(lr.cipher()));
                    // If we don't have params, try to restore from file's public key info
                    status("Loaded file. Public key: n=" + lr.pub().n() + "  e=" + lr.pub().e(), ACCENT2);
                } catch (Exception ex) {
                    error("Load failed: " + ex.getMessage());
                }
            }
        });

        decryptBtn.addActionListener(e -> {
            if (params == null) { error("Generate keys first (tab ①) so the private key is known."); return; }
            String cipherStr = cipherInput.getText().trim();
            if (cipherStr.isEmpty()) { error("No ciphertext to decrypt."); return; }
            try {
                List<BigInteger> cipher = RSACore.stringToCipher(cipherStr);
                String plain = RSACore.decrypt(cipher, params.privateKey());
                plainOutput.setText(plain);
                status("Decrypted " + cipher.size() + " block(s) successfully.", SUCCESS);
            } catch (Exception ex) {
                error("Decryption failed: " + ex.getMessage());
            }
        });

        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 0));
        btnRow.setOpaque(false);
        btnRow.add(loadBtn);
        btnRow.add(decryptBtn);

        JPanel main = new JPanel(new GridLayout(2, 1, 0, 16));
        main.setOpaque(false);
        main.add(labeledScrollArea("CIPHERTEXT  (paste or load from file)", cipherInput));
        main.add(labeledScrollArea("DECRYPTED PLAINTEXT", plainOutput));

        root.add(main, BorderLayout.CENTER);
        root.add(btnRow, BorderLayout.SOUTH);
        return root;
    }

    // ─────────────────────────────────────────────────
    //  TAB 4 — MATHEMATICAL ATTACK
    // ─────────────────────────────────────────────────
    private JPanel buildAttackTab() {
        JPanel root = card();
        root.setLayout(new BorderLayout(0, 16));
        root.setBorder(pad(20));

        JLabel info = new JLabel("<html><body style='color:#888; font-family:monospace; font-size:11px'>" +
            "This tab demonstrates the mathematical attack: given only the public key (n, e) and ciphertext, <br>" +
            "factor n to recover p and q, recompute φ and the private key d, then decrypt.</body></html>");

        // Inputs
        JTextField nField = styledField("n  (from public key)");
        JTextField eField = styledField("e  (from public key)");
        JTextArea  cipherInput = styledArea();
        cipherInput.setFont(new Font("Monospaced", Font.PLAIN, 11));

        JTextArea results = styledArea();
        results.setEditable(false);
        results.setFont(new Font("Monospaced", Font.PLAIN, 13));

        // Pre-fill from current params if available
        JButton prefillBtn = dimButton("PRE-FILL FROM CURRENT SESSION");
        prefillBtn.addActionListener(e -> {
            if (params == null || currentCipher == null) {
                error("Encrypt something first (tabs ①②).");
                return;
            }
            nField.setText(params.n.toString());
            eField.setText(params.e.toString());
            cipherInput.setText(RSACore.cipherToString(currentCipher));
        });

        JButton attackBtn = new JButton("RUN ATTACK  ⚡");
        styleButton(attackBtn, ERROR, Color.WHITE);

        attackBtn.addActionListener(e -> {
            try {
                BigInteger n = new BigInteger(nField.getText().trim());
                BigInteger ev = new BigInteger(eField.getText().trim());
                List<BigInteger> cipher = RSACore.stringToCipher(cipherInput.getText().trim());

                RSACore.AttackResult ar = RSACore.decryptViaAttack(cipher, n, ev);

                results.setText(String.format(
                    "═══════════════════════════════════════\n" +
                    "  ATTACK RESULTS\n" +
                    "═══════════════════════════════════════\n\n" +
                    "  Step 1: Factor n=%s\n" +
                    "    → p = %d\n" +
                    "    → q = %d\n\n" +
                    "  Step 2: Compute φ = (p−1)(q−1)\n" +
                    "    → φ = %s\n\n" +
                    "  Step 3: Recover private key\n" +
                    "    → d = e⁻¹ mod φ = %s\n\n" +
                    "  Step 4: Decrypt\n" +
                    "    → PLAINTEXT: \"%s\"\n" +
                    "═══════════════════════════════════════",
                    n, ar.p(), ar.q(), ar.phi(), ar.d(), ar.plaintext()
                ));
                status("Attack succeeded — plaintext recovered!", SUCCESS);
            } catch (Exception ex) {
                error("Attack failed: " + ex.getMessage());
            }
        });

        JPanel topInputs = new JPanel(new GridLayout(1, 2, 12, 0));
        topInputs.setOpaque(false);
        topInputs.add(labeledField("n (modulus)", nField));
        topInputs.add(labeledField("e (public exponent)", eField));

        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 0));
        btnRow.setOpaque(false);
        btnRow.add(prefillBtn);
        btnRow.add(attackBtn);

        JPanel top = new JPanel(new BorderLayout(0, 10));
        top.setOpaque(false);
        top.add(info, BorderLayout.NORTH);
        top.add(topInputs, BorderLayout.CENTER);
        top.add(labeledScrollArea("CIPHERTEXT", cipherInput), BorderLayout.SOUTH);

        JPanel main = new JPanel(new BorderLayout(0, 12));
        main.setOpaque(false);
        main.add(top, BorderLayout.NORTH);
        main.add(btnRow, BorderLayout.CENTER);
        main.add(labeledScrollArea("ATTACK LOG", results), BorderLayout.CENTER);

        root.add(main, BorderLayout.CENTER);
        return root;
    }

    // ─────────────────────────────────────────────────
    //  TAB 5 — ALGORITHM EXPLANATION
    // ─────────────────────────────────────────────────
    private JPanel buildInfoTab() {
        JPanel root = card();
        root.setLayout(new BorderLayout());
        root.setBorder(pad(20));

        JTextArea text = styledArea();
        text.setEditable(false);
        text.setFont(new Font("Monospaced", Font.PLAIN, 13));
        text.setLineWrap(true);
        text.setWrapStyleWord(true);
        text.setText(
            "RSA ALGORITHM — HOW IT WORKS\n" +
            "══════════════════════════════════════════════════════\n\n" +

            "1. KEY GENERATION\n" +
            "   ─────────────\n" +
            "   • Choose two distinct primes p and q.\n" +
            "   • Compute n = p × q  (the modulus, public).\n" +
            "   • Compute φ(n) = (p−1)(q−1)  (Euler's totient).\n" +
            "   • Choose e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1.\n" +
            "   • Compute d = e⁻¹ mod φ(n) using the Extended Euclidean Algorithm.\n" +
            "   • Public key  = (n, e)\n" +
            "   • Private key = (n, d)\n\n" +

            "2. EUCLIDEAN ALGORITHM\n" +
            "   ───────────────────\n" +
            "   gcd(a, b):\n" +
            "     while b ≠ 0:\n" +
            "       (a, b) ← (b, a mod b)\n" +
            "     return a\n\n" +

            "3. EXTENDED EUCLIDEAN ALGORITHM\n" +
            "   ─────────────────────────────\n" +
            "   Finds x, y such that: a·x + b·y = gcd(a, b)\n" +
            "   Used to compute d = e⁻¹ mod φ(n),\n" +
            "   since e·d ≡ 1 (mod φ(n)).\n\n" +

            "4. ENCRYPTION\n" +
            "   ──────────\n" +
            "   For each character with Unicode codepoint m:\n" +
            "     c = m^e mod n\n" +
            "   Condition: m < n (use larger primes for larger codepoints).\n\n" +

            "5. DECRYPTION\n" +
            "   ──────────\n" +
            "   For each ciphertext block c:\n" +
            "     m = c^d mod n\n" +
            "   Converts m back to a Unicode character.\n\n" +

            "6. SECURITY INTUITION\n" +
            "   ──────────────────\n" +
            "   • The public key (n, e) can be freely shared.\n" +
            "   • Recovering d from (n, e) requires factoring n.\n" +
            "   • Factoring large semiprimes (e.g. 2048-bit n) is\n" +
            "     computationally infeasible — that is what keeps RSA secure.\n" +
            "   • In this demo, small primes are used intentionally so\n" +
            "     the mathematical attack (tab ④) can factor n easily.\n\n" +

            "7. DATA FLOW IN THIS APPLICATION\n" +
            "   ───────────────────────────────\n" +
            "   Plaintext → [Unicode codepoints] → RSA encrypt (e, n)\n" +
            "            → ciphertext BigIntegers → saved to .rsaenc file\n\n" +
            "   .rsaenc file → load ciphertext + public key (n, e)\n" +
            "              → RSA decrypt (d, n) → Unicode codepoints\n" +
            "              → Plaintext\n"
        );

        root.add(new JScrollPane(text), BorderLayout.CENTER);
        return root;
    }

    // ─────────────────────────────────────────────────
    //  STATUS BAR
    // ─────────────────────────────────────────────────
    private JPanel buildStatus() {
        JPanel p = new JPanel(new BorderLayout());
        p.setBackground(PANEL);
        p.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, BORDER));
        p.setPreferredSize(new Dimension(0, 32));

        statusBar = new JLabel("  Ready.");
        statusBar.setFont(new Font("Monospaced", Font.PLAIN, 12));
        statusBar.setForeground(DIM);
        p.add(statusBar, BorderLayout.CENTER);
        return p;
    }

    void status(String msg, Color color) {
        statusBar.setText("  " + msg);
        statusBar.setForeground(color);
    }

    void error(String msg) {
        status("✖  " + msg, ERROR);
        JOptionPane.showMessageDialog(this, msg, "Error", JOptionPane.ERROR_MESSAGE);
    }

    // ─────────────────────────────────────────────────
    //  UI HELPERS
    // ─────────────────────────────────────────────────

    private void applyLookAndFeel() {
        try { UIManager.setLookAndFeel(UIManager.getCrossPlatformLookAndFeelClassName()); }
        catch (Exception ignored) {}
        UIManager.put("Panel.background",        BG);
        UIManager.put("TextArea.background",     CARD);
        UIManager.put("TextArea.foreground",     TEXT);
        UIManager.put("TextField.background",    CARD);
        UIManager.put("TextField.foreground",    TEXT);
        UIManager.put("ScrollPane.background",   CARD);
        UIManager.put("OptionPane.background",   PANEL);
        UIManager.put("OptionPane.messageForeground", TEXT);
    }

    JPanel card() {
        JPanel p = new JPanel();
        p.setBackground(BG);
        return p;
    }

    Border pad(int n) { return new EmptyBorder(n, n, n, n); }

    JTextArea styledArea() {
        JTextArea a = new JTextArea();
        a.setBackground(CARD);
        a.setForeground(TEXT);
        a.setCaretColor(ACCENT);
        a.setBorder(new EmptyBorder(8, 10, 8, 10));
        a.setSelectionColor(new Color(0x3A3A00));
        return a;
    }

    JTextField styledField(String hint) {
        JTextField f = new JTextField();
        f.setBackground(CARD);
        f.setForeground(TEXT);
        f.setCaretColor(ACCENT);
        f.setFont(new Font("Monospaced", Font.PLAIN, 14));
        f.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(BORDER),
            new EmptyBorder(6, 10, 6, 10)));
        f.setToolTipText(hint);
        return f;
    }

    JButton accentButton(String label) {
        JButton b = new JButton(label);
        styleButton(b, ACCENT, Color.BLACK);
        return b;
    }

    JButton dimButton(String label) {
        JButton b = new JButton(label);
        styleButton(b, BORDER, DIM);
        return b;
    }

    void styleButton(JButton b, Color bg, Color fg) {
        b.setBackground(bg);
        b.setForeground(fg);
        b.setFont(new Font("Monospaced", Font.BOLD, 13));
        b.setFocusPainted(false);
        b.setBorderPainted(false);
        b.setPreferredSize(new Dimension(200, 40));
        b.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
    }

    JLabel sectionLabel(String text) {
        JLabel l = new JLabel(text);
        l.setFont(new Font("Monospaced", Font.BOLD, 11));
        l.setForeground(DIM);
        l.setBorder(new EmptyBorder(0, 0, 6, 0));
        return l;
    }

    JPanel labeledField(String label, JTextField field) {
        JPanel p = new JPanel(new BorderLayout(0, 6));
        p.setOpaque(false);
        p.add(sectionLabel(label), BorderLayout.NORTH);
        p.add(field, BorderLayout.CENTER);
        return p;
    }

    JPanel labeledScrollArea(String label, JTextArea area) {
        JPanel p = new JPanel(new BorderLayout(0, 6));
        p.setOpaque(false);
        p.add(sectionLabel(label), BorderLayout.NORTH);
        JScrollPane sp = new JScrollPane(area);
        sp.setBorder(BorderFactory.createLineBorder(BORDER));
        sp.getViewport().setBackground(CARD);
        p.add(sp, BorderLayout.CENTER);
        return p;
    }

    JFileChooser fileChooser() {
        JFileChooser fc = new JFileChooser();
        fc.setFileFilter(new FileNameExtensionFilter("RSA Encrypted Files (*.rsaenc)", "rsaenc"));
        fc.setCurrentDirectory(new File("data"));
        return fc;
    }

    File ensureExt(File f) {
        String name = f.getName();
        return name.endsWith(RSAStorage.EXT) ? f : new File(f.getParent(), name + RSAStorage.EXT);
    }
}
