package com.jwtbreaker;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * Main UI for the JWTBreaker tab.
 *
 * Top: a table of detected JWTs.
 * Middle: the decoded header and payload of the selected token.
 * Bottom: attack buttons (alg:none, weak-secret brute-force, expiry check).
 */
public class JwtBreakerPanel extends JPanel {

    private static final Color VULN_RED = new Color(0xC0392B);
    private static final Color SECURE_GREEN = new Color(0x1E8449);

    private final MontoyaApi api;
    private final DefaultTableModel tableModel;
    private final JTable table;
    private final JTextArea decodedArea;
    private JTextArea resultArea;
    private JLabel statusLabel;
    private final List<JwtEntry> entries = new ArrayList<>();

    // Last alg:none token generated, used by Phase 4 repeater/copy buttons.
    private String lastGeneratedToken;

    public JwtBreakerPanel(MontoyaApi api) {
        super(new BorderLayout());
        this.api = api;

        String[] columns = {"Host", "Method", "Path", "Source", "Token"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        table = new JTable(tableModel);
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                showSelected();
            }
        });

        decodedArea = new JTextArea();
        decodedArea.setEditable(false);
        decodedArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        decodedArea.setText("Select a request above to decode its JWT.");

        JScrollPane tableScroll = new JScrollPane(table);
        tableScroll.setBorder(BorderFactory.createTitledBorder("Detected JWTs"));

        JScrollPane decodedScroll = new JScrollPane(decodedArea);
        decodedScroll.setBorder(BorderFactory.createTitledBorder("Decoded JWT"));

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, decodedScroll);
        split.setResizeWeight(0.4);
        split.setDividerLocation(240);

        add(split, BorderLayout.CENTER);
        add(buildSouthPanel(), BorderLayout.SOUTH);
    }

    private JPanel buildSouthPanel() {
        JPanel south = new JPanel(new BorderLayout());

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton algNoneBtn = new JButton("Test alg:none");
        JButton bruteBtn = new JButton("Brute-force Weak Secret");
        JButton expiryBtn = new JButton("Check Expiry");
        JButton repeaterBtn = new JButton("Send to Repeater");
        JButton copyBtn = new JButton("Copy Token");

        algNoneBtn.setToolTipText("Generate an alg:none version of the selected token");
        bruteBtn.setToolTipText("Try to crack the HMAC-SHA256 signing key using secrets.txt");
        expiryBtn.setToolTipText("Inspect the exp claim of the selected token");
        repeaterBtn.setToolTipText("Send the selected request with the generated alg:none token to Repeater");
        copyBtn.setToolTipText("Copy the generated token to the clipboard");

        buttons.add(algNoneBtn);
        buttons.add(bruteBtn);
        buttons.add(expiryBtn);
        buttons.add(repeaterBtn);
        buttons.add(copyBtn);

        algNoneBtn.addActionListener(e -> testAlgNone());
        bruteBtn.addActionListener(e -> bruteForceSecret());
        expiryBtn.addActionListener(e -> checkExpiry());
        repeaterBtn.addActionListener(e -> sendToRepeater());
        copyBtn.addActionListener(e -> copyToken());

        resultArea = new JTextArea(6, 40);
        resultArea.setEditable(false);
        resultArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane resultScroll = new JScrollPane(resultArea);
        resultScroll.setBorder(BorderFactory.createTitledBorder("Attack Output"));

        statusLabel = new JLabel("Ready.");
        statusLabel.setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6));

        south.add(buttons, BorderLayout.NORTH);
        south.add(resultScroll, BorderLayout.CENTER);
        south.add(statusLabel, BorderLayout.SOUTH);
        return south;
    }

    /** Adds a detected JWT entry. Safe to call from any thread. */
    public void addEntry(JwtEntry entry) {
        SwingUtilities.invokeLater(() -> {
            for (JwtEntry e : entries) {
                if (e.token().equals(entry.token()) && e.path().equals(entry.path())) {
                    return;
                }
            }
            entries.add(entry);
            String shortToken = entry.token().length() > 40
                    ? entry.token().substring(0, 40) + "..."
                    : entry.token();
            tableModel.addRow(new Object[]{
                    entry.host(), entry.method(), entry.path(), entry.source(), shortToken});

            if (entries.size() == 1) {
                table.setRowSelectionInterval(0, 0);
            }
        });
    }

    private void showSelected() {
        JwtEntry entry = getSelectedEntry();
        if (entry == null) {
            return;
        }
        try {
            JwtUtils.DecodedJwt decoded = JwtUtils.decodeJwt(entry.token());
            StringBuilder sb = new StringBuilder();
            sb.append("=== RAW TOKEN ===\n").append(entry.token()).append("\n\n");
            sb.append("=== HEADER ===\n").append(decoded.headerPretty).append("\n\n");
            sb.append("=== PAYLOAD ===\n").append(decoded.payloadPretty).append("\n\n");
            sb.append("=== SIGNATURE (Base64Url) ===\n")
              .append(decoded.signature.isEmpty() ? "(empty)" : decoded.signature);
            decodedArea.setText(sb.toString());
            decodedArea.setCaretPosition(0);
        } catch (Exception ex) {
            decodedArea.setText("Failed to decode token: " + ex.getMessage());
        }
    }

    /** Returns the currently selected entry, or null. */
    public JwtEntry getSelectedEntry() {
        int row = table.getSelectedRow();
        if (row < 0 || row >= entries.size()) {
            return null;
        }
        return entries.get(row);
    }

    /** Last generated alg:none token (for Phase 4). May be null. */
    public String getLastGeneratedToken() {
        return lastGeneratedToken;
    }

    // ---- Attack 1: alg:none ------------------------------------------------

    private void testAlgNone() {
        JwtEntry entry = requireSelection();
        if (entry == null) {
            return;
        }
        try {
            JwtUtils.DecodedJwt decoded = JwtUtils.decodeJwt(entry.token());
            String token = JwtUtils.generateAlgNoneToken(decoded.payloadRaw);
            lastGeneratedToken = token;
            resultArea.setText("Generated alg:none token:\n" + token
                    + "\n\n(Header forced to {\"alg\":\"none\",\"typ\":\"JWT\"}, signature removed.)");
            setStatus("[INFO] alg:none token generated. Send it to Repeater to test the server.",
                    SECURE_GREEN);
        } catch (Exception ex) {
            setStatus("Error generating alg:none token: " + ex.getMessage(), VULN_RED);
        }
    }

    // ---- Attack 2: weak secret brute-force ---------------------------------

    private void bruteForceSecret() {
        JwtEntry entry = requireSelection();
        if (entry == null) {
            return;
        }
        final String token = entry.token();

        List<String> secrets = loadSecrets();
        if (secrets.isEmpty()) {
            setStatus("Could not load secrets.txt wordlist.", VULN_RED);
            return;
        }

        resultArea.setText("Brute-forcing HMAC-SHA256 secret against " + secrets.size() + " candidates...\n");
        setStatus("Testing 0/" + secrets.size() + "...", Color.DARK_GRAY);

        SwingWorker<String, Integer> worker = new SwingWorker<>() {
            @Override
            protected String doInBackground() {
                int total = secrets.size();
                for (int i = 0; i < total; i++) {
                    String secret = secrets.get(i);
                    publish(i + 1);
                    if (JwtUtils.verifyHs256(token, secret)) {
                        return secret;
                    }
                }
                return null;
            }

            @Override
            protected void process(List<Integer> chunks) {
                int latest = chunks.get(chunks.size() - 1);
                setStatus("Testing " + latest + "/" + secrets.size() + "...", Color.DARK_GRAY);
            }

            @Override
            protected void done() {
                try {
                    String found = get();
                    if (found != null) {
                        resultArea.append("[VULNERABLE] Found secret: " + found + "\n");
                        setStatus("[VULNERABLE] Weak signing key found: " + found, VULN_RED);
                    } else {
                        resultArea.append("No weak secret matched. Token not trivially crackable.\n");
                        setStatus("[SECURE] No weak secret matched (" + secrets.size() + " tried).",
                                SECURE_GREEN);
                    }
                } catch (Exception ex) {
                    setStatus("Brute-force error: " + ex.getMessage(), VULN_RED);
                }
            }
        };
        worker.execute();
    }

    private List<String> loadSecrets() {
        List<String> secrets = new ArrayList<>();
        try (InputStream in = getClass().getResourceAsStream("/secrets.txt")) {
            if (in == null) {
                return secrets;
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            String line;
            while ((line = reader.readLine()) != null) {
                String s = line.trim();
                if (!s.isEmpty()) {
                    secrets.add(s);
                }
            }
        } catch (Exception e) {
            api.logging().logToError("Failed to read secrets.txt: " + e.getMessage());
        }
        return secrets;
    }

    // ---- Attack 3: expiry check --------------------------------------------

    private void checkExpiry() {
        JwtEntry entry = requireSelection();
        if (entry == null) {
            return;
        }
        try {
            JwtUtils.DecodedJwt decoded = JwtUtils.decodeJwt(entry.token());
            Long exp = JwtUtils.readExp(decoded.payloadRaw);
            if (exp == null) {
                resultArea.setText("[INFO] Token never expires (no \"exp\" claim).");
                setStatus("[INFO] Token never expires - no exp claim.", VULN_RED);
                return;
            }
            Instant expInstant = Instant.ofEpochSecond(exp);
            String human = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z")
                    .withZone(ZoneId.systemDefault())
                    .format(expInstant);
            boolean expired = Instant.now().isAfter(expInstant);
            if (expired) {
                resultArea.setText("exp = " + exp + "\nExpires: " + human + "\n[EXPIRED] Token is no longer valid.");
                setStatus("[EXPIRED] Token expired at " + human, VULN_RED);
            } else {
                resultArea.setText("exp = " + exp + "\nExpires: " + human + "\n[VALID] Token is still active.");
                setStatus("[VALID] Token active until " + human, SECURE_GREEN);
            }
        } catch (Exception ex) {
            setStatus("Error checking expiry: " + ex.getMessage(), VULN_RED);
        }
    }

    // ---- Phase 4: Repeater + clipboard -------------------------------------

    private void sendToRepeater() {
        JwtEntry entry = requireSelection();
        if (entry == null) {
            return;
        }
        if (lastGeneratedToken == null) {
            setStatus("Generate an alg:none token first (Test alg:none).", VULN_RED);
            return;
        }
        try {
            HttpRequest modified = buildRequestWithToken(entry, lastGeneratedToken);
            api.repeater().sendToRepeater(modified, "JWTBreaker alg:none");
            setStatus("[INFO] Sent modified request to Repeater (tab: JWTBreaker alg:none).",
                    SECURE_GREEN);
        } catch (Exception ex) {
            setStatus("Failed to send to Repeater: " + ex.getMessage(), VULN_RED);
        }
    }

    /** Rebuilds the request with the original JWT replaced by the new one. */
    private HttpRequest buildRequestWithToken(JwtEntry entry, String newToken) {
        HttpRequest request = entry.request();
        String headerName = entry.source().startsWith("Authorization") ? "Authorization" : "Cookie";
        String currentValue = headerValue(request, headerName);
        if (currentValue == null) {
            // Header gone; just return original request unchanged.
            return request;
        }
        String newValue = currentValue.replace(entry.token(), newToken);
        return request.withUpdatedHeader(headerName, newValue);
    }

    private String headerValue(HttpRequest request, String name) {
        for (HttpHeader h : request.headers()) {
            if (h.name().equalsIgnoreCase(name)) {
                return h.value();
            }
        }
        return null;
    }

    private void copyToken() {
        if (lastGeneratedToken == null) {
            setStatus("No generated token to copy. Run Test alg:none first.", VULN_RED);
            return;
        }
        Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(lastGeneratedToken), null);
        setStatus("[INFO] Generated token copied to clipboard.", SECURE_GREEN);
    }

    // ---- helpers -----------------------------------------------------------

    private JwtEntry requireSelection() {
        JwtEntry entry = getSelectedEntry();
        if (entry == null) {
            setStatus("Select a detected JWT from the table first.", VULN_RED);
        }
        return entry;
    }

    private void setStatus(String text, Color color) {
        SwingUtilities.invokeLater(() -> {
            statusLabel.setText(text);
            statusLabel.setForeground(color);
        });
    }
}
