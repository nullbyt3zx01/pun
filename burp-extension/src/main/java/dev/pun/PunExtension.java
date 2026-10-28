package dev.pun;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.google.gson.*;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

/**
 * Pun 0.2: Burp is the ONLY outbound HTTP execution engine.
 * The local MCP bridge serves sanitized metadata and queues user-approved replays.
 */
public final class PunExtension implements BurpExtension, HttpHandler {
    private static final int MAX_OBS = 400;
    private static final int MAX_JOBS = 80;
    private static final Set<String> SAFE_METHODS = Set.of("GET", "HEAD", "OPTIONS");
    private static final Pattern CREDENTIAL_HEADER = Pattern.compile(
        "(?i)(authorization|cookie|proxy-authorization|x-.*(api[-_]?key|token|auth|session|csrf)|x-xsrf-token)");
    private static final Pattern AUTH_PARAMETER = Pattern.compile(
        "(?i)(token|access_token|refresh_token|api_key|apikey|key|auth|jwt|session|password|signature|sig)");
    private static final Pattern JSON_FIELD = Pattern.compile("[A-Za-z_][A-Za-z0-9_-]{0,60}");

    private MontoyaApi api;
    private HttpServer bridge;
    private final Gson gson = new Gson();
    private final CookieInspector cookieInspector = new CookieInspector();
    private final LinkedHashMap<String, Observation> observations = new LinkedHashMap<>();
    private final LinkedHashMap<String, Job> jobs = new LinkedHashMap<>();
    private final LinkedHashMap<String, Role> roles = new LinkedHashMap<>();
    private final Set<String> allowedHosts = new HashSet<>();
    private final AtomicInteger serial = new AtomicInteger();
    private final String token = randomToken();
    private volatile boolean allowMutations = false;
    private DefaultTableModel trafficModel;
    private DefaultTableModel jobModel;
    private JLabel statusLabel;

    private static final class Role {
        final String name;
        final String cookie;
        final String authorization;
        Role(String n, String c, String a) { name = n; cookie = c; authorization = a; }
    }

    private static final class Observation {
        String id;
        long timestamp;
        HttpRequest rawRequest; // In-memory only. NEVER JSON serialized.
        String host, method, path, role, contentType;
        int status, requestLength, responseLength;
        String responseSha256;
        List<String> inputKeys, outputKeys;
        List<CookieInspector.Entry> requestCookies, responseCookies;
        List<Map<String, Object>> cookieInsights, setCookieInsights;

        Map<String, Object> json() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", id); m.put("timestamp", timestamp); m.put("host", host);
            m.put("method", method); m.put("path", path); m.put("role", role);
            m.put("status", status); m.put("content_type", contentType);
            m.put("request_length", requestLength); m.put("response_length", responseLength);
            m.put("response_sha256", responseSha256); m.put("input_keys", inputKeys);
            m.put("output_keys", outputKeys);
            m.put("cookie_insights", cookieInsights);
            m.put("set_cookie_insights", setCookieInsights);
            return m;
        }
    }

    private static final class Job {
        String id, requestId, role, reason, status, error;
        long queuedAt;
        Map<String, Object> result;
        Map<String, Object> json() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", id); m.put("request_id", requestId); m.put("role", role);
            m.put("reason", reason); m.put("status", status);
            m.put("queued_at", queuedAt); m.put("result", result);
            if (error != null) m.put("error", error);
            return m;
        }
    }

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Pun — AuthGraph + LogicHunter MCP");
        api.userInterface().registerSuiteTab("Pun", buildUi());
        api.http().registerHttpHandler(this);
        api.extension().registerUnloadingHandler(() -> {
            if (bridge != null) bridge.stop(0);
            synchronized (this) { observations.clear(); jobs.clear(); roles.clear(); }
        });
        try {
            bridge = HttpServer.create(new InetSocketAddress("127.0.0.1", 8765), 12);
            bridge.createContext("/", this::serve);
            bridge.setExecutor(Executors.newFixedThreadPool(3, r -> {
                Thread t = new Thread(r, "Pun-bridge"); t.setDaemon(true); return t;
            }));
            bridge.start();
            uiStatus("Bridge on 127.0.0.1:8765. Configure hosts + Burp Target scope.");
        } catch (IOException e) {
            api.logging().logToError("Pun bridge failed to start: " + e);
            uiStatus("ERROR: Bridge port 8765 unavailable.");
        }
    }

    private JComponent buildUi() {
        JPanel main = new JPanel(new BorderLayout(8, 8));
        main.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        JPanel config = new JPanel();
        config.setLayout(new BoxLayout(config, BoxLayout.Y_AXIS));
        JPanel scope = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JTextField hostField = new JTextField(42);
        JButton saveHosts = new JButton("Save allowed hosts");
        scope.add(new JLabel("Exact test hosts (comma separated):"));
        scope.add(hostField); scope.add(saveHosts);
        saveHosts.addActionListener(e -> {
            Set<String> next = new HashSet<>();
            for (String part : hostField.getText().split(",")) {
                String h = part.trim().toLowerCase(Locale.ROOT);
                if (h.isEmpty()) continue;
                if (!h.matches("[a-z0-9][a-z0-9.-]*[a-z0-9]|localhost")) {
                    JOptionPane.showMessageDialog(main, "Invalid host: " + h);
                    return;
                }
                next.add(h);
            }
            synchronized (this) { allowedHosts.clear(); allowedHosts.addAll(next); }
            uiStatus(next.isEmpty() ? "No allowed hosts: capture + replay disabled" : "Allowed hosts: " + next);
        });
        config.add(scope);

        JPanel roleLine = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JTextField nameField = new JTextField(10);
        JPasswordField cookieField = new JPasswordField(24);
        JPasswordField authField = new JPasswordField(24);
        JButton saveRole = new JButton("Save role (memory only)");
        roleLine.add(new JLabel("Role:")); roleLine.add(nameField);
        roleLine.add(new JLabel("Cookie value:")); roleLine.add(cookieField);
        roleLine.add(new JLabel("Authorization value:")); roleLine.add(authField);
        roleLine.add(saveRole);
        saveRole.addActionListener(e -> {
            String name = nameField.getText().trim();
            if (!name.matches("[A-Za-z][A-Za-z0-9_-]{0,31}")) {
                JOptionPane.showMessageDialog(main, "Role name must be 1–32 letters/numbers/_/-"); return;
            }
            String cookie = new String(cookieField.getPassword());
            String auth = new String(authField.getPassword());
            if (cookie.contains("\r") || cookie.contains("\n") || auth.contains("\r") || auth.contains("\n")) {
                JOptionPane.showMessageDialog(main, "Newlines in credentials are forbidden"); return;
            }
            synchronized (this) { roles.put(name, new Role(name, cookie, auth)); }
            cookieField.setText(""); authField.setText("");
            uiStatus("Saved local test role " + name + ". Blank both values = unauthenticated.");
        });
        config.add(roleLine);

        JPanel bridgeLine = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JTextField tokenField = new JTextField(token, 36);
        tokenField.setEditable(false);
        JButton copy = new JButton("Copy MCP token");
        copy.addActionListener(e -> Toolkit.getDefaultToolkit().getSystemClipboard()
            .setContents(new StringSelection(token), null));
        JCheckBox mutationBox = new JCheckBox("Allow mutating replays (POST/PUT/PATCH/DELETE) after manual approval");
        mutationBox.addActionListener(e -> allowMutations = mutationBox.isSelected());
        bridgeLine.add(new JLabel("Bridge token:")); bridgeLine.add(tokenField); bridgeLine.add(copy);
        bridgeLine.add(mutationBox);
        config.add(bridgeLine);

        trafficModel = new DefaultTableModel(new String[] {"ID", "Role", "Method", "Path", "HTTP"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        jobModel = new DefaultTableModel(new String[] {"Job ID", "Request ID", "Role", "Status", "Reason"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        JTable trafficTable = new JTable(trafficModel);
        JTable jobTable = new JTable(jobModel);
        JPanel jobsPanel = new JPanel(new BorderLayout());
        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton approve = new JButton("Approve selected replay");
        JButton deny = new JButton("Deny selected replay");
        JButton refresh = new JButton("Refresh queues");
        JButton inspect = new JButton("Inspect selected baseline locally");
        JButton cookies = new JButton("Decode cookies locally");
        controls.add(approve); controls.add(deny); controls.add(refresh); controls.add(inspect); controls.add(cookies);
        jobsPanel.add(controls, BorderLayout.NORTH);
        jobsPanel.add(new JScrollPane(jobTable), BorderLayout.CENTER);
        inspect.addActionListener(e -> {
            int selected = trafficTable.getSelectedRow();
            if (selected < 0) { uiStatus("Select a traffic row to inspect"); return; }
            String id = String.valueOf(trafficModel.getValueAt(trafficTable.convertRowIndexToModel(selected), 0));
            Observation obs;
            synchronized (this) { obs = observations.get(id); }
            if (obs == null) { uiStatus("Baseline was evicted"); return; }
            JTextArea source = new JTextArea(obs.rawRequest.toString());
            source.setEditable(false);
            source.setLineWrap(false);
            // Raw session data remains within Burp UI and is never sent over MCP.
            JScrollPane pane = new JScrollPane(source);
            pane.setPreferredSize(new Dimension(790, 420));
            JOptionPane.showMessageDialog(main, pane, "Raw baseline (local only) " + obs.id,
                JOptionPane.INFORMATION_MESSAGE);
        });
        cookies.addActionListener(e -> {
            int selected = trafficTable.getSelectedRow();
            if (selected < 0) { uiStatus("Select a traffic row to decode cookies"); return; }
            String id = String.valueOf(trafficModel.getValueAt(trafficTable.convertRowIndexToModel(selected), 0));
            Observation obs;
            synchronized (this) { obs = observations.get(id); }
            if (obs == null) { uiStatus("Selected observation no longer available"); return; }
            JTextArea decoded = new JTextArea(cookieInspector.formatLocal(obs.requestCookies, obs.responseCookies));
            decoded.setEditable(false);
            JScrollPane pane = new JScrollPane(decoded);
            pane.setPreferredSize(new Dimension(790, 460));
            JOptionPane.showMessageDialog(main, pane, "Pun Cookie Inspector (local only) " + id,
                JOptionPane.WARNING_MESSAGE);
        });
        approve.addActionListener(e -> {
            int selected = jobTable.getSelectedRow(); if (selected < 0) return;
            String id = String.valueOf(jobModel.getValueAt(jobTable.convertRowIndexToModel(selected), 0));
            Job job; Observation obs;
            synchronized (this) {
                job = jobs.get(id); obs = job == null ? null : observations.get(job.requestId);
            }
            if (job == null || !"PENDING".equals(job.status) || obs == null) {
                uiStatus("Select a pending replay with an existing baseline"); return;
            }
            String msg = "Pun will send ONE " + obs.method + " request to " + obs.host + "\n"
                + "Path: " + obs.path + "\nRole: " + job.role + "\nReason: " + job.reason
                + "\n\nThis may change server state. Proceed ONLY on authorized test data?";
            if (JOptionPane.showConfirmDialog(main, msg, "Approve exact replay", JOptionPane.YES_NO_OPTION,
                    JOptionPane.WARNING_MESSAGE) == JOptionPane.YES_OPTION) {
                synchronized (this) { if ("PENDING".equals(job.status)) job.status = "RUNNING"; else return; }
                refreshJobs();
                new Thread(() -> execute(job.id), "Pun-replay-" + job.id).start();
            }
        });
        deny.addActionListener(e -> {
            int selected = jobTable.getSelectedRow(); if (selected < 0) return;
            String id = String.valueOf(jobModel.getValueAt(jobTable.convertRowIndexToModel(selected), 0));
            synchronized (this) { Job j = jobs.get(id); if (j != null && "PENDING".equals(j.status)) j.status = "DENIED"; }
            refreshJobs();
        });
        refresh.addActionListener(e -> refreshJobs());
        JSplitPane tables = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
            new JScrollPane(trafficTable), jobsPanel);
        tables.setResizeWeight(0.55);
        statusLabel = new JLabel("Configure exact hosts and Burp Target scope to start capture.");
        main.add(config, BorderLayout.NORTH);
        main.add(tables, BorderLayout.CENTER);
        main.add(statusLabel, BorderLayout.SOUTH);
        return main;
    }

    private void uiStatus(String message) {
        SwingUtilities.invokeLater(() -> { if (statusLabel != null) statusLabel.setText(message); });
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        return RequestToBeSentAction.continueWith(request);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        try {
            HttpRequest request = response.initiatingRequest();
            if (!allowed(request)) return ResponseReceivedAction.continueWith(response);
            Observation obs = new Observation();
            obs.id = "req-" + serial.incrementAndGet();
            obs.timestamp = Instant.now().toEpochMilli();
            obs.rawRequest = request;
            obs.host = request.httpService().host().toLowerCase(Locale.ROOT);
            obs.method = request.method();
            obs.path = request.pathWithoutQuery(); // Query values never exported.
            obs.status = response.statusCode();
            obs.contentType = safeType(response.headerValue("Content-Type"));
            obs.requestLength = request.body().length();
            obs.responseLength = response.body().length();
            obs.responseSha256 = sha256(response.body().getBytes());
            obs.inputKeys = request.body().length() <= 262144
                ? keys(request.bodyToString(), request.headerValue("Content-Type"), request.query())
                : keys("", "", request.query());
            obs.requestCookies = cookieInspector.inspectCookieHeader(request.headerValue("Cookie"));
            List<String> newCookies = new ArrayList<>();
            for (HttpHeader h : response.headers()) {
                if ("Set-Cookie".equalsIgnoreCase(h.name())) newCookies.add(h.value());
            }
            obs.responseCookies = cookieInspector.inspectSetCookies(newCookies);
            obs.cookieInsights = cookieInspector.metadata(obs.requestCookies);
            obs.setCookieInsights = cookieInspector.metadata(obs.responseCookies);
            obs.outputKeys = response.body().length() <= 262144
                ? keys(response.bodyToString(), response.headerValue("Content-Type"), "")
                : List.of();
            synchronized (this) {
                obs.role = matchRole(request);
                observations.put(obs.id, obs);
                while (observations.size() > MAX_OBS) observations.remove(observations.keySet().iterator().next());
            }
            SwingUtilities.invokeLater(() -> {
                trafficModel.addRow(new Object[] {obs.id, obs.role, obs.method, obs.path, obs.status});
                while (trafficModel.getRowCount() > MAX_OBS) trafficModel.removeRow(0);
            });
        } catch (Exception e) {
            api.logging().logToError("Pun observation error: " + e.getMessage());
        }
        return ResponseReceivedAction.continueWith(response);
    }

    private synchronized boolean allowed(HttpRequest request) {
        try {
            return request.isInScope() && allowedHosts.contains(request.httpService().host().toLowerCase(Locale.ROOT));
        } catch (Exception e) { return false; }
    }

    private String matchRole(HttpRequest req) {
        String c = Objects.toString(req.headerValue("Cookie"), "");
        String a = Objects.toString(req.headerValue("Authorization"), "");
        for (Role role : roles.values()) {
            if (role.cookie.equals(c) && role.authorization.equals(a)) return role.name;
        }
        return "unknown";
    }

    /** Only JSON KEY NAMES, form/query PARAMETER NAMES are available to MCP. */
    private static List<String> keys(String body, String contentType, String query) {
        Set<String> result = new TreeSet<>();
        if (query != null && !query.isBlank()) {
            for (String pair : query.split("&", 80)) {
                String key = pair.split("=", 2)[0].replaceAll("[^A-Za-z0-9_-]", "");
                if (JSON_FIELD.matcher(key).matches()) result.add(key);
            }
        }
        if (body != null && body.length() <= 262144 && contentType != null) {
            String type = contentType.toLowerCase(Locale.ROOT);
            if (type.contains("json")) {
                try { collectJsonKeys(JsonParser.parseString(body), result, 0); }
                catch (JsonParseException ignored) { }
            } else if (type.contains("x-www-form-urlencoded")) {
                for (String pair : body.split("&", 100)) {
                    String key = pair.split("=", 2)[0].replaceAll("[^A-Za-z0-9_-]", "");
                    if (JSON_FIELD.matcher(key).matches()) result.add(key);
                }
            }
        }
        return new ArrayList<>(result).subList(0, Math.min(result.size(), 80));
    }

    private static void collectJsonKeys(JsonElement e, Set<String> keys, int depth) {
        if (depth > 4 || keys.size() >= 80) return;
        if (e.isJsonObject()) {
            for (var entry : e.getAsJsonObject().entrySet()) {
                if (JSON_FIELD.matcher(entry.getKey()).matches()) keys.add(entry.getKey());
                collectJsonKeys(entry.getValue(), keys, depth + 1);
            }
        } else if (e.isJsonArray()) {
            int n = 0;
            for (JsonElement item : e.getAsJsonArray()) {
                if (++n > 4) break;
                collectJsonKeys(item, keys, depth + 1);
            }
        }
    }

    private static String safeType(String type) {
        if (type == null) return "";
        String sanitized = type.split(";", 2)[0].replaceAll("[^a-zA-Z0-9/+._-]", "");
        return sanitized.substring(0, Math.min(100, sanitized.length()));
    }

    private static String sha256(byte[] raw) {
        try {
            byte[] dig = MessageDigest.getInstance("SHA-256").digest(raw);
            StringBuilder s = new StringBuilder();
            for (byte b : dig) s.append(String.format("%02x", b & 0xff));
            return s.toString();
        } catch (Exception e) { throw new IllegalStateException(e); }
    }

    private static String randomToken() {
        byte[] buf = new byte[32]; new SecureRandom().nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }

    private void serve(HttpExchange exchange) throws IOException {
        try {
            // Deliberately no CORS; token is also required, even for GET /health.
            String supplied = Objects.toString(exchange.getRequestHeaders().getFirst("Authorization"), "");
            byte[] candidate = supplied.getBytes(StandardCharsets.UTF_8);
            byte[] expected = ("Bearer " + token).getBytes(StandardCharsets.UTF_8);
            if (!MessageDigest.isEqual(candidate, expected)) { respond(exchange, 401, Map.of("error", "Unauthorized")); return; }
            String method = exchange.getRequestMethod();
            String path = exchange.getRequestURI().getPath();
            if ("GET".equals(method) && "/health".equals(path)) {
                int obsCount; int roleCount; int jobCount; List<String> hosts;
                synchronized (this) { obsCount = observations.size(); roleCount = roles.size();
                    jobCount = jobs.size(); hosts = new ArrayList<>(allowedHosts); }
                respond(exchange, 200, Map.of("name", "Pun", "version", "0.2.0", "observations", obsCount,
                    "roles_count", roleCount, "jobs_count", jobCount, "allowed_hosts", hosts,
                    "bridge", "local_authenticated", "replay", "manual_approval_only"));
                return;
            }
            if ("GET".equals(method) && "/traffic".equals(path)) {
                List<Map<String, Object>> rows = new ArrayList<>();
                synchronized (this) { for (Observation obs : observations.values()) rows.add(obs.json()); }
                respond(exchange, 200, Map.of("items", rows)); return;
            }
            if ("GET".equals(method) && "/roles".equals(path)) {
                List<String> names;
                synchronized (this) { names = new ArrayList<>(roles.keySet()); }
                respond(exchange, 200, Map.of("roles", names)); return;
            }
            if ("GET".equals(method) && "/jobs".equals(path)) {
                List<Map<String, Object>> items = new ArrayList<>();
                synchronized (this) { for (Job j : jobs.values()) items.add(j.json()); }
                respond(exchange, 200, Map.of("jobs", items)); return;
            }
            if ("POST".equals(method) && "/replays".equals(path)) {
                byte[] input;
                try (var stream = exchange.getRequestBody()) { input = stream.readNBytes(8193); }
                if (input.length > 8192) { respond(exchange, 413, Map.of("error", "Body too long")); return; }
                JsonObject payload;
                try { payload = JsonParser.parseString(new String(input, StandardCharsets.UTF_8)).getAsJsonObject(); }
                catch (RuntimeException ex) { respond(exchange, 400, Map.of("error", "Invalid JSON")); return; }
                String reqId = readField(payload, "request_id");
                String role = readField(payload, "role");
                String reason = readField(payload, "reason");
                if (reason.isBlank() || reason.length() > 350) {
                    respond(exchange, 400, Map.of("error", "Short justification required")); return;
                }
                Job job = null; String error = null;
                synchronized (this) {
                    Observation obs = observations.get(reqId);
                    if (obs == null) error = "Unknown request";
                    else if (!roles.containsKey(role)) error = "Unknown role";
                    else if (!allowed(obs.rawRequest)) error = "Target no longer in scope/allowlist";
                    else if (hasQueryCredentials(obs.rawRequest)) error = "Replay refused: original URL has credential-like query values";
                    else if (!allowMutations && !SAFE_METHODS.contains(obs.method)) error = "Mutating replays are disabled in Pun UI";
                    else if (jobs.values().stream().filter(j -> "PENDING".equals(j.status)).count() >= 20) error = "Too many pending replays";
                    else {
                        job = new Job(); job.id = "job-" + UUID.randomUUID(); job.requestId = reqId;
                        job.role = role; job.reason = reason; job.status = "PENDING";
                        job.queuedAt = Instant.now().toEpochMilli(); jobs.put(job.id, job);
                        while (jobs.size() > MAX_JOBS) jobs.remove(jobs.keySet().iterator().next());
                    }
                }
                if (error != null) { respond(exchange, 400, Map.of("error", error)); return; }
                refreshJobs();
                respond(exchange, 202, Map.of("id", job.id, "status", "PENDING",
                    "instruction", "Approve the exact request in the Pun Burp tab. MCP cannot approve it."));
                return;
            }
            respond(exchange, 404, Map.of("error", "Not found"));
        } catch (Exception e) {
            api.logging().logToError("Pun bridge error: " + e);
            respond(exchange, 500, Map.of("error", "Internal bridge error"));
        } finally { exchange.close(); }
    }

    private static boolean hasQueryCredentials(HttpRequest request) {
        String query = request.query();
        for (String pair : query.split("&")) {
            if (AUTH_PARAMETER.matcher(pair.split("=", 2)[0]).matches()) return true;
        }
        return false;
    }

    private static String readField(JsonObject obj, String field) {
        try { return obj.get(field).getAsString().trim(); }
        catch (Exception e) { return ""; }
    }

    private void respond(HttpExchange ex, int status, Object data) throws IOException {
        byte[] body = gson.toJson(data).getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.getResponseHeaders().set("Cache-Control", "no-store");
        ex.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        ex.sendResponseHeaders(status, body.length);
        try (var out = ex.getResponseBody()) { out.write(body); }
    }

    private void execute(String jobId) {
        Job job; Observation obs; Role role;
        synchronized (this) {
            job = jobs.get(jobId); obs = job == null ? null : observations.get(job.requestId);
            role = job == null ? null : roles.get(job.role);
        }
        if (job == null) return;
        try {
            if (obs == null || role == null || !allowed(obs.rawRequest))
                throw new IllegalStateException("Request/role missing or no longer in scope");
            if (!allowMutations && !SAFE_METHODS.contains(obs.method))
                throw new IllegalStateException("Mutating replays disabled");
            if (hasQueryCredentials(obs.rawRequest))
                throw new IllegalStateException("Original URL includes credential-like query parameters");
            // Replace BOTH auth mechanisms; never reuse a baseline account's credentials.
            HttpRequest replacement = obs.rawRequest;
            for (HttpHeader header : obs.rawRequest.headers()) {
                if (CREDENTIAL_HEADER.matcher(header.name()).matches()) {
                    replacement = replacement.withRemovedHeader(header.name());
                }
            }
            if (!role.cookie.isBlank()) replacement = replacement.withHeader("Cookie", role.cookie);
            if (!role.authorization.isBlank()) replacement = replacement.withHeader("Authorization", role.authorization);
            HttpRequestResponse answer = api.http().sendRequest(replacement);
            if (!answer.hasResponse()) throw new IOException("No HTTP response received");
            HttpResponse response = answer.response();
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("status", (int) response.statusCode());
            result.put("response_length", response.body().length());
            result.put("response_sha256", sha256(response.body().getBytes()));
            result.put("output_keys", response.body().length() <= 262144
                ? keys(response.bodyToString(), response.headerValue("Content-Type"), "") : List.of());
            synchronized (this) { job.status = "COMPLETED"; job.result = result; }
            uiStatus("Replay completed: " + job.id + " (does not establish a vulnerability)");
        } catch (Exception e) {
            synchronized (this) { job.status = "ERROR"; job.error = e.getClass().getSimpleName() + ": " + e.getMessage(); }
            uiStatus("Replay failed: " + job.id);
            api.logging().logToError("Pun replay error: " + e);
        } finally { refreshJobs(); }
    }

    private void refreshJobs() {
        SwingUtilities.invokeLater(() -> {
            jobModel.setRowCount(0);
            synchronized (this) {
                for (Job j : jobs.values()) jobModel.addRow(
                    new Object[] {j.id, j.requestId, j.role, j.status, j.reason});
            }
        });
    }
}
