package dev.pun;

import com.google.gson.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.net.URLDecoder;
import java.util.*;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;

/** Bounded local cookie decoder. Public metadata NEVER contains raw or decoded values. */
final class CookieInspector {
    private static final int MAX_COOKIES = 48, MAX_VALUE = 8192, MAX_LAYERS = 5;
    private static final Pattern VALID_NAME = Pattern.compile("[A-Za-z_][A-Za-z0-9_-]{0,60}");
    private static final Pattern B64 = Pattern.compile("[A-Za-z0-9+/=_-]{8,8192}");
    private static final Pattern HEX = Pattern.compile("[a-fA-F0-9]{4,8192}");
    private static final Pattern ALGO = Pattern.compile("[A-Za-z0-9_-]{1,32}");
    private final byte[] secret = new byte[32];

    CookieInspector() { new java.security.SecureRandom().nextBytes(secret); }

    static final class Entry {
        String name;
        String raw; // UI local ONLY: never return from bridge.
        String decoded;
        List<String> chain = new ArrayList<>();
        List<String> keys = new ArrayList<>();
        String structure = "opaque";
        String hashFamily;
        Map<String, Object> jwt;
        String fingerprint;
        Map<String, Object> metadata() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("name", name); m.put("structure", structure);
            m.put("encoding_chain", chain); m.put("json_keys", keys);
            if (hashFamily != null) m.put("hash_family", hashFamily);
            if (jwt != null) m.put("jwt", jwt);
            m.put("fingerprint", fingerprint);
            return m;
        }
    }

    List<Entry> inspectCookieHeader(String header) {
        if (header == null || header.isEmpty()) return List.of();
        List<Entry> results = new ArrayList<>();
        for (String part : header.split(";", MAX_COOKIES + 1)) {
            if (results.size() >= MAX_COOKIES) break;
            int at = part.indexOf('=');
            if (at <= 0) continue;
            String name = part.substring(0, at).trim();
            String value = part.substring(at + 1).trim();
            if (!VALID_NAME.matcher(name).matches() || value.length() > MAX_VALUE) continue;
            results.add(inspect(name, value));
        }
        return results;
    }

    List<Entry> inspectSetCookies(List<String> headers) {
        List<Entry> out = new ArrayList<>();
        if (headers == null) return out;
        for (String header : headers) {
            if (out.size() >= MAX_COOKIES || header == null) break;
            String pair = header.split(";", 2)[0];
            int at = pair.indexOf('=');
            if (at <= 0) continue;
            String name = pair.substring(0, at).trim(), value = pair.substring(at + 1).trim();
            if (VALID_NAME.matcher(name).matches() && value.length() <= MAX_VALUE) out.add(inspect(name, value));
        }
        return out;
    }

    List<Map<String, Object>> metadata(List<Entry> entries) {
        List<Map<String, Object>> result = new ArrayList<>();
        for (Entry entry : entries) result.add(entry.metadata());
        return result;
    }

    String formatLocal(List<Entry> req, List<Entry> resp) {
        StringBuilder out = new StringBuilder("Pun Cookie Inspector — LOCAL ONLY (contains sensitive values)\n"
            + "Never paste this output into a cloud AI client or report without redaction.\n"
            + "Encoding is reversible; MD5/SHA hashes cannot be decrypted.\n\n");
        appendLocal(out, "REQUEST COOKIE", req);
        appendLocal(out, "RESPONSE SET-COOKIE", resp);
        return out.toString();
    }

    private static void appendLocal(StringBuilder out, String title, List<Entry> entries) {
        out.append("== ").append(title).append(" ==\n");
        if (entries.isEmpty()) { out.append("(none)\n\n"); return; }
        for (Entry e : entries) {
            out.append("Cookie: ").append(e.name).append("\n")
               .append("  Encoding: ").append(e.chain).append("\n")
               .append("  Structure: ").append(e.structure).append("\n")
               .append("  Field names: ").append(e.keys).append("\n");
            if (e.hashFamily != null) out.append("  Hash-like: ").append(e.hashFamily)
                .append(" (NOT reversible; verify only against candidate inputs)\n");
            if (e.jwt != null) out.append("  JWT metadata: ").append(e.jwt).append("\n");
            out.append("  Original (local): ").append(e.raw).append("\n")
               .append("  Decoded (local): ").append(e.decoded).append("\n\n");
        }
    }

    private Entry inspect(String name, String value) {
        Entry entry = new Entry();
        entry.name = name;
        entry.raw = value;
        entry.decoded = value;
        entry.fingerprint = fingerprint(name, value);
        String current = trimQuotes(value);
        String firstHash = detectHash(current);
        if (firstHash != null) {
            entry.hashFamily = firstHash; entry.structure = "hash";
            return entry;
        }
        if (current.split("\\.", -1).length == 3) {
            String[] parts = current.split("\\.", -1);
            String h = toText(decodeB64(parts[0]));
            String p = toText(decodeB64(parts[1]));
            if (h != null && p != null && isJson(h) && isJson(p)) {
                entry.structure = "jwt";
                entry.chain.add("jwt-base64url");
                entry.keys = jsonKeys(p);
                Map<String, Object> jwt = new LinkedHashMap<>();
                jwt.put("header_keys", jsonKeys(h));
                jwt.put("claim_keys", jsonKeys(p));
                jwt.put("signature_present", !parts[2].isEmpty());
                try {
                    JsonElement header = JsonParser.parseString(h);
                    if (header.isJsonObject() && header.getAsJsonObject().has("alg")) {
                        String alg = header.getAsJsonObject().get("alg").getAsString();
                        if (ALGO.matcher(alg).matches()) {
                            jwt.put("algorithm", alg);
                            if (alg.equalsIgnoreCase("none"))
                                jwt.put("review_hint", "alg=none observed; enforcement unknown");
                        }
                    }
                } catch (RuntimeException ignored) { }
                entry.jwt = jwt;
                entry.decoded = "JWT header: " + h + "\nJWT payload: " + p
                    + "\nJWT signature: " + (parts[2].isEmpty() ? "absent" : "present (not verified)");
                return entry;
            }
        }
        for (int i = 0; i < MAX_LAYERS; i++) {
            String previous = current;
            if (current.contains("%")) {
                try {
                    String decoded = URLDecoder.decode(current.replace("+", "%2B"), StandardCharsets.UTF_8);
                    if (decoded.length() <= MAX_VALUE && !decoded.equals(current)) {
                        current = decoded; entry.chain.add("url-percent");
                    }
                } catch (IllegalArgumentException ignored) { }
            }
            if (current.equals(previous)) {
                byte[] data = decodeB64(current);
                if (data != null) {
                    String text = toText(data);
                    if (text == null && data.length >= 2 && (data[0] & 255) == 31 && (data[1] & 255) == 139) {
                        text = gunzip(data);
                        if (text != null) entry.chain.add("gzip");
                    }
                    if (text != null && !text.equals(current)) {
                        current = text;
                        entry.chain.add("base64");
                    }
                } else if (detectHash(current) == null && HEX.matcher(current).matches() && current.length() % 2 == 0) {
                    String text = toText(decodeHex(current));
                    if (text != null && !text.equals(current)) {
                        current = text; entry.chain.add("hex");
                    }
                }
            }
            if (current.equals(previous) || detectHash(current) != null) break;
        }
        entry.decoded = current;
        entry.hashFamily = detectHash(current);
        entry.keys = jsonKeys(current);
        entry.structure = entry.hashFamily != null ? "hash" : isJson(current) ? "json" :
            entry.chain.isEmpty() ? "opaque" : "text";
        return entry;
    }

    private String fingerprint(String name, String value) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            byte[] bytes = mac.doFinal((name + "\u0000" + value).getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(bytes, 0, 12);
        } catch (Exception e) { throw new IllegalStateException(e); }
    }

    private static String trimQuotes(String value) {
        return value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")
            ? value.substring(1, value.length() - 1) : value;
    }
    private static String detectHash(String v) {
        if (!HEX.matcher(v).matches()) return null;
        return switch (v.length()) {
            case 32 -> "MD5-like";
            case 40 -> "SHA-1-like";
            case 64 -> "SHA-256-like";
            case 128 -> "SHA-512-like";
            default -> null;
        };
    }
    private static byte[] decodeB64(String value) {
        if (!B64.matcher(value).matches()) return null;
        try {
            String raw = value.replace('-', '+').replace('_', '/').replaceAll("=+$", "");
            if (raw.length() % 4 == 1) return null;
            byte[] b = Base64.getDecoder().decode(raw + "=".repeat((4 - raw.length() % 4) % 4));
            String roundTrip = Base64.getEncoder().withoutPadding().encodeToString(b);
            return roundTrip.equals(raw) && b.length <= MAX_VALUE ? b : null;
        } catch (IllegalArgumentException ignored) { return null; }
    }
    private static byte[] decodeHex(String v) {
        try { return HexFormat.of().parseHex(v); }
        catch (IllegalArgumentException e) { return null; }
    }
    private static String toText(byte[] data) {
        if (data == null || data.length > MAX_VALUE) return null;
        try {
            String text = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(data)).toString();
            for (int i = 0; i < text.length(); i++) {
                char c = text.charAt(i);
                if (Character.isISOControl(c) && c != '\r' && c != '\n' && c != '\t') return null;
            }
            return text;
        } catch (CharacterCodingException e) { return null; }
    }
    private static String gunzip(byte[] input) {
        try (GZIPInputStream stream = new GZIPInputStream(new ByteArrayInputStream(input))) {
            byte[] bytes = stream.readNBytes(MAX_VALUE + 1);
            return toText(bytes);
        } catch (Exception ignored) { return null; }
    }
    private static boolean isJson(String text) {
        try {
            JsonElement e = JsonParser.parseString(text);
            return e.isJsonObject() || e.isJsonArray();
        } catch (RuntimeException e) { return false; }
    }
    private static List<String> jsonKeys(String text) {
        TreeSet<String> names = new TreeSet<>();
        try { collectKeys(JsonParser.parseString(text), names, 0); }
        catch (RuntimeException ignored) { }
        return new ArrayList<>(names);
    }
    private static void collectKeys(JsonElement node, Set<String> names, int depth) {
        if (depth > 3 || names.size() >= 30) return;
        if (node.isJsonObject()) {
            for (var e : node.getAsJsonObject().entrySet()) {
                if (VALID_NAME.matcher(e.getKey()).matches()) names.add(e.getKey());
                collectKeys(e.getValue(), names, depth + 1);
                if (names.size() >= 30) break;
            }
        } else if (node.isJsonArray()) {
            int n = 0;
            for (JsonElement value : node.getAsJsonArray()) {
                collectKeys(value, names, depth + 1);
                if (++n >= 3) break;
            }
        }
    }
}
