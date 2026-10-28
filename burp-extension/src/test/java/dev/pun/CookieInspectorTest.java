package dev.pun;

import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class CookieInspectorTest {
    @Test void decodesBase64AndHexLocallyButNeverExportsRawValues() {
        var inspector = new CookieInspector();
        var entries = inspector.inspectCookieHeader("session=YWRtaW4=; hex=68656c6c6f");
        assertEquals("admin", entries.get(0).decoded);
        assertEquals("hello", entries.get(1).decoded);
        String safe = inspector.metadata(entries).toString();
        assertFalse(safe.contains("YWRtaW4="));
        assertFalse(safe.contains("admin"));
        assertFalse(safe.contains("68656c6c6f"));
    }

    @Test void recognizesHashShapesWithoutClaimingToReverseThem() {
        var entries = new CookieInspector().inspectCookieHeader("sid=098f6bcd4621d373cade4e832627b4f6");
        assertEquals("MD5-like", entries.get(0).hashFamily);
        assertEquals(entries.get(0).raw, entries.get(0).decoded);
    }

    @Test void decodesJwtClaimsOnlyInsideBurpUi() {
        var codec = new CookieInspector();
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8));
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"sub\":\"demo.user@example.test\",\"role\":\"user\"}".getBytes(StandardCharsets.UTF_8));
        var entries = codec.inspectCookieHeader("token=" + header + "." + payload + ".");
        assertEquals("jwt", entries.get(0).structure);
        assertTrue(entries.get(0).keys.contains("sub"));
        assertTrue(entries.get(0).decoded.contains("demo.user@example.test"));
        assertFalse(codec.metadata(entries).toString().contains("demo.user@example.test"));
    }

    @Test void stableFingerprintsForSameCookieButDifferentAcrossValues() {
        var codec = new CookieInspector();
        String a = codec.inspectCookieHeader("session=YWJjZA==").get(0).fingerprint;
        String b = codec.inspectCookieHeader("session=YWJjZA==").get(0).fingerprint;
        String c = codec.inspectCookieHeader("session=YWJjZQ==").get(0).fingerprint;
        assertEquals(a,b);
        assertNotEquals(a,c);
    }
}
