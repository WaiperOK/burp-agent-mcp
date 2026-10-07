import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpHeader;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Passive checks and body export for the agent. Nothing is sent to the target: they only read responses
 * that have already passed through Burp.
 *
 * - Findings: ~/burp_agent_findings/findings.jsonl (JSON lines); the gateway reads them with read_passive_findings.
 * - Full JavaScript bodies (not truncated): ~/burp_agent_findings/bodies/<sha256>.txt and index.jsonl,
 *   the gateway searches them with search_bundles. HTML is deliberately not exported.
 *
 * Loaded by the person: Extensions -> Add -> Java -> AgentFindings.jar.
 * Scope: ~/burp_agent_findings/scope.txt, one host per line ("*.example.test" means all subdomains).
 * Without scope.txt the extension writes nothing.
 */
public class AgentFindings implements BurpExtension {
    private static final Path DIR = Path.of(System.getProperty("user.home"), "burp_agent_findings");
    private static final Path FINDINGS = DIR.resolve("findings.jsonl");
    private static final Path SCOPE = DIR.resolve("scope.txt");
    private static final Path BODIES = DIR.resolve("bodies");
    private static final Pattern JWT = Pattern.compile("eyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}");
    private static final int MAX_BODY_SCAN = 200_000;
    private static final int MAX_EXPORT = 5 * 1024 * 1024;
    private static final int MAX_SEEN = 10_000;
    // Findings and JS bodies contain target data: only the owner may read them.
    private static final Set<PosixFilePermission> OWNER_FILE = PosixFilePermissions.fromString("rw-------");
    private static final Set<PosixFilePermission> OWNER_DIR = PosixFilePermissions.fromString("rwx------");

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Agent Findings");
        api.http().registerHttpHandler(new Checks(api));
        api.logging().logToOutput("AgentFindings loaded, findings file: " + FINDINGS);
    }

    static final class Checks implements HttpHandler {
        private final MontoyaApi api;
        private final Object lock = new Object();
        private final Set<String> seen = new HashSet<>();
        private final Set<String> exported = new HashSet<>();
        private List<String> scope = List.of();
        private long scopeLoadedAt = 0;

        Checks(MontoyaApi api) {
            this.api = api;
        }

        @Override
        public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
            return RequestToBeSentAction.continueWith(request);
        }

        @Override
        public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
            try {
                inspect(response);
            } catch (RuntimeException ex) {
                api.logging().logToError("AgentFindings check failed: " + ex);
            }
            return ResponseReceivedAction.continueWith(response);
        }

        private void inspect(HttpResponseReceived response) {
            var request = response.initiatingRequest();
            String host = request.httpService().host().toLowerCase();
            if (!inScope(host)) {
                return;
            }
            String path = request.pathWithoutQuery();
            String url = request.url();
            boolean https = url.startsWith("https://");

            String contentType = response.headerValue("Content-Type");
            String ctLower = contentType == null ? "" : contentType.toLowerCase();
            // Export JavaScript only: HTML of medical pages may contain personal data in the rendered markup.
            if (ctLower.contains("javascript")) {
                exportBody(host, path, ctLower, response.body().getBytes());
            }

            if (JWT.matcher(url).find()) {
                record(host, path, "jwt_in_url", "JWT-like string in the URL (value is not stored)");
            }

            String body = response.bodyToString();
            if (body.length() > MAX_BODY_SCAN) {
                body = body.substring(0, MAX_BODY_SCAN);
            }
            if (JWT.matcher(body).find()) {
                record(host, path, "jwt_in_response_body", "JWT-like string in the response body (value is not stored)");
            }

            for (HttpHeader h : response.headers()) {
                if (!h.name().equalsIgnoreCase("Set-Cookie")) {
                    continue;
                }
                String value = h.value();
                String cookieName = value.split("=", 2)[0].trim();
                String flags = value.toLowerCase();
                if (!flags.contains("httponly")) {
                    record(host, path, "cookie_no_httponly", "cookie: " + cookieName);
                }
                if (https && !flags.contains("secure")) {
                    record(host, path, "cookie_no_secure", "cookie: " + cookieName);
                }
            }

            if (ctLower.contains("text/html")) {
                if (!response.hasHeader("Content-Security-Policy")) {
                    record(host, path, "html_no_csp", "HTML without Content-Security-Policy");
                }
                if (https && !response.hasHeader("Strict-Transport-Security")) {
                    record(host, path, "html_no_hsts", "HTML without Strict-Transport-Security");
                }
            }

            // A candidate for manual review, not a proven vulnerability.
            if (response.statusCode() == 200
                    && "GET".equalsIgnoreCase(request.method())
                    && path.contains("/api/")
                    && !request.hasHeader("Cookie")
                    && !request.hasHeader("Authorization")) {
                record(host, path, "api_200_without_credentials", "GET 200 without Cookie and Authorization: check by hand");
            }
        }

        private boolean inScope(String host) {
            long now = System.currentTimeMillis();
            if (now - scopeLoadedAt > 10_000) {
                scope = loadScope();
                scopeLoadedAt = now;
            }
            for (String pattern : scope) {
                if (pattern.startsWith("*.") ? host.endsWith(pattern.substring(1)) : host.equals(pattern)) {
                    return true;
                }
            }
            return false;
        }

        private static List<String> loadScope() {
            try {
                if (!Files.isRegularFile(SCOPE)) {
                    return List.of();
                }
                return Files.readAllLines(SCOPE, StandardCharsets.UTF_8).stream()
                        .map(String::trim)
                        .filter(s -> !s.isEmpty() && !s.startsWith("#"))
                        .map(String::toLowerCase)
                        .toList();
            } catch (IOException e) {
                return List.of();
            }
        }

        private void exportBody(String host, String path, String contentType, byte[] raw) {
            if (raw.length == 0 || raw.length > MAX_EXPORT) {
                return;
            }
            String sha = sha256Hex(raw);
            synchronized (lock) {
                if (!exported.add(sha)) {
                    return;
                }
                if (exported.size() > MAX_SEEN) {
                    exported.clear();
                }
                String line = "{\"ts\":" + json(Instant.now().toString())
                        + ",\"host\":" + json(host)
                        + ",\"path\":" + json(path)
                        + ",\"content_type\":" + json(contentType)
                        + ",\"sha256\":" + json(sha)
                        + ",\"file\":" + json(sha + ".txt")
                        + ",\"size\":" + raw.length + "}\n";
                try {
                    Files.createDirectories(BODIES);
                    restrict(BODIES, OWNER_DIR);
                    Path file = BODIES.resolve(sha + ".txt");
                    if (!Files.exists(file)) {
                        Files.write(file, raw);
                        restrict(file, OWNER_FILE);
                    }
                    Path index = BODIES.resolve("index.jsonl");
                    boolean fresh = !Files.exists(index);
                    Files.writeString(index, line, StandardCharsets.UTF_8,
                            StandardOpenOption.CREATE, StandardOpenOption.APPEND);
                    if (fresh) {
                        restrict(index, OWNER_FILE);
                    }
                } catch (IOException e) {
                    api.logging().logToError("AgentFindings body export failed: " + e.getMessage());
                }
            }
        }

        private static String sha256Hex(byte[] data) {
            try {
                byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
                StringBuilder hex = new StringBuilder();
                for (byte b : digest) {
                    hex.append(String.format("%02x", b));
                }
                return hex.toString();
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }
        }

        private void record(String host, String path, String check, String evidence) {
            String key = host + "\u0000" + path + "\u0000" + check + "\u0000" + evidence;
            synchronized (lock) {
                if (!seen.add(key)) {
                    return;
                }
                if (seen.size() > MAX_SEEN) {
                    seen.clear();
                }
                String line = "{\"ts\":" + json(Instant.now().toString())
                        + ",\"host\":" + json(host)
                        + ",\"path\":" + json(path)
                        + ",\"check\":" + json(check)
                        + ",\"evidence\":" + json(evidence) + "}\n";
                try {
                    Files.createDirectories(DIR);
                    restrict(DIR, OWNER_DIR);
                    boolean fresh = !Files.exists(FINDINGS);
                    Files.writeString(FINDINGS, line, StandardCharsets.UTF_8,
                            StandardOpenOption.CREATE, StandardOpenOption.APPEND);
                    if (fresh) {
                        restrict(FINDINGS, OWNER_FILE);
                    }
                } catch (IOException e) {
                    api.logging().logToError("AgentFindings write failed: " + e.getMessage());
                }
            }
        }

        /** Restricts permissions on POSIX systems; on other systems it is silently skipped. */
        private static void restrict(Path target, Set<PosixFilePermission> perms) {
            try {
                Files.setPosixFilePermissions(target, perms);
            } catch (IOException | UnsupportedOperationException e) {
                // Permissions were not set (not POSIX or no access): the file keeps the OS default permissions.
            }
        }

        private static String json(String s) {
            StringBuilder out = new StringBuilder("\"");
            for (char c : s.toCharArray()) {
                switch (c) {
                    case '"' -> out.append("\\\"");
                    case '\\' -> out.append("\\\\");
                    case '\n' -> out.append("\\n");
                    case '\r' -> out.append("\\r");
                    case '\t' -> out.append("\\t");
                    default -> {
                        if (c < 0x20) {
                            out.append(String.format("\\u%04x", (int) c));
                        } else {
                            out.append(c);
                        }
                    }
                }
            }
            return out.append('"').toString();
        }
    }
}
