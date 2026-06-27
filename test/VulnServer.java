import com.sun.net.httpserver.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Deliberately VULNERABLE test server — positive control to demonstrate the
 * Auto Scan engine catching real issues (reflected XSS, sensitive-file exposure,
 * insecure cookie, missing headers) with request/response proof. NOT the real app.
 */
public class VulnServer {
    public static void main(String[] args) throws Exception {
        int port = args.length>0 ? Integer.parseInt(args[0]) : 5599;
        HttpServer s = HttpServer.create(new InetSocketAddress(port), 0);
        s.createContext("/", VulnServer::handle);
        s.setExecutor(null);
        s.start();
        System.out.println("VulnServer on http://localhost:"+port);
    }

    static void handle(HttpExchange ex) throws IOException {
        String path = ex.getRequestURI().getPath();
        Map<String,String> q = parse(ex.getRequestURI().getRawQuery());

        // Sensitive file exposure (Critical)
        if (path.equals("/appsettings.json")) {
            byte[] body = "{\"ConnectionStrings\":{\"DefaultConnection\":\"DataSource=app.db\"}}".getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().add("Content-Type","application/json");
            ex.sendResponseHeaders(200, body.length); ex.getResponseBody().write(body); ex.close(); return;
        }

        // Reflected XSS: ReturnUrl / q reflected UNENCODED into HTML.
        String ru = q.getOrDefault("ReturnUrl", q.getOrDefault("q",""));
        String html = "<!DOCTYPE html><html><body><h1>Login</h1>"
                + "<p>Redirect target: " + ru + "</p>"   // <-- unencoded reflection
                + "<a href=\"/Account/Register?ReturnUrl=next\">Register</a></body></html>";
        byte[] body = html.getBytes(StandardCharsets.UTF_8);
        // Insecure cookie (no HttpOnly / SameSite) + no security headers + Server banner
        ex.getResponseHeaders().add("Set-Cookie","sid=abc123; path=/");
        ex.getResponseHeaders().add("Content-Type","text/html");
        ex.getResponseHeaders().add("Server","VulnServer/1.0");
        ex.sendResponseHeaders(200, body.length);
        ex.getResponseBody().write(body); ex.close();
    }

    static Map<String,String> parse(String q) {
        Map<String,String> m = new HashMap<>();
        if (q==null) return m;
        for (String kv : q.split("&")) {
            int i = kv.indexOf('=');
            if (i<0) continue;
            try { m.put(kv.substring(0,i), java.net.URLDecoder.decode(kv.substring(i+1), "UTF-8")); }
            catch (Exception ignore) {}
        }
        return m;
    }
}
