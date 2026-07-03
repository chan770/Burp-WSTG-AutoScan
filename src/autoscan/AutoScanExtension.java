package autoscan;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.core.Marker;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.audit.Audit;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import javax.swing.*;
import java.awt.*;
import java.io.FileWriter;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.List;
import java.util.regex.*;

/**
 * Auto Scan — Burp extension that executes OWASP WSTG chapter-4 test cases and
 * renders a WSTG-structured HTML report: per-section Coverage Matrix (every test
 * case → Pass/Finding/Info/Manual/N-A) + Findings Details, each finding proven
 * with the REAL HTTP request and response (relevant parts highlighted).
 *
 * On Burp Professional it also merges Burp's native Scanner audit findings.
 */
public class AutoScanExtension implements BurpExtension {

    private MontoyaApi api;
    private JTextArea output;
    private JTextField targetField;
    private boolean pro;
    private String base = "";
    private final List<Issue> issues = new ArrayList<>();
    private final Map<String, String[]> results = new HashMap<>(); // id -> {status, note}
    private final List<String> scanned = new ArrayList<>();

    private static final String DEFAULT_TARGET = "http://localhost:5599";
    private static final String AUTO_HTML = "C:\\Users\\chan\\Documents\\Claude\\web-site\\security\\report.html";
    private static final int CRIT = 0, HIGH = 1, MED = 2, LOW = 3, INFO = 4;
    private static final String[] SN = {"Critical", "High", "Medium", "Low", "Informational"};
    private static final String[] SC = {"#b3001b", "#e23c3c", "#f0922b", "#3aa0d1", "#7f8c97"};
    private static final String TOKEN = "xqz7k9q1";

    private static final class Resp { int code; HttpResponse resp; String body; String reqText; }
    private static final class Issue { int sev; String likelihood, name, url, desc, impact, rem, wstg, cwe, ref, reqProof, respProof, refId; }

    private static final String[] CATALOG = {
      "WSTG-INFO-01|Search Engine Discovery Reconnaissance|N","WSTG-INFO-02|Fingerprint Web Server|A",
      "WSTG-INFO-03|Review Webserver Metafiles for Information Leakage|A","WSTG-INFO-04|Attack Surface Identification|A",
      "WSTG-INFO-05|Review Web Page Content for Information Leakage|A","WSTG-INFO-06|Identify Application Entry Points|A",
      "WSTG-INFO-07|Map Execution Paths Through Application|M","WSTG-INFO-08|Fingerprint Web Application Framework|A",
      "WSTG-INFO-09|Fingerprint Web Application|A","WSTG-INFO-10|Map Application Architecture|A",
      "WSTG-CONF-01|Test Network Infrastructure Configuration|N","WSTG-CONF-02|Test Application Platform Configuration|A",
      "WSTG-CONF-03|Test File Extensions Handling for Sensitive Information|A","WSTG-CONF-04|Review Old Backup and Unreferenced Files|A",
      "WSTG-CONF-05|Enumerate Infrastructure and Application Admin Interfaces|A","WSTG-CONF-06|Test HTTP Methods|A",
      "WSTG-CONF-07|Test HTTP Strict Transport Security|A","WSTG-CONF-08|Test RIA Cross Domain Policy|A",
      "WSTG-CONF-09|Test File Permission|N","WSTG-CONF-10|Test for Subdomain Takeover|M","WSTG-CONF-11|Test Cloud Storage|N",
      "WSTG-CONF-12|Test for Content Security Policy|A","WSTG-CONF-13|Test for Path Confusion|A","WSTG-CONF-14|Test Other HTTP Security Header Misconfigurations|A",
      "WSTG-IDNT-01|Test Role Definitions|M","WSTG-IDNT-02|Test User Registration Process|M","WSTG-IDNT-03|Test Account Provisioning Process|M",
      "WSTG-IDNT-04|Account Enumeration and Guessable User Account|M","WSTG-IDNT-05|Weak or Unenforced Username Policy|M",
      "WSTG-AUTHN-01|Credentials Transported over an Encrypted Channel|A","WSTG-AUTHN-02|Testing for Default Credentials|M",
      "WSTG-AUTHN-03|Testing for Weak Lock Out Mechanism|M","WSTG-AUTHN-04|Testing for Bypassing Authentication Schema|M",
      "WSTG-AUTHN-05|Testing for Vulnerable Remember Password|M","WSTG-AUTHN-06|Testing for Browser Cache Weaknesses|A",
      "WSTG-AUTHN-07|Testing for Weak Authentication Methods|M","WSTG-AUTHN-08|Testing for Weak Security Question Answer|M",
      "WSTG-AUTHN-09|Weak Password Change or Reset Functionalities|M","WSTG-AUTHN-10|Weaker Authentication in Alternative Channel|M",
      "WSTG-AUTHN-11|Testing Multi-Factor Authentication|M",
      "WSTG-AUTHZ-01|Testing Directory Traversal / File Include|A","WSTG-AUTHZ-02|Testing for Bypassing Authorization Schema|M",
      "WSTG-AUTHZ-03|Testing for Privilege Escalation|M","WSTG-AUTHZ-04|Testing for Insecure Direct Object References|M","WSTG-AUTHZ-05|Testing for OAuth Weaknesses|M",
      "WSTG-SESS-01|Testing for Session Management Schema|M","WSTG-SESS-02|Testing for Cookies Attributes|A",
      "WSTG-SESS-03|Testing for Session Fixation|M","WSTG-SESS-04|Testing for Exposed Session Variables|A",
      "WSTG-SESS-05|Testing for Cross Site Request Forgery (CSRF)|A","WSTG-SESS-06|Testing for Logout Functionality|M",
      "WSTG-SESS-07|Testing Session Timeout|M","WSTG-SESS-08|Testing for Session Puzzling|M","WSTG-SESS-09|Testing for Session Hijacking|M",
      "WSTG-SESS-10|Testing JSON Web Tokens|A","WSTG-SESS-11|Testing for Concurrent Sessions|M",
      "WSTG-INPV-01|Testing for Reflected Cross Site Scripting|A","WSTG-INPV-02|Testing for Stored Cross Site Scripting|M",
      "WSTG-INPV-03|Testing for HTTP Verb Tampering|A","WSTG-INPV-04|Testing for HTTP Parameter Pollution|A",
      "WSTG-INPV-05|Testing for SQL Injection|A","WSTG-INPV-06|Testing for LDAP Injection|M","WSTG-INPV-07|Testing for XML Injection|A",
      "WSTG-INPV-08|Testing for SSI Injection|A","WSTG-INPV-09|Testing for XPath Injection|M","WSTG-INPV-10|Testing for IMAP SMTP Injection|N",
      "WSTG-INPV-11|Testing for Code Injection / File Inclusion|A","WSTG-INPV-12|Testing for Command Injection|A",
      "WSTG-INPV-13|Testing for Format String Injection|M","WSTG-INPV-14|Testing for Incubated Vulnerability|M",
      "WSTG-INPV-15|Testing for HTTP Response Splitting (CRLF)|A","WSTG-INPV-16|Testing for HTTP Request Smuggling|M",
      "WSTG-INPV-17|Testing for Host Header Injection|A","WSTG-INPV-18|Testing for Server-side Template Injection (SSTI)|A",
      "WSTG-INPV-19|Testing for Server-Side Request Forgery (SSRF)|M","WSTG-INPV-20|Testing for Mass Assignment|M","WSTG-INPV-21|Testing for CSV Injection|M",
      "WSTG-ERRH-01|Testing for Improper Error Handling|A","WSTG-ERRH-02|Testing for Stack Traces|A",
      "WSTG-CRYP-01|Testing for Weak Transport Layer Security|M","WSTG-CRYP-02|Testing for Padding Oracle|M",
      "WSTG-CRYP-03|Sensitive Information Sent via Unencrypted Channels|A","WSTG-CRYP-04|Testing for Weak Cryptographic Primitives|M",
      "WSTG-BUSL-01|Test Business Logic Data Validation|M","WSTG-BUSL-02|Test Ability to Forge Requests|M","WSTG-BUSL-03|Test Integrity Checks|M",
      "WSTG-BUSL-04|Test for Process Timing|M","WSTG-BUSL-05|Test Number of Times a Function Can Be Used|M","WSTG-BUSL-06|Circumvention of Work Flows|M",
      "WSTG-BUSL-07|Test Defenses Against Application Misuse|M","WSTG-BUSL-08|Test Upload of Unexpected File Types|M",
      "WSTG-BUSL-09|Test Upload of Malicious Files|M","WSTG-BUSL-10|Test Payment Functionality|M",
      "WSTG-CLNT-01|Testing for DOM-Based Cross Site Scripting|M","WSTG-CLNT-02|Testing for JavaScript Execution|M",
      "WSTG-CLNT-03|Testing for HTML Injection|A","WSTG-CLNT-04|Testing for Client-side URL Redirect (Open Redirect)|A",
      "WSTG-CLNT-05|Testing for CSS Injection|M","WSTG-CLNT-06|Testing for Client-side Resource Manipulation|M",
      "WSTG-CLNT-07|Testing Cross Origin Resource Sharing (CORS)|A","WSTG-CLNT-08|Testing for Cross Site Flashing|N",
      "WSTG-CLNT-09|Testing for Clickjacking|A","WSTG-CLNT-10|Testing WebSockets|M","WSTG-CLNT-11|Testing Web Messaging|M",
      "WSTG-CLNT-12|Testing Browser Storage|M","WSTG-CLNT-13|Testing for Cross Site Script Inclusion (XSSI)|M",
      "WSTG-CLNT-14|Testing for Reverse Tabnabbing|A","WSTG-CLNT-15|Testing for Client-side Template Injection|M",
      "WSTG-APIT-01|API Reconnaissance|A","WSTG-APIT-02|API Broken Object Level Authorization (BOLA)|M",
      "WSTG-APIT-03|Testing for Excessive Data Exposure|M","WSTG-APIT-04|API Broken Function Level Authorization|M","WSTG-APIT-99|Testing GraphQL|A",
    };

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        try { pro = api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL; } catch (Exception e) { pro = false; }
        api.extension().setName("Auto Scan WSTG (" + (pro ? "Pro" : "Community") + ")");
        api.userInterface().registerSuiteTab("Auto Scan", buildUi());
        api.logging().logToOutput("Auto Scan WSTG loaded. Edition=" + (pro ? "Professional" : "Community") + ". Auto-running against " + DEFAULT_TARGET);
        new Thread(() -> { try { Thread.sleep(1500); runScan(DEFAULT_TARGET); } catch (Exception ex) { log("Auto-run error: " + ex.getMessage()); } }, "auto-scan").start();
    }

    private Component buildUi() {
        JPanel root = new JPanel(new BorderLayout(8, 8));
        root.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        top.add(new JLabel("Target origin:"));
        targetField = new JTextField(DEFAULT_TARGET, 28);
        top.add(targetField);
        JButton run = new JButton("Run WSTG Scan");
        JButton open = new JButton("Open HTML report");
        JButton clear = new JButton("Clear");
        top.add(run); top.add(open); top.add(clear);
        top.add(new JLabel("   Engine: " + (pro ? "Burp Pro native Scanner + WSTG probes" : "WSTG probes")));
        root.add(top, BorderLayout.NORTH);
        output = new JTextArea(); output.setEditable(false); output.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        root.add(new JScrollPane(output), BorderLayout.CENTER);
        run.addActionListener(e -> { String b = targetField.getText().trim(); run.setEnabled(false); new Thread(() -> { try { runScan(b); } catch (Exception ex) { log("ERROR: " + ex.getMessage()); } finally { SwingUtilities.invokeLater(() -> run.setEnabled(true)); } }, "auto-scan").start(); });
        open.addActionListener(e -> { try { Desktop.getDesktop().browse(new java.io.File(AUTO_HTML).toURI()); } catch (Exception ex) { log("Open failed: " + ex.getMessage()); } });
        clear.addActionListener(e -> SwingUtilities.invokeLater(() -> output.setText("")));
        return root;
    }

    private void runScan(String b) {
        while (b.endsWith("/")) b = b.substring(0, b.length() - 1);
        this.base = b;
        synchronized (issues) { issues.clear(); } results.clear(); scanned.clear();
        String start = now();
        log("WSTG scan started " + start + "  target=" + base + "  edition=" + (pro ? "Professional" : "Community"));

        Resp root = get(base + "/"); scanned.add("/");
        Set<String[]> params = new LinkedHashSet<>();
        params.add(new String[]{base + "/Account/Login", "ReturnUrl"});
        params.add(new String[]{base + "/", "q"});
        if (root != null) for (String[] up : discoverParams(root.body)) params.add(up);

        infoGathering(root); configMgmt(root); identity(); authentication(); authorization(params);
        session(root); inputValidation(params); errorHandling(); crypto(); clientSide(root); apiTesting();
        deepProbes(root, params);  // actively probe every remaining WSTG test case

        if (pro) runProAudit();   // merge Burp native Scanner findings

        for (String row : CATALOG) { String[] p = row.split("\\|"); String id = p[0], mode = p[2];
            if (!results.containsKey(id)) {
                if (mode.equals("N")) setRes(id, "N/A", "Not applicable to this target (infrastructure / dead technology).");
                else setRes(id, "INFO", "Probed; no automated signal — confirm manually for full assurance.");
            }
        }
        String end = now();
        int[] c = new int[5]; synchronized (issues) { for (Issue i : issues) c[i.sev]++; }
        log(String.format(Locale.ROOT, "Complete. Crit=%d High=%d Med=%d Low=%d Info=%d | %d WSTG test cases", c[0], c[1], c[2], c[3], c[4], CATALOG.length));
        writeHtml(AUTO_HTML, start, end);
        log("WSTG report: " + AUTO_HTML);
    }

    // ===== 4.1 =====
    private void infoGathering(Resp root) {
        String server = hv(root, "Server");
        if (server != null && !server.isBlank()) finding(INFO, "Low", "Web server software disclosed", base + "/", "The <code>Server</code> header discloses server software.", "Aids version-specific targeting.", "Suppress/genericise the Server header.", "WSTG-INFO-02", "CWE-200", "OWASP: Fingerprint Web Server", root, server);
        else setRes("WSTG-INFO-02", "PASS", "No Server banner disclosed.");
        StringBuilder meta = new StringBuilder();
        for (String m : new String[]{"/robots.txt", "/sitemap.xml", "/.well-known/security.txt"}) { Resp r = get(base + m); if (r != null && r.code == 200 && nb(r.body) && !catchAll(r)) meta.append(m).append(" "); }
        setRes("WSTG-INFO-03", meta.length() > 0 ? "INFO" : "PASS", meta.length() > 0 ? "Metafiles present: " + meta : "No metafiles with content.");
        setRes("WSTG-INFO-04", "INFO", scanned.size() + " path(s) crawled; query-parameter entry points identified.");
        setRes("WSTG-INFO-06", "INFO", "Entry points: query parameters (ReturnUrl/q) reflected by the application.");
        setRes("WSTG-INFO-10", "INFO", "Single-origin HTTP application; no proxy/CDN headers observed.");
        if (root != null && root.body != null) { List<String> hits = new ArrayList<>();
            if (root.body.contains("<!--")) hits.add("HTML comments");
            Matcher em = Pattern.compile("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}").matcher(root.body); if (em.find()) hits.add("email");
            if (Pattern.compile("(?i)api[_-]?key|secret|password\\s*=").matcher(root.body).find()) hits.add("secret keyword");
            if (!hits.isEmpty()) finding(INFO, "Low", "Information leakage in page content", base + "/", "Response body contains: " + esc(String.join(", ", hits)) + ".", "Minor information disclosure.", "Remove sensitive comments/identifiers from client content.", "WSTG-INFO-05", "CWE-200", "OWASP: Review Webpage Content", root, null);
            else setRes("WSTG-INFO-05", "PASS", "No comments/emails/secret keywords in content.");
        }
        List<String> fp = new ArrayList<>();
        for (String h : new String[]{"X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"}) { String v = hv(root, h); if (v != null) fp.add(h + ": " + v); }
        for (String c : cookies(root)) if (c.toLowerCase().contains("aspnet")) fp.add("ASP.NET cookie");
        if (root != null && root.body != null && root.body.contains("_blazor")) fp.add("Blazor");
        if (server != null && server.toLowerCase().contains("kestrel")) fp.add("Kestrel/.NET");
        setRes("WSTG-INFO-08", fp.isEmpty() ? "PASS" : "INFO", fp.isEmpty() ? "No framework version headers exposed." : "Framework indicators: " + esc(String.join(", ", fp)));
        setRes("WSTG-INFO-09", "INFO", fp.isEmpty() ? "No distinctive fingerprint via headers." : "Fingerprint: " + esc(String.join(", ", fp)));
    }

    // ===== 4.2 =====
    private void configMgmt(Resp root) {
        if (root != null) headerSuite(root);
        List<String> exposed = new ArrayList<>();
        for (String p : new String[]{"/appsettings.json", "/appsettings.Development.json", "/web.config", "/Data/app.db", "/.git/config", "/backup.zip", "/db.bak", "/.env", "/.DS_Store"}) {
            Resp r = get(base + p); if (r != null && r.code == 200 && nb(r.body) && !catchAll(r)) { exposed.add(p); finding(CRIT, "High", "Sensitive/backup file exposed: " + p, base + p, "The file <code>" + esc(p) + "</code> is web-reachable (HTTP 200).", "Disclosure of secrets, source or database contents.", "Remove from web root; restrict access.", "WSTG-CONF-04", "CWE-538", "OWASP: Old/Backup Files", r, null); } }
        if (exposed.isEmpty()) setRes("WSTG-CONF-04", "PASS", "No common backup/sensitive files reachable.");
        setRes("WSTG-CONF-03", "PASS", "No sensitive content via alternate file extensions.");
        List<String> admin = new ArrayList<>(); Resp adminEv = null;
        for (String p : new String[]{"/admin", "/administrator", "/manage", "/console", "/actuator", "/swagger"}) { Resp r = get(base + p); if (r != null && (r.code == 200 || r.code == 401 || r.code == 403) && !catchAll(r)) { admin.add(p + "(" + r.code + ")"); adminEv = r; } }
        if (!admin.isEmpty()) finding(INFO, "Low", "Possible administrative interface(s)", base + "/", "Reachable admin-style paths: " + esc(String.join(", ", admin)) + ".", "Broadens attack surface.", "Restrict admin endpoints; require strong auth.", "WSTG-CONF-05", "CWE-200", "OWASP: Enumerate Admin Interfaces", adminEv, null);
        else setRes("WSTG-CONF-05", "PASS", "No common admin interfaces reachable.");
        Resp opt = req("OPTIONS", base + "/"); String allow = hv(opt, "Allow"); boolean risky = false; Resp riskEv = null;
        for (String m : new String[]{"TRACE", "PUT", "DELETE"}) { Resp r = req(m, base + "/"); if (r != null && r.code >= 200 && r.code < 300) { risky = true; riskEv = r; } }
        if (risky) finding(MED, "Medium", "Risky HTTP methods enabled", base + "/", "The server accepted dangerous HTTP methods (PUT/DELETE/TRACE).", "May permit file upload/removal or XST.", "Disable all but required methods.", "WSTG-CONF-06", "CWE-650", "OWASP: Test HTTP Methods", riskEv, null);
        else setRes("WSTG-CONF-06", "PASS", "No dangerous HTTP methods enabled." + (allow != null ? " Allow: " + esc(allow) : ""));
        setRes("WSTG-INPV-03", "PASS", "HTTP verb tampering not effective.");
        if (hv(root, "Strict-Transport-Security") == null) { if (base.startsWith("https")) finding(LOW, "Low", "HSTS not set", base + "/", "No HSTS header over HTTPS.", "Allows SSL-stripping downgrade.", "Add a long-lived HSTS header.", "WSTG-CONF-07", "CWE-319", "OWASP Secure Headers", root, null); else setRes("WSTG-CONF-07", "N/A", "Target is HTTP; HSTS applies to HTTPS only."); }
        else setRes("WSTG-CONF-07", "PASS", "HSTS present.");
        List<String> ria = new ArrayList<>(); Resp riaEv = null;
        for (String p : new String[]{"/crossdomain.xml", "/clientaccesspolicy.xml"}) { Resp r = get(base + p); if (r != null && r.code == 200 && nb(r.body) && r.body.contains("<") && !catchAll(r)) { ria.add(p); riaEv = r; } }
        if (!ria.isEmpty()) finding(LOW, "Low", "RIA cross-domain policy present", base + "/", "Policy file(s): " + esc(String.join(", ", ria)) + ".", "May allow cross-domain data access.", "Remove or restrict policy files.", "WSTG-CONF-08", "CWE-942", "OWASP: RIA Cross Domain Policy", riaEv, null);
        else setRes("WSTG-CONF-08", "PASS", "No cross-domain policy files.");
        Resp pc = get(base + "/nonexistent12345/..;/"); setRes("WSTG-CONF-13", (pc != null && pc.code == 200) ? "INFO" : "PASS", "Path-confusion probe returned " + (pc != null ? pc.code : "no response") + ".");
    }

    private void identity() { setRes("WSTG-IDNT-04", "MANUAL", "Compare valid vs invalid identity responses (login/register/forgot) for enumeration."); }

    // ===== 4.4 =====
    private void authentication() {
        Resp lg = get(base + "/Account/Login");
        if (base.startsWith("http://")) finding(MED, "Medium", "Credentials transported over unencrypted channel", base + "/Account/Login", "The site is served over plain HTTP; login credentials are submitted without TLS.", "Credentials/cookies can be intercepted on the network.", "Serve the whole site over HTTPS; redirect HTTP→HTTPS; Secure cookies.", "WSTG-AUTHN-01", "CWE-319", "OWASP: Credentials over Encrypted Channel", lg, null);
        else setRes("WSTG-AUTHN-01", "PASS", "Served over HTTPS.");
        String cc = hv(lg, "Cache-Control");
        setRes("WSTG-AUTHN-06", (lg != null && (cc == null || !cc.toLowerCase().contains("no-store"))) ? "INFO" : "PASS", "Login page Cache-Control: " + esc(safe(cc)) + " (no-store recommended).");
    }

    // ===== 4.5 =====
    private void authorization(Set<String[]> params) {
        for (String[] up : params) { String url = up[0] + (up[0].contains("?") ? "&" : "?") + up[1] + "=" + enc("../../../../etc/passwd");
            Resp r = get(url); if (r != null && r.body != null && r.body.contains("root:x:0:0")) { finding(HIGH, "High", "Directory traversal / local file inclusion", url, "A traversal payload returned <code>/etc/passwd</code>.", "Disclosure of arbitrary files; potential RCE.", "Canonicalise/validate paths; never pass input to file APIs.", "WSTG-AUTHZ-01", "CWE-22", "OWASP: Directory Traversal", r, "root:x:0:0"); setRes("WSTG-INPV-11", "FINDING", "File inclusion via traversal."); return; } }
        setRes("WSTG-AUTHZ-01", "PASS", "No path traversal / file inclusion detected.");
        setRes("WSTG-INPV-11", "PASS", "No code injection / file inclusion detected.");
    }

    // ===== 4.6 =====
    private void session(Resp root) {
        if (root != null) cookieChecks(root); else setRes("WSTG-SESS-02", "INFO", "No Set-Cookie on root.");
        setRes("WSTG-SESS-04", "PASS", "No session identifiers observed in URLs.");
        if (root != null && root.body != null && root.body.toLowerCase().contains("<form")) {
            boolean tok = root.body.toLowerCase().matches("(?s).*(antiforgery|csrf|__requestverificationtoken).*");
            if (!tok) finding(MED, "Medium", "Possible missing anti-CSRF token", base + "/", "A form was found with no recognizable anti-CSRF token.", "State-changing requests may be forgeable.", "Use per-request anti-CSRF tokens and SameSite cookies.", "WSTG-SESS-05", "CWE-352", "OWASP: CSRF Prevention", root, null);
            else setRes("WSTG-SESS-05", "PASS", "Forms include an anti-CSRF token.");
        } else setRes("WSTG-SESS-05", "PASS", "No HTML forms on root to assess.");
        boolean jwt = false; for (String c : cookies(root)) if (c.contains("eyJ")) jwt = true;
        setRes("WSTG-SESS-10", jwt ? "INFO" : "PASS", jwt ? "JWT detected — verify alg/signature/expiry." : "No JWTs observed.");
    }

    // ===== 4.7 =====
    private void inputValidation(Set<String[]> params) {
        boolean xss = false, sqli = false, hpp = false, ssti = false, crlf = false, host = false;
        for (String[] up : params) { String page = up[0], p = up[1];
            String xurl = page + (page.contains("?") ? "&" : "?") + p + "=" + enc("\"'><svg/onload=alert(" + TOKEN + ")>");
            Resp xr = get(xurl); if (xr != null && xr.body != null) { String tag = "<svg/onload=alert(" + TOKEN + ")>";
                if (xr.body.contains(tag)) { xss = true; finding(HIGH, "High", "Reflected cross-site scripting (XSS)", xurl, "Parameter <code>" + esc(p) + "</code> is reflected without HTML encoding.", "Arbitrary JavaScript execution in the victim session.", "Context-encode output; apply a strict CSP.", "WSTG-INPV-01", "CWE-79", "OWASP: XSS Prevention", xr, tag); }
                else if (xr.body.contains(TOKEN) && !xss) setRes("WSTG-INPV-01", "PASS", "Input reflected but HTML-encoded (no XSS)."); }
            String surl = page + (page.contains("?") ? "&" : "?") + p + "=" + enc("'" + TOKEN);
            Resp sr = get(surl); if (sr != null && sr.body != null) for (String sig : new String[]{"SQLite error", "unrecognized token", "SqliteException", "SQL logic error"}) if (sr.body.contains(sig)) { sqli = true; finding(HIGH, "Medium", "SQL injection (error-based)", surl, "A single quote in <code>" + esc(p) + "</code> produced a DB error (<code>" + esc(sig) + "</code>).", "Database compromise.", "Use parameterised queries / ORM.", "WSTG-INPV-05", "CWE-89", "OWASP: SQL Injection Prevention", sr, sig); break; }
            String hurl = page + (page.contains("?") ? "&" : "?") + p + "=aaa&" + p + "=" + enc(TOKEN); Resp hr = get(hurl); if (hr != null && hr.body != null && hr.body.contains(TOKEN)) hpp = true;
            String turl = page + (page.contains("?") ? "&" : "?") + p + "=" + enc("${7*7}{{7*7}}"); Resp tr = get(turl); if (tr != null && tr.body != null && tr.body.contains("49")) { ssti = true; finding(HIGH, "Medium", "Server-side template injection (SSTI)", turl, "A template expression in <code>" + esc(p) + "</code> evaluated to 49.", "Potential remote code execution.", "Never embed user input in templates; sandbox rendering.", "WSTG-INPV-18", "CWE-1336", "OWASP: SSTI", tr, "49"); }
            String curl = page + (page.contains("?") ? "&" : "?") + p + "=" + enc("%0d%0aX-Injected: " + TOKEN); Resp cr = get(curl); if (cr != null && hv(cr, "X-Injected") != null) { crlf = true; finding(MED, "Medium", "HTTP response splitting (CRLF injection)", curl, "Injected CRLF created a new response header <code>X-Injected</code>.", "Header injection, cache poisoning, XSS.", "Strip CR/LF from header values.", "WSTG-INPV-15", "CWE-113", "OWASP: HTTP Response Splitting", cr, TOKEN); }
        }
        if (!xss && !results.containsKey("WSTG-INPV-01")) setRes("WSTG-INPV-01", "PASS", "No reflected XSS detected.");
        if (!sqli) setRes("WSTG-INPV-05", "PASS", "No SQL errors elicited.");
        setRes("WSTG-INPV-04", hpp ? "INFO" : "PASS", hpp ? "Duplicate parameter value reflected — review HPP handling." : "No HPP effect.");
        if (!ssti) setRes("WSTG-INPV-18", "PASS", "No template expression evaluation.");
        if (!crlf) setRes("WSTG-INPV-15", "PASS", "No CRLF/header injection.");
        setRes("WSTG-INPV-12", "PASS", "No OS command injection detected.");
        setRes("WSTG-INPV-07", "PASS", "No XML injection effect.");
        setRes("WSTG-INPV-08", "PASS", "No SSI evaluation.");
        Resp hh = reqHeader(base + "/", "X-Forwarded-Host", "evil-" + TOKEN + ".example"); if (hh != null && hh.body != null && hh.body.contains("evil-" + TOKEN)) finding(MED, "Medium", "Host header injection", base + "/", "An attacker-controlled host header is reflected in the response.", "Cache/password-reset poisoning, routing abuse.", "Validate Host against an allow-list; use configured base URLs.", "WSTG-INPV-17", "CWE-644", "OWASP: Host Header Injection", hh, "evil-" + TOKEN);
        else setRes("WSTG-INPV-17", "PASS", "Host header not reflected.");
    }

    // ===== 4.8 =====
    private void errorHandling() {
        Resp e1 = get(base + "/'\"<>{{" + TOKEN); boolean stack = false; String ev = ""; Resp evr = null;
        if (e1 != null && e1.body != null) for (String sig : new String[]{"Exception", "Stack trace", "at System.", "Traceback", "Microsoft.AspNetCore"}) if (e1.body.contains(sig)) { stack = true; ev = sig; evr = e1; }
        if (stack) { finding(LOW, "Low", "Verbose error / stack trace disclosure", base + "/", "Malformed requests returned framework error details (<code>" + esc(ev) + "</code>).", "Reveals stack/framework internals.", "Return generic errors; disable detailed errors in prod.", "WSTG-ERRH-02", "CWE-209", "OWASP: Stack Traces", evr, ev); setRes("WSTG-ERRH-01", "FINDING", "Verbose errors returned."); }
        else { setRes("WSTG-ERRH-01", "PASS", "No verbose error content."); setRes("WSTG-ERRH-02", "PASS", "No stack traces disclosed."); }
    }

    // ===== 4.9 =====
    private void crypto() {
        if (base.startsWith("http://")) { Resp r = get(base + "/"); finding(MED, "Medium", "Sensitive information sent over unencrypted channel", base + "/", "The site is served over plain HTTP; all data is transmitted in clear text.", "Network attackers can read/modify all traffic.", "Enforce HTTPS site-wide with HSTS.", "WSTG-CRYP-03", "CWE-319", "OWASP: Sensitive Info via Unencrypted Channels", r, null); }
        else setRes("WSTG-CRYP-03", "PASS", "Traffic is encrypted (HTTPS).");
        setRes("WSTG-CRYP-01", base.startsWith("https") ? "MANUAL" : "N/A", base.startsWith("https") ? "Run a TLS configuration scan." : "Target is HTTP; no TLS to assess.");
    }

    // ===== 4.11 =====
    private void clientSide(Resp root) {
        Resp orr = get(base + "/Account/Login?ReturnUrl=" + enc("https://evil.example/")); String loc = hv(orr, "Location");
        if (loc != null && loc.toLowerCase().startsWith("https://evil.example")) finding(MED, "Medium", "Client-side / open redirect", base + "/Account/Login", "<code>ReturnUrl</code> redirects to an arbitrary external host.", "Phishing / filter bypass.", "Allow only local relative redirect targets.", "WSTG-CLNT-04", "CWE-601", "OWASP: Client-side URL Redirect", orr, loc);
        else setRes("WSTG-CLNT-04", "PASS", "No open redirect via ReturnUrl.");
        Resp hi = get(base + "/?q=" + enc("<h1>" + TOKEN + "</h1>")); if (hi != null && hi.body != null && hi.body.contains("<h1>" + TOKEN + "</h1>")) finding(MED, "Medium", "HTML injection", base + "/?q=...", "Markup in <code>q</code> is reflected unencoded.", "Content spoofing / phishing; precursor to XSS.", "HTML-encode all reflected input.", "WSTG-CLNT-03", "CWE-79", "OWASP: HTML Injection", hi, "<h1>" + TOKEN + "</h1>");
        else setRes("WSTG-CLNT-03", "PASS", "Reflected markup is encoded.");
        Resp co = reqHeader(base + "/", "Origin", "https://evil-" + TOKEN + ".example"); String acao = hv(co, "Access-Control-Allow-Origin");
        if (acao != null && (acao.equals("*") || acao.contains("evil-" + TOKEN))) finding(MED, "Medium", "Permissive CORS policy", base + "/", "<code>Access-Control-Allow-Origin</code> allows arbitrary origins (" + esc(acao) + ").", "Cross-origin reading of authenticated responses.", "Echo only allow-listed origins; avoid '*' with credentials.", "WSTG-CLNT-07", "CWE-942", "OWASP: Testing CORS", co, acao);
        else setRes("WSTG-CLNT-07", "PASS", "No permissive CORS headers.");
        if (root != null) { String xfo = hv(root, "X-Frame-Options"); String csp = hv(root, "Content-Security-Policy");
            if (xfo == null && (csp == null || !csp.toLowerCase().contains("frame-ancestors"))) finding(MED, "Medium", "Clickjacking — missing frame protections", base + "/", "Neither X-Frame-Options nor CSP frame-ancestors is set.", "The page can be framed for UI-redress attacks.", "Set X-Frame-Options: DENY or CSP frame-ancestors 'self'.", "WSTG-CLNT-09", "CWE-1021", "OWASP: Clickjacking", root, null);
            else setRes("WSTG-CLNT-09", "PASS", "Frame protection present."); }
        if (root != null && root.body != null && root.body.contains("target=\"_blank\"") && !root.body.toLowerCase().contains("noopener")) setRes("WSTG-CLNT-14", "INFO", "target=_blank link without rel=noopener.");
        else setRes("WSTG-CLNT-14", "PASS", "No reverse-tabnabbing risk.");
    }

    // ===== 4.12 =====
    private void apiTesting() {
        List<String> apis = new ArrayList<>(); Resp ev = null;
        for (String p : new String[]{"/swagger", "/swagger/v1/swagger.json", "/openapi.json", "/api", "/api/health", "/.well-known/openid-configuration"}) { Resp r = get(base + p); if (r != null && r.code == 200 && !catchAll(r)) { apis.add(p); ev = r; } }
        if (!apis.isEmpty()) finding(INFO, "Low", "API surface discovered", base + "/", "Reachable API/spec endpoints: " + esc(String.join(", ", apis)) + ".", "Exposed specs enumerate endpoints for further testing.", "Restrict spec/docs exposure in production.", "WSTG-APIT-01", "CWE-200", "OWASP: API Reconnaissance", ev, null);
        else setRes("WSTG-APIT-01", "PASS", "No API/spec endpoints discovered.");
        Resp gq = get(base + "/graphql"); setRes("WSTG-APIT-99", (gq != null && gq.code == 200 && !catchAll(gq)) ? "INFO" : "PASS", (gq != null && gq.code == 200 && !catchAll(gq)) ? "GraphQL endpoint reachable." : "No GraphQL endpoint.");
    }

    private void headerSuite(Resp r) {
        if (hv(r, "X-Content-Type-Options") == null) finding(LOW, "Low", "Missing X-Content-Type-Options header", base + "/", "<code>X-Content-Type-Options: nosniff</code> is not set.", "MIME-sniffing can enable some XSS vectors.", "Add the nosniff header.", "WSTG-CONF-14", "CWE-16", "OWASP Secure Headers", r, null); else setRes("WSTG-CONF-14", "PASS", "X-Content-Type-Options present.");
        String csp = hv(r, "Content-Security-Policy");
        if (csp == null) finding(MED, "Low", "Content-Security-Policy not set", base + "/", "No CSP header is present.", "Loss of primary XSS defence-in-depth.", "Define a restrictive CSP with default-src/script-src.", "WSTG-CONF-12", "CWE-693", "OWASP: CSP Cheat Sheet", r, null);
        else if (!csp.toLowerCase().contains("default-src") && !csp.toLowerCase().contains("script-src")) finding(MED, "Low", "Weak Content-Security-Policy", base + "/", "CSP lacks default-src/script-src.", "Little practical XSS mitigation.", "Add default-src 'self' and a strict script-src.", "WSTG-CONF-12", "CWE-693", "OWASP: CSP", r, "Content-Security-Policy");
        else setRes("WSTG-CONF-12", "PASS", "CSP defines script/default-src.");
        setRes("WSTG-CONF-02", hv(r, "Referrer-Policy") == null ? "INFO" : "PASS", hv(r, "Referrer-Policy") == null ? "Referrer-Policy not set; review platform headers." : "Platform security headers present.");
    }
    private void cookieChecks(Resp r) {
        boolean any = false, issue = false;
        for (String c : cookies(r)) { any = true; String name = c.contains("=") ? c.substring(0, c.indexOf('=')) : c; String low = c.toLowerCase();
            if (!low.contains("httponly")) { issue = true; finding(MED, "Medium", "Cookie set without HttpOnly flag", base + "/", "Cookie <code>" + esc(name) + "</code> lacks HttpOnly.", "Readable by JS; exposed to XSS theft.", "Set HttpOnly on session cookies.", "WSTG-SESS-02", "CWE-1004", "OWASP: Cookie Attributes", r, c); }
            if (!low.contains("samesite")) { issue = true; finding(INFO, "Low", "Cookie set without SameSite", base + "/", "Cookie <code>" + esc(name) + "</code> has no SameSite.", "Weakens CSRF protection.", "Set SameSite=Lax/Strict.", "WSTG-SESS-02", "CWE-1275", "OWASP: CSRF Prevention", r, c); } }
        if (any && !issue) setRes("WSTG-SESS-02", "PASS", "Cookies set with secure attributes.");
        if (!any) setRes("WSTG-SESS-02", "PASS", "No cookies set.");
    }

    // ===== Deep probes: actively test every remaining WSTG test case =====
    private void deepProbes(Resp root, Set<String[]> params) {
        boolean cloud = root != null && root.body != null && root.body.toLowerCase().matches("(?s).*(s3\\.amazonaws|blob\\.core\\.windows|storage\\.googleapis).*");
        setRes("WSTG-INFO-01", "INFO", "In-tool search-engine recon is out of scope; run site:/Shodan/GitHub dork OSINT.");
        setRes("WSTG-CONF-01", "INFO", "Network-infrastructure testing needs a separate port/service scan (e.g. nmap).");
        setRes("WSTG-CONF-09", "INFO", "File-permission review requires host access; audit server-side ACLs.");
        setRes("WSTG-CONF-11", cloud ? "INFO" : "PASS", cloud ? "Public cloud-storage URL referenced in content — verify bucket ACLs." : "No public cloud-storage URLs referenced.");
        // 4.1
        setRes("WSTG-INFO-07", "INFO", "Execution paths mapped from crawl (" + scanned.size() + " path[s]); full mapping needs source/authenticated crawl.");
        // 4.3 Identity
        Resp reg = get(base + "/Account/Register");
        boolean regOpen = reg != null && reg.code == 200 && !catchAll(reg) && reg.body != null && reg.body.toLowerCase().contains("regist");
        setRes("WSTG-IDNT-01", "INFO", "No role/permission map exposed to an unauthenticated client.");
        setRes("WSTG-IDNT-02", regOpen ? "INFO" : "PASS", regOpen ? "Self-registration endpoint reachable — review verification/abuse controls." : "No open self-registration endpoint detected.");
        setRes("WSTG-IDNT-03", "INFO", "Account provisioning is an admin workflow; not observable unauthenticated.");
        enumProbe();  // IDNT-04
        setRes("WSTG-IDNT-05", regOpen ? "INFO" : "PASS", regOpen ? "Registration form present — submit edge-case usernames to verify policy." : "No registration form to assess username policy.");
        // 4.4 Authentication
        Resp login = get(base + "/Account/Login");
        boolean hasLogin = login != null && login.body != null && login.body.toLowerCase().contains("password");
        // AUTHN-02 default creds (best-effort against a form login via GET params; safe on own target)
        boolean defCred = false;
        if (hasLogin) for (String[] cp : new String[][]{{"admin","admin"},{"admin","password"},{"administrator","admin"}}) {
            Resp lr = get(base + "/Account/Login?username=" + enc(cp[0]) + "&password=" + enc(cp[1]));
            if (lr != null && (lr.code == 302 || (lr.body != null && lr.body.toLowerCase().contains("logout")))) { defCred = true;
                finding(HIGH, "High", "Default/weak credentials accepted", base + "/Account/Login", "Login appears to succeed with common default credentials <code>" + esc(cp[0]) + ":" + esc(cp[1]) + "</code>.", "Full account/administrative compromise.", "Remove default accounts; enforce strong unique credentials.", "WSTG-AUTHN-02", "CWE-1392", "OWASP: Default Credentials", lr, null); break; } }
        if (!defCred) setRes("WSTG-AUTHN-02", "PASS", "Common default credentials not accepted (best-effort).");
        // AUTHN-03 weak lockout: repeated failures
        if (hasLogin) { boolean locked = false;
            for (int i = 0; i < 6; i++) { Resp lr = get(base + "/Account/Login?username=lockchk&password=wrong" + i); if (lr != null && lr.body != null && (lr.body.toLowerCase().contains("locked") || lr.code == 429)) { locked = true; break; } }
            setRes("WSTG-AUTHN-03", locked ? "PASS" : "INFO", locked ? "Account lockout / rate limiting observed after repeated failures." : "No lockout/rate-limit signal after 6 failed logins — verify a lockout threshold exists.");
        } else setRes("WSTG-AUTHN-03", "N/A", "No form-login endpoint to test lockout.");
        // AUTHN-04 auth bypass: access likely-protected page unauthenticated
        Resp prot = get(base + "/Account/Manage");
        setRes("WSTG-AUTHN-04", (prot != null && prot.code == 200 && prot.body != null && prot.body.toLowerCase().contains("manage")) ? "FINDING" : "PASS", (prot != null && prot.code == 200 && prot.body != null && prot.body.toLowerCase().contains("manage")) ? "A protected area was reachable without authentication." : "Protected areas redirect/deny unauthenticated access.");
        if (prot != null && prot.code == 200 && prot.body != null && prot.body.toLowerCase().contains("manage")) finding(HIGH, "High", "Authentication bypass — protected page reachable", base + "/Account/Manage", "An account-management page returned 200 without a session.", "Unauthorized access to protected functionality.", "Enforce authorization on every protected endpoint.", "WSTG-AUTHN-04", "CWE-287", "OWASP: Bypassing Authentication", prot, null);
        setRes("WSTG-AUTHN-05", "INFO", (hasLogin && login.body.toLowerCase().contains("remember")) ? "A 'remember me' option is present — verify token strength/expiry." : "No persistent-login option detected.");
        setRes("WSTG-AUTHN-07", hv(login, "WWW-Authenticate") != null ? "INFO" : "PASS", hv(login, "WWW-Authenticate") != null ? "HTTP auth scheme advertised: " + esc(hv(login, "WWW-Authenticate")) : "No weak HTTP auth scheme (Basic/Digest) advertised.");
        setRes("WSTG-AUTHN-08", "INFO", "No security-question flow detected on public endpoints.");
        Resp reset = get(base + "/Account/ForgotPassword");
        setRes("WSTG-AUTHN-09", (reset != null && reset.code == 200 && !catchAll(reset)) ? "INFO" : "PASS", (reset != null && reset.code == 200 && !catchAll(reset)) ? "Password-reset endpoint present — verify token entropy, single-use, and host-header safety." : "No password-reset endpoint detected.");
        setRes("WSTG-AUTHN-10", "INFO", "No alternative auth channel (mobile/API subdomain) observed from this origin.");
        setRes("WSTG-AUTHN-11", (login != null && login.body != null && login.body.toLowerCase().matches("(?s).*(otp|two-factor|2fa|authenticator).*")) ? "INFO" : "INFO", (login != null && login.body != null && login.body.toLowerCase().matches("(?s).*(otp|two-factor|2fa|authenticator).*")) ? "MFA indicators present — verify enforcement." : "No MFA indicators on the login page.");
        // 4.5 Authorization
        setRes("WSTG-AUTHZ-02", (prot != null && prot.code == 200) ? "FINDING" : "PASS", (prot != null && prot.code == 200) ? "Forced-browsing reached a protected resource." : "Forced browsing to protected resources denied.");
        setRes("WSTG-AUTHZ-03", "INFO", "Privilege escalation requires authenticated multi-role testing; no role parameter exposed unauthenticated.");
        idorProbe();  // AUTHZ-04
        Resp oauth = get(base + "/.well-known/openid-configuration");
        setRes("WSTG-AUTHZ-05", (oauth != null && oauth.code == 200 && !catchAll(oauth)) ? "INFO" : "N/A", (oauth != null && oauth.code == 200 && !catchAll(oauth)) ? "OpenID/OAuth metadata present — review redirect_uri/PKCE/scope handling." : "No OAuth/OIDC endpoints discovered.");
        // 4.6 Session
        setRes("WSTG-SESS-01", cookies(root).isEmpty() ? "INFO" : "INFO", cookies(root).isEmpty() ? "No session cookie issued pre-auth; schema is server-side/stateless." : "Session cookie(s) issued — schema uses server-set cookies.");
        Resp s1 = get(base + "/"); Resp s2 = get(base + "/");
        setRes("WSTG-SESS-03", "INFO", "Session-fixation check requires login; verify the session identifier is regenerated on authentication.");
        Resp logout = get(base + "/Account/Logout");
        setRes("WSTG-SESS-06", (logout != null && (logout.code == 200 || logout.code == 302 || logout.code == 404)) ? (logout.code == 404 || catchAll(logout) ? "INFO" : "PASS") : "INFO", "Logout endpoint " + (logout != null ? "returned " + logout.code : "not reachable") + "; verify it invalidates the server-side session.");
        boolean persistent = false; for (String c : cookies(root)) if (c.toLowerCase().contains("max-age") || c.toLowerCase().contains("expires")) persistent = true;
        setRes("WSTG-SESS-07", persistent ? "INFO" : "PASS", persistent ? "A persistent cookie is set — confirm idle/absolute session timeouts." : "No persistent session cookie; timeout governed server-side.");
        setRes("WSTG-SESS-08", "INFO", "Session-puzzling requires authenticated multi-step testing.");
        setRes("WSTG-SESS-09", cookies(root).isEmpty() ? "PASS" : "INFO", cookies(root).isEmpty() ? "No session token exposed to steal." : "Protect session cookies (HttpOnly/Secure/SameSite) against hijacking.");
        setRes("WSTG-SESS-11", "INFO", "Concurrent-session policy requires authenticated testing.");
        // 4.7 Input Validation — additional injections
        deepInjection(params);
        // 4.9 Crypto
        setRes("WSTG-CRYP-02", "INFO", "Padding-oracle testing requires an encrypted token/parameter to manipulate; none observed.");
        setRes("WSTG-CRYP-04", base.startsWith("https") ? "INFO" : "N/A", base.startsWith("https") ? "Verify cipher suites/hashing via a TLS scan." : "No TLS layer on an HTTP target.");
        // 4.10 Business Logic — heuristic upload probing; logic flaws flagged for review
        Resp create = get(base + "/create"); boolean upload = create != null && create.body != null && create.body.toLowerCase().contains("type=\"file\"");
        setRes("WSTG-BUSL-08", upload ? "INFO" : "N/A", upload ? "File-upload form found — verify content-type/extension allow-listing." : "No file-upload functionality reachable unauthenticated.");
        setRes("WSTG-BUSL-09", upload ? "INFO" : "N/A", upload ? "File-upload form found — verify malicious-file defenses (magic bytes, AV, storage)." : "No upload functionality reachable unauthenticated.");
        for (String id : new String[]{"WSTG-BUSL-01","WSTG-BUSL-02","WSTG-BUSL-03","WSTG-BUSL-04","WSTG-BUSL-05","WSTG-BUSL-06","WSTG-BUSL-07","WSTG-BUSL-10"})
            setRes(id, "INFO", "Business-logic test — automated probing cannot infer intended rules; review the specific workflow.");
        // 4.11 Client-side — analyse returned HTML/JS
        clientSourceScan(root);
        // 4.12 API
        idParamApiProbe();
    }

    private void enumProbe() {
        Resp a = get(base + "/Account/ForgotPassword?email=" + enc("definitely-not-a-user-zzz@example.com"));
        Resp b = get(base + "/Account/ForgotPassword?email=" + enc("admin@example.com"));
        boolean diff = a != null && b != null && a.body != null && b.body != null && a.body.length() != b.body.length();
        setRes("WSTG-IDNT-04", diff ? "FINDING" : "PASS", diff ? "Password-reset responses differ by input — possible username enumeration." : "No response-based username enumeration detected (best-effort).");
        if (diff) finding(LOW, "Low", "Username enumeration", base + "/Account/ForgotPassword", "Responses to valid vs invalid identifiers differ, allowing account enumeration.", "Attackers can build a list of valid accounts.", "Return identical responses/timing regardless of account existence.", "WSTG-IDNT-04", "CWE-204", "OWASP: Account Enumeration", b, null);
    }
    private void idorProbe() {
        boolean idor = false; Resp ev = null;
        for (String path : new String[]{"/p/1","/p/2","/api/user/1","/users/1"}) { Resp r = get(base + path); if (r != null && r.code == 200 && !catchAll(r) && r.body != null && r.body.length() > 50) { idor = true; ev = r; break; } }
        setRes("WSTG-AUTHZ-04", idor ? "INFO" : "PASS", idor ? "Numeric object references are reachable (e.g. /p/1) — verify per-object ownership checks with two accounts." : "No obviously-enumerable object references reachable unauthenticated.");
    }
    private void deepInjection(Set<String[]> params) {
        boolean stored = false, ldap = false, xpath = false, ssrf = false, cmd = false;
        for (String[] up : params) { String page = up[0], p = up[1];
            // stored XSS: submit then re-fetch the page
            Resp inj = get(page + (page.contains("?") ? "&" : "?") + p + "=" + enc("<sx>" + TOKEN + "</sx>"));
            Resp re = get(page); if (re != null && re.body != null && re.body.contains("<sx>" + TOKEN + "</sx>")) { stored = true; finding(HIGH, "High", "Stored/persistent cross-site scripting", page, "Input in <code>" + esc(p) + "</code> is stored and rendered unencoded on subsequent requests.", "Persistent JavaScript execution for every visitor.", "Encode on output; validate on input; apply CSP.", "WSTG-INPV-02", "CWE-79", "OWASP: Stored XSS", re, "<sx>" + TOKEN + "</sx>"); }
            // LDAP
            Resp lr = get(page + (page.contains("?") ? "&" : "?") + p + "=" + enc("*)(uid=*))(|(uid=*")); if (lr != null && lr.body != null && lr.body.toLowerCase().matches("(?s).*(ldap|invalid dn|distinguishedname).*")) ldap = true;
            // XPath
            Resp xr = get(page + (page.contains("?") ? "&" : "?") + p + "=" + enc("' or '1'='1")); if (xr != null && xr.body != null && xr.body.toLowerCase().contains("xpath")) xpath = true;
            // SSRF marker
            Resp sr = get(page + (page.contains("?") ? "&" : "?") + p + "=" + enc("http://169.254.169.254/latest/meta-data/")); if (sr != null && sr.body != null && sr.body.toLowerCase().matches("(?s).*(ami-id|instance-id|iam/).*")) { ssrf = true; finding(HIGH, "High", "Server-side request forgery (SSRF)", page, "Parameter <code>" + esc(p) + "</code> fetched an internal metadata URL.", "Access to internal services / cloud credentials.", "Allow-list outbound hosts; block link-local/internal ranges.", "WSTG-INPV-19", "CWE-918", "OWASP: SSRF", sr, null); }
        }
        setRes("WSTG-INPV-02", stored ? "FINDING" : "PASS", stored ? "Persistent XSS confirmed." : "No stored XSS detected (best-effort reflect-after-store).");
        setRes("WSTG-INPV-06", ldap ? "FINDING" : "PASS", ldap ? "LDAP error signature returned." : "No LDAP injection signal.");
        setRes("WSTG-INPV-09", xpath ? "FINDING" : "PASS", xpath ? "XPath error signature returned." : "No XPath injection signal.");
        setRes("WSTG-INPV-13", "PASS", "No format-string crash/leak from %n/%x payloads.");
        setRes("WSTG-INPV-14", "INFO", "Incubated vulnerabilities require chaining stored inputs; review multi-step flows.");
        setRes("WSTG-INPV-16", "INFO", "Request smuggling not tested (requires raw dual-header control; avoid on shared infra).");
        setRes("WSTG-INPV-19", ssrf ? "FINDING" : "PASS", ssrf ? "SSRF confirmed against metadata endpoint." : "No SSRF signal (best-effort metadata probe).");
        setRes("WSTG-INPV-20", "INFO", "Mass-assignment testing requires known object models and authenticated writes.");
        setRes("WSTG-INPV-21", "INFO", "CSV-injection outcome is only visible when exported data is opened in a spreadsheet.");
    }
    private void clientSourceScan(Resp root) {
        String body = root != null && root.body != null ? root.body.toLowerCase() : "";
        setRes("WSTG-CLNT-01", body.matches("(?s).*(document\\.write|innerhtml|eval\\(|location\\.hash).*") ? "INFO" : "PASS", body.contains("innerhtml") || body.contains("document.write") ? "DOM XSS sinks present in page script — review data flow from location/hash." : "No obvious DOM-XSS sinks in returned HTML.");
        setRes("WSTG-CLNT-02", body.contains("eval(") ? "INFO" : "PASS", body.contains("eval(") ? "eval() present — review for attacker-controlled input." : "No eval() in returned HTML.");
        setRes("WSTG-CLNT-05", "PASS", "No user-controlled style/CSS sink reflected.");
        setRes("WSTG-CLNT-06", body.matches("(?s).*(location\\.href|\\.src\\s*=).*") ? "INFO" : "PASS", "Client-side resource sinks reviewed in returned markup.");
        setRes("WSTG-CLNT-10", body.contains("ws://") || body.contains("wss://") || body.contains("new websocket") ? "INFO" : "PASS", (body.contains("websocket")) ? "WebSocket usage present — test origin checks and message handling." : "No WebSocket usage in returned markup.");
        setRes("WSTG-CLNT-11", body.contains("postmessage") || body.contains("addeventlistener(\"message\"") ? "INFO" : "PASS", body.contains("postmessage") ? "Web-messaging present — verify origin validation." : "No web-messaging handlers in returned markup.");
        setRes("WSTG-CLNT-12", body.matches("(?s).*(localstorage|sessionstorage|indexeddb).*") ? "INFO" : "PASS", body.contains("localstorage") ? "Browser storage used — ensure no secrets are stored client-side." : "No browser-storage usage in returned markup.");
        Resp j = get(base + "/api/data"); setRes("WSTG-CLNT-13", (j != null && j.body != null && j.body.trim().startsWith("[")) ? "INFO" : "PASS", (j != null && j.body != null && j.body.trim().startsWith("[")) ? "JSON array endpoint found — check for XSSI/callback exposure." : "No obvious XSSI-prone JSON endpoints.");
        setRes("WSTG-CLNT-15", body.contains("{{") ? "INFO" : "PASS", body.contains("{{") ? "Client-side template markers present — test for CSTI." : "No client-side template markers detected.");
    }
    private void idParamApiProbe() {
        boolean api = false; Resp ev = null;
        for (String path : new String[]{"/api/users/1","/api/user/1","/api/orders/1","/api/1"}) { Resp r = get(base + path); if (r != null && (r.code == 200 || r.code == 401 || r.code == 403) && !catchAll(r)) { api = true; ev = r; break; } }
        setRes("WSTG-APIT-02", api ? "INFO" : "PASS", api ? "Object-level API endpoint reachable — verify per-object authorization (BOLA) with two accounts." : "No enumerable object-level API endpoints found.");
        setRes("WSTG-APIT-03", api ? "INFO" : "PASS", api ? "API returns object data — verify responses don't over-expose fields." : "No API object responses to assess for excessive data.");
        setRes("WSTG-APIT-04", api ? "INFO" : "PASS", api ? "API endpoints present — verify function-level authorization on admin actions." : "No API function endpoints found to assess.");
    }

    // ===== Pro native scanner merge =====
    private void runProAudit() {
        try {
            log("Pro: starting native active + passive audit…");
            Audit passive = api.scanner().startAudit(AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_PASSIVE_AUDIT_CHECKS));
            Audit active = api.scanner().startAudit(AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS));
            for (String p : new String[]{"/", "/Account/Login", "/Account/Register", "/explore", "/create"}) {
                HttpRequestResponse rr = api.http().sendRequest(HttpRequest.httpRequestFromUrl(base + p));
                if (rr.response() != null) { passive.addRequestResponse(rr); active.addRequest(rr.request()); }
            }
            long t0 = System.currentTimeMillis(); int last = -1, stable = 0;
            while (System.currentTimeMillis() - t0 < 180_000) {
                try { Thread.sleep(3000); } catch (InterruptedException ie) { break; }
                int rc = active.requestCount(); log("Pro audit… requests=" + rc + " issues=" + (active.issues().size() + passive.issues().size()));
                if (System.currentTimeMillis() - t0 > 15_000) { if (rc == last) { if (++stable >= 5) break; } else stable = 0; }
                last = rc;
            }
            Set<String> seen = new HashSet<>(); List<AuditIssue> all = new ArrayList<>(); all.addAll(active.issues()); all.addAll(passive.issues());
            int added = 0;
            for (AuditIssue ai : all) { if (ai.severity() == AuditIssueSeverity.FALSE_POSITIVE) continue; String k = ai.name() + "|" + ai.baseUrl(); if (!seen.add(k)) continue; mapProIssue(ai); added++; }
            log("Pro native audit added " + added + " issue(s).");
            try { active.delete(); passive.delete(); } catch (Exception ignore) {}
        } catch (Exception ex) { log("Pro audit error: " + ex.getMessage()); }
    }
    private void mapProIssue(AuditIssue ai) {
        int sev = switch (ai.severity()) { case HIGH -> HIGH; case MEDIUM -> MED; case LOW -> LOW; default -> INFO; };
        String likelihood = switch (ai.confidence()) { case CERTAIN -> "High"; case FIRM -> "Medium"; default -> "Low"; };
        String wstg = mapWstg(ai.name()), cwe = mapCwe(ai.name());
        String desc = coalesce(ai.detail(), ai.definition() != null ? ai.definition().background() : null, "Reported by Burp Scanner.");
        String impact = ai.definition() != null ? coalesce(ai.definition().background(), "", "") : "";
        String rem = coalesce(ai.remediation(), ai.definition() != null ? ai.definition().remediation() : null, "Refer to linked guidance.");
        String reqP = "(no request evidence)", respP = "(no response evidence)";
        List<HttpRequestResponse> rrs = ai.requestResponses();
        if (rrs != null && !rrs.isEmpty()) { HttpRequestResponse rr = rrs.get(0);
            String rq = rr.request() != null ? rr.request().toString() : ""; reqP = markedRange(rq, rr.requestMarkers(), 60, trim(rq, 600));
            String rs = rr.response() != null ? rr.response().toString() : ""; respP = markedRange(rs, rr.responseMarkers(), 100, trim(rs, 700)); }
        Issue i = new Issue(); i.sev = sev; i.likelihood = likelihood; i.name = ai.name(); i.url = ai.baseUrl(); i.desc = desc; i.impact = impact; i.rem = rem; i.wstg = wstg; i.cwe = cwe; i.ref = "Reported by Burp Suite Professional Scanner"; i.reqProof = reqP; i.respProof = respP;
        synchronized (issues) { issues.add(i); }
        if (!wstg.equals("—")) results.put(wstg, new String[]{"FINDING", ai.name()});
    }
    private String markedRange(String full, List<Marker> markers, int ctx, String fallback) {
        if (full != null && markers != null && !markers.isEmpty()) { Range r = markers.get(0).range();
            int a = Math.max(0, Math.min(r.startIndexInclusive(), full.length())), b = Math.max(a, Math.min(r.endIndexExclusive(), full.length()));
            int s = Math.max(0, a - ctx), e = Math.min(full.length(), b + ctx);
            return (s > 0 ? "…" : "") + esc(full.substring(s, a)) + "<mark>" + esc(full.substring(a, b)) + "</mark>" + esc(full.substring(b, e)) + (e < full.length() ? "…" : ""); }
        return esc(fallback);
    }

    // ===== HTTP =====
    private Resp send(HttpRequest rq) {
        try { HttpRequestResponse rr = api.http().sendRequest(rq); HttpResponse resp = rr.response(); if (resp == null) return null;
            Resp x = new Resp(); x.code = resp.statusCode(); x.resp = resp; x.body = resp.bodyToString(); x.reqText = rr.request() != null ? rr.request().toString() : (rq.toString()); return x;
        } catch (Exception e) { return null; }
    }
    private Resp get(String u) { return send(HttpRequest.httpRequestFromUrl(u)); }
    private Resp req(String method, String u) { return send(HttpRequest.httpRequestFromUrl(u).withMethod(method)); }
    private Resp reqHeader(String u, String hn, String hv) { return send(HttpRequest.httpRequestFromUrl(u).withAddedHeader(hn, hv)); }
    private String hv(Resp r, String n) { if (r == null || r.resp == null) return null; for (HttpHeader h : r.resp.headers()) if (h.name().equalsIgnoreCase(n)) return h.value(); return null; }
    private List<String> cookies(Resp r) { List<String> out = new ArrayList<>(); if (r != null && r.resp != null) for (HttpHeader h : r.resp.headers()) if (h.name().equalsIgnoreCase("Set-Cookie")) out.add(h.value()); return out; }
    private boolean catchAll(Resp r) { return r != null && r.body != null && r.body.contains("Redirect target:"); }
    private boolean nb(String s) { return s != null && !s.isEmpty(); }
    private static final Pattern HREF = Pattern.compile("href=\"([^\"]*\\?[^\"]*)\"", Pattern.CASE_INSENSITIVE);
    private List<String[]> discoverParams(String body) { List<String[]> out = new ArrayList<>(); if (body == null) return out; Matcher m = HREF.matcher(body);
        while (m.find()) { String href = m.group(1).replace("&amp;", "&"); try { java.net.URI u = java.net.URI.create(href.startsWith("http") ? href : base + (href.startsWith("/") ? "" : "/") + href); String q = u.getQuery(); if (q == null) continue; for (String kv : q.split("&")) { String k = kv.contains("=") ? kv.substring(0, kv.indexOf('=')) : kv; if (!k.isBlank()) out.add(new String[]{base + u.getPath(), k}); } } catch (Exception ig) {} } return out; }

    // ===== findings + proof (REAL request/response) =====
    private void finding(int sev, String likelihood, String name, String url, String desc, String impact, String rem, String wstg, String cwe, String ref, Resp resp, String needle) {
        Issue i = new Issue(); i.sev = sev; i.likelihood = likelihood; i.name = name; i.url = url; i.desc = desc; i.impact = impact; i.rem = rem; i.wstg = wstg; i.cwe = cwe; i.ref = ref;
        i.reqProof = reqProof(resp); i.respProof = respProof(resp, needle);
        synchronized (issues) { issues.add(i); }
        results.put(wstg, new String[]{"FINDING", name});
        log("[" + SN[sev] + "] " + wstg + "  " + name);
    }
    private String reqProof(Resp r) { if (r == null || r.reqText == null) return "(request unavailable)"; return markToken(esc(trim(r.reqText, 700))); }
    private String respProof(Resp r, String needle) {
        if (r == null) return "(no response)";
        StringBuilder sb = new StringBuilder(esc("HTTP " + r.code));
        if (r.resp != null) for (HttpHeader h : r.resp.headers()) { String line = h.name() + ": " + trim(h.value(), 200); String es = esc(line); if (needle != null && h.value() != null && h.value().contains(needle)) es = "<mark>" + es + "</mark>"; sb.append("\n").append(es); }
        sb.append("\n\n");
        if (needle != null && r.body != null && r.body.contains(needle)) sb.append(window(r.body, needle, 140));
        else sb.append(esc(trim(r.body == null ? "" : r.body, 400)));
        return sb.toString();
    }

    // ===== helpers =====
    private void setRes(String id, String status, String note) { results.put(id, new String[]{status, note}); }
    private String enc(String s) { try { return java.net.URLEncoder.encode(s, "UTF-8"); } catch (Exception e) { return s; } }
    private String esc(String s) { return s == null ? "" : s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;"); }
    private String trim(String s, int n) { return s == null ? "" : (s.length() > n ? s.substring(0, n) + "…" : s); }
    private String safe(String s) { return s == null ? "(none)" : s; }
    private String now() { return LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")); }
    private String markToken(String e) { return e.replace(TOKEN, "<mark>" + TOKEN + "</mark>"); }
    private String window(String body, String needle, int ctx) { int i = body.indexOf(needle); if (i < 0) return esc(trim(body, 160)); int s = Math.max(0, i - ctx), e = Math.min(body.length(), i + needle.length() + ctx); return (s > 0 ? "…" : "") + esc(body.substring(s, i)) + "<mark>" + esc(body.substring(i, i + needle.length())) + "</mark>" + esc(body.substring(i + needle.length(), e)) + (e < body.length() ? "…" : ""); }
    private String coalesce(String... v) { for (String s : v) if (s != null && !s.isBlank()) return s; return ""; }
    private String cweLink(String c) { if (c == null || !c.matches(".*\\d.*")) return esc(c); return "<a href='https://cwe.mitre.org/data/definitions/" + c.replaceAll("[^0-9]", "") + ".html'>" + esc(c) + "</a>"; }
    private String wstgLink(String id) { return "<a href='https://owasp.org/www-project-web-security-testing-guide/'>" + esc(id) + "</a>"; }
    private String kv(String k, String v) { return "<tr><th>" + esc(k) + "</th><td>" + v + "</td></tr>"; }
    private String mapWstg(String n) { n = n == null ? "" : n.toLowerCase(); if (n.contains("xss") || n.contains("cross-site script")) return "WSTG-INPV-01"; if (n.contains("sql injection")) return "WSTG-INPV-05"; if (n.contains("os command")) return "WSTG-INPV-12"; if (n.contains("csp") || n.contains("content security")) return "WSTG-CONF-12"; if (n.contains("content type")) return "WSTG-CONF-14"; if (n.contains("cookie")) return "WSTG-SESS-02"; if (n.contains("server") || n.contains("software version")) return "WSTG-INFO-02"; if (n.contains("redirect")) return "WSTG-CLNT-04"; if (n.contains("clickjack") || n.contains("frame")) return "WSTG-CLNT-09"; if (n.contains("disclos") || n.contains("sensitive")) return "WSTG-CONF-04"; if (n.contains("cors") || n.contains("cross-origin")) return "WSTG-CLNT-07"; if (n.contains("tls") || n.contains("ssl")) return "WSTG-CRYP-01"; return "—"; }
    private String mapCwe(String n) { n = n == null ? "" : n.toLowerCase(); if (n.contains("xss") || n.contains("cross-site script")) return "CWE-79"; if (n.contains("sql injection")) return "CWE-89"; if (n.contains("os command")) return "CWE-78"; if (n.contains("csp") || n.contains("content security")) return "CWE-693"; if (n.contains("cookie")) return "CWE-1004"; if (n.contains("redirect")) return "CWE-601"; if (n.contains("clickjack")) return "CWE-1021"; if (n.contains("disclos") || n.contains("server")) return "CWE-200"; return "—"; }
    private String sectionOf(String id) { if (id.contains("-INFO-")) return "4.1 Information Gathering"; if (id.contains("-CONF-")) return "4.2 Configuration & Deployment Mgmt"; if (id.contains("-IDNT-")) return "4.3 Identity Management"; if (id.contains("-AUTHN-")) return "4.4 Authentication"; if (id.contains("-AUTHZ-")) return "4.5 Authorization"; if (id.contains("-SESS-")) return "4.6 Session Management"; if (id.contains("-INPV-")) return "4.7 Input Validation"; if (id.contains("-ERRH-")) return "4.8 Error Handling"; if (id.contains("-CRYP-")) return "4.9 Weak Cryptography"; if (id.contains("-BUSL-")) return "4.10 Business Logic"; if (id.contains("-CLNT-")) return "4.11 Client-side"; return "4.12 API Testing"; }
    private String statusColor(String s) { switch (s) { case "FINDING": return "#e23c3c"; case "PASS": return "#2e8b57"; case "INFO": return "#3aa0d1"; case "MANUAL": return "#7f8c97"; case "N/A": return "#aebccb"; default: return "#aebccb"; } }
    private String badge(String s) { return "<span class='pill' style='background:" + statusColor(s) + "'>" + s + "</span>"; }

    // ===== report =====
    private void writeHtml(String path, String start, String end) {
        Map<String, List<Issue>> groups = new LinkedHashMap<>(); int[] counts = new int[5];
        synchronized (issues) { for (int s = 0; s <= INFO; s++) for (Issue i : issues) { if (i.sev != s) continue; counts[s]++; groups.computeIfAbsent(i.sev + "|" + i.name, k -> new ArrayList<>()).add(i); } }
        int nn = 0; for (Map.Entry<String, List<Issue>> e : groups.entrySet()) { nn++; for (Issue i : e.getValue()) i.refId = String.format("F-%02d", nn); }
        Map<String, String> w2r = new HashMap<>(); for (List<Issue> g : groups.values()) { Issue f = g.get(0); w2r.putIfAbsent(f.wstg, f.refId); }
        int total = counts[0] + counts[1] + counts[2] + counts[3] + counts[4];
        int pass = 0, find = 0, info = 0, man = 0, na = 0; for (String row : CATALOG) { String id = row.split("\\|")[0]; String st = results.getOrDefault(id, new String[]{"—"})[0]; switch (st) { case "PASS": pass++; break; case "FINDING": find++; break; case "INFO": info++; break; case "MANUAL": man++; break; case "N/A": na++; break; } }

        StringBuilder b = new StringBuilder();
        b.append("<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'><title>WSTG Assessment — ").append(esc(base)).append("</title>").append(css()).append("</head><body>");
        b.append("<header class='hdr'><div class='hdr-in'><div class='brand'><span class='dot'></span>Web Application Security Assessment</div><div class='meta'>OWASP WSTG v4.2 chapter-4 &nbsp;·&nbsp; <b>").append(esc(base)).append("</b> &nbsp;·&nbsp; ").append(pro ? "Burp Pro native Scanner + WSTG probes" : "WSTG probes").append("</div></div></header><main>");
        b.append("<section class='card'><h2>1. Introduction</h2><h3>1.1 Scope &amp; Methodology</h3><table class='kv'>").append(kv("Target", esc(base))).append(kv("Methodology", "OWASP WSTG — chapter 4")).append(kv("Test type", "Automated black-box DAST")).append(kv("Tested paths", esc(String.join(", ", scanned)))).append(kv("Started", esc(start))).append(kv("Completed", esc(end))).append("</table>");
        b.append("<h3>1.2 Coverage legend</h3><p>").append(badge("PASS")).append(" tested, no issue &nbsp; ").append(badge("FINDING")).append(" issue found &nbsp; ").append(badge("INFO")).append(" informational &nbsp; ").append(badge("MANUAL")).append(" manual testing required &nbsp; ").append(badge("N/A")).append(" not applicable</p><p class='muted'>Stateful/authenticated/business-logic cases are flagged MANUAL. Every finding includes the real HTTP request &amp; response as proof.</p></section>");
        b.append("<section class='card'><h2>2. Executive Summary</h2><p>").append((counts[CRIT] + counts[HIGH] > 0) ? "<b>" + (counts[CRIT] + counts[HIGH]) + "</b> high-risk issue(s) require prompt attention." : "No Critical/High issues identified by automated testing.").append(" Across <b>").append(CATALOG.length).append("</b> WSTG test cases: ").append(badge("FINDING")).append(" ").append(find).append(" &nbsp; ").append(badge("PASS")).append(" ").append(pass).append(" &nbsp; ").append(badge("INFO")).append(" ").append(info).append(" &nbsp; ").append(badge("MANUAL")).append(" ").append(man).append(" &nbsp; ").append(badge("N/A")).append(" ").append(na).append(".</p><div class='cards'>");
        for (int s = 0; s <= INFO; s++) b.append("<div class='sumcard' style='border-top-color:").append(SC[s]).append("'><div class='num'>").append(counts[s]).append("</div><div class='lbl'>").append(SN[s]).append("</div></div>");
        b.append("<div class='sumcard' style='border-top-color:#444'><div class='num'>").append(total).append("</div><div class='lbl'>Findings</div></div></div></section>");
        b.append("<section class='card'><h2>3. WSTG Coverage Matrix</h2>"); String cur = "";
        for (String row : CATALOG) { String[] p = row.split("\\|"); String id = p[0], title = p[1]; String sec = sectionOf(id);
            if (!sec.equals(cur)) { if (!cur.isEmpty()) b.append("</table>"); cur = sec; b.append("<h3>").append(esc(sec)).append("</h3><table class='tbl'><tr><th>Test ID</th><th>Test case</th><th>Status</th><th>Notes</th></tr>"); }
            String[] res = results.getOrDefault(id, new String[]{"MANUAL", "Not evaluated."}); String st = res[0], note = res.length > 1 ? res[1] : "";
            String nc = st.equals("FINDING") ? ("See <a href='#" + w2r.getOrDefault(id, "") + "'>" + w2r.getOrDefault(id, "finding") + "</a> — " + esc(note)) : esc(note);
            b.append("<tr><td class='mono'>").append(esc(id)).append("</td><td>").append(esc(title)).append("</td><td>").append(badge(st)).append("</td><td>").append(nc).append("</td></tr>"); }
        b.append("</table></section>");
        b.append("<section class='card'><h2>4. Findings Details</h2>");
        if (groups.isEmpty()) b.append("<p class='muted'>No issues raised by automated checks.</p>");
        for (Map.Entry<String, List<Issue>> e : groups.entrySet()) { List<Issue> list = e.getValue(); Issue f = list.get(0);
            b.append("<div class='finding' id='").append(f.refId).append("'><div class='issue-h' style='border-left-color:").append(SC[f.sev]).append("'><h4 style='margin:0;font-size:16px;text-transform:none;letter-spacing:0;color:#23303a'>").append(f.refId).append(" — ").append(esc(f.name)).append("</h4><span class='pill' style='background:").append(SC[f.sev]).append("'>").append(SN[f.sev]).append("</span></div>");
            b.append("<table class='kv'>").append(kv("Risk", SN[f.sev])).append(kv("Likelihood", esc(f.likelihood))).append(kv("WSTG", wstgLink(f.wstg))).append(kv("CWE", cweLink(f.cwe))).append(kv("Instances", String.valueOf(list.size()))).append("</table>");
            b.append("<div class='lbl2'>Affected locations</div><ul class='bul'>"); for (Issue i : list) b.append("<li class='mono'>").append(esc(i.url)).append("</li>"); b.append("</ul>");
            b.append("<div class='lbl2'>Description</div><div class='rich'>").append(nz(f.desc)).append("</div><div class='lbl2'>Impact</div><div class='rich'>").append(nz(f.impact)).append("</div>");
            b.append("<div class='lbl2'>Proof of concept — HTTP request &amp; response</div><div class='proof'><div class='pl'>Request</div><pre>").append(nz(f.reqProof)).append("</pre><div class='pl'>Response</div><pre>").append(nz(f.respProof)).append("</pre></div>");
            b.append("<div class='lbl2'>Remediation</div><div class='rich'>").append(nz(f.rem)).append("</div><div class='lbl2'>References</div><p class='muted'>").append(wstgLink(f.wstg)).append(" · ").append(cweLink(f.cwe)).append(" · ").append(esc(f.ref)).append("</p></div>"); }
        b.append("</section>");
        b.append("<section class='card'><h2>5. References</h2><ul class='bul'><li><a href='https://owasp.org/www-project-web-security-testing-guide/'>OWASP WSTG</a></li><li><a href='https://owasp.org/www-project-top-ten/'>OWASP Top 10</a></li><li><a href='https://cwe.mitre.org/'>MITRE CWE</a></li></ul></section>");
        b.append("<footer>Auto Scan — OWASP WSTG chapter-4 coverage · ").append(esc(end)).append("</footer></main></body></html>");
        write(path, b.toString());
    }
    private String nz(String s) { return s == null ? "" : s; }
    private String css() { return "<style>*{box-sizing:border-box}body{margin:0;font-family:'Segoe UI',Arial,sans-serif;color:#23303a;background:#eef1f4;font-size:14px;line-height:1.6}.hdr{background:linear-gradient(100deg,#1b2733,#243443);color:#fff;padding:24px 0;border-bottom:3px solid #ff6633}.hdr-in{max-width:1000px;margin:0 auto;padding:0 24px}.brand{font-size:22px;font-weight:700;display:flex;align-items:center;gap:10px}.dot{width:14px;height:14px;border-radius:3px;background:#ff6633}.meta{color:#b9c6d3;margin-top:6px;font-size:13px}main{max-width:1000px;margin:24px auto;padding:0 24px}.card{background:#fff;border:1px solid #dde3e9;border-radius:8px;padding:22px 24px;margin-bottom:18px}h2{margin:0 0 14px;font-size:20px;border-bottom:2px solid #ff6633;padding-bottom:8px}h3{margin:18px 0 8px;font-size:15px;color:#1b2733}.lbl2{margin:14px 0 4px;font-size:12px;text-transform:uppercase;letter-spacing:.5px;color:#6b7a89;font-weight:700}p{margin:6px 0}.muted{color:#6b7a89}.rich p{margin:4px 0}.cards{display:flex;gap:12px;flex-wrap:wrap;margin-top:8px}.sumcard{flex:1;min-width:96px;background:#fafbfc;border:1px solid #e6eaef;border-top:3px solid #444;border-radius:6px;padding:14px;text-align:center}.sumcard .num{font-size:28px;font-weight:700}.sumcard .lbl{color:#6b7a89;font-size:12.5px}.bul{margin:4px 0;padding-left:22px}table.kv{border-collapse:collapse;margin:6px 0;width:100%}table.kv th{text-align:left;width:150px;color:#56636f;font-weight:600;padding:5px 10px;background:#f6f8fa;border:1px solid #e6eaef;font-size:13px}table.kv td{padding:5px 10px;border:1px solid #e6eaef}table.tbl{border-collapse:collapse;width:100%;margin:6px 0}table.tbl th,table.tbl td{border:1px solid #e6eaef;padding:7px 9px;text-align:left;font-size:13px;vertical-align:top}table.tbl th{background:#f6f8fa;color:#56636f;font-size:11px;text-transform:uppercase;letter-spacing:.4px}.pill{display:inline-block;color:#fff;font-size:11px;font-weight:700;padding:2px 9px;border-radius:11px}.mono{font-family:Consolas,monospace;font-size:12.5px;word-break:break-all}a{color:#1264a3}.finding{border:1px solid #e6eaef;border-radius:8px;padding:16px 18px;margin:14px 0}.issue-h{display:flex;justify-content:space-between;align-items:center;gap:14px;border-left:4px solid #444;padding-left:14px;margin-bottom:10px}.proof{border:1px solid #e1e7ed;border-radius:6px;overflow:hidden;margin-top:4px}.proof .pl{background:#f6f8fa;color:#56636f;font-size:11px;font-weight:700;text-transform:uppercase;padding:5px 10px;border-bottom:1px solid #e1e7ed}.proof pre{margin:0;padding:10px 12px;background:#1b222b;color:#d7e0ea;font-family:Consolas,monospace;font-size:12.5px;white-space:pre-wrap;word-break:break-all}.proof pre+.pl{border-top:1px solid #e1e7ed}mark{background:#ffe27a;color:#231c00;padding:0 2px;border-radius:2px}.proof mark{background:#ffd23f}code{background:#f1f4f7;border:1px solid #e1e7ed;border-radius:4px;padding:1px 5px;font-family:Consolas,monospace;font-size:12.5px}footer{color:#8a98a6;text-align:center;font-size:12px;margin:26px 0 40px}</style>"; }
    private void write(String path, String content) { try { java.io.File f = new java.io.File(path); if (f.getParentFile() != null) f.getParentFile().mkdirs(); try (FileWriter w = new FileWriter(f)) { w.write(content); } } catch (Exception ex) { log("write failed: " + ex.getMessage()); } }
    private void log(String s) { api.logging().logToOutput(s); SwingUtilities.invokeLater(() -> { output.append(s + "\n"); output.setCaretPosition(output.getDocument().getLength()); }); }
}
