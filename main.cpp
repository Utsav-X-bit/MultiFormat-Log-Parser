#include <bits/stdc++.h>
using namespace std;

struct NormalizedLog {
    string raw_line;
    string log_family;

    // Common
    string timestamp;
    string level;

    // Syslog
    string host;
    string process;
    string module;
    int pid = -1;

    // Web
    string source_ip;
    string http_method;
    string url;
    string http_version;
    int status_code = -1;
    int response_size = -1;
    string referer;
    string user_agent;

    // Application
    string logger;
    unordered_map<string, string> metadata;



    string message;
};


static bool is_ip(const string &s) {
    static regex ip_regex(
        R"((\b\d{1,3}(\.\d{1,3}){3}\b)|(\b[a-fA-F0-9:]+\b))");
    return regex_match(s, ip_regex);
}

static vector<string> extract_quoted(const string &s) {
    vector<string> out;
    bool in = false;
    string cur;
    for (char c : s) {
        if (c == '"') {
            if (in) out.push_back(cur), cur.clear();
            in = !in;
        } else if (in) cur.push_back(c);
    }
    return out;
}

/* -------------------- Format Detection -------------------- */

enum class LogType { SYSLOG, WEB, APPLICATION, UNKNOWN };

static LogType detect_format(const string &line) {
    if (line.size() >= 3 && isdigit(line[0]) && line.find('[') != string::npos)
        return LogType::WEB;

    if (line.rfind("INFO ", 0) == 0 ||
        line.rfind("ERROR ", 0) == 0 ||
        line.rfind("WARN ", 0) == 0 ||
        line.rfind("DEBUG ", 0) == 0)
        return LogType::APPLICATION;

    static vector<string> months = {
        "Jan","Feb","Mar","Apr","May","Jun",
        "Jul","Aug","Sep","Oct","Nov","Dec"
    };
    for (auto &m : months)
        if (line.rfind(m + " ", 0) == 0)
            return LogType::SYSLOG;

    return LogType::UNKNOWN;
}

/* -------------------- Syslog Parser -------------------- */

static void parse_syslog(const string &line, NormalizedLog &log) {
    log.log_family = "syslog";
    log.raw_line = line;

    stringstream ss(line);
    string m, d, t;
    ss >> m >> d >> t;
    log.timestamp = m + " " + d + " " + t;

    ss >> log.host;

    string rest;
    getline(ss, rest);
    auto colon = rest.find(':');
    if (colon == string::npos) return;

    string proc = rest.substr(0, colon);
    log.message = rest.substr(colon + 1);
    while (!log.message.empty() && log.message[0] == ' ')
        log.message.erase(log.message.begin());

    auto lb = proc.find('[');
    auto rb = proc.find(']');
    auto lp = proc.find('(');
    auto rp = proc.find(')');

    if (lp != string::npos && rp != string::npos) {
        log.process = proc.substr(1, lp - 1);
        log.module = proc.substr(lp + 1, rp - lp - 1);
    } else {
        log.process = proc.substr(1);
    }

    if (lb != string::npos && rb != string::npos) {
        log.pid = stoi(proc.substr(lb + 1, rb - lb - 1));
    }
}

/* -------------------- Web Log Parser -------------------- */

static void parse_web(const string &line, NormalizedLog &log) {
    log.log_family = "web_access";
    log.raw_line = line;

    auto lb = line.find('[');
    auto rb = line.find(']');
    if (lb != string::npos && rb != string::npos)
        log.timestamp = line.substr(lb + 1, rb - lb - 1);

    auto quoted = extract_quoted(line);
    if (!quoted.empty()) {
        stringstream rs(quoted[0]);
        rs >> log.http_method >> log.url >> log.http_version;
    }
    if (quoted.size() >= 2) log.referer = quoted[1];
    if (quoted.size() >= 3) log.user_agent = quoted[2];

    string tmp = line;
    for (auto &q : quoted) {
        auto pos = tmp.find("\"" + q + "\"");
        if (pos != string::npos)
            tmp.erase(pos, q.size() + 2);
    }

    stringstream ss(tmp);
    vector<string> tokens;
        string tok;
        while (ss >> tok)
            tokens.push_back(tok);

        // Prefer first valid IP only
        for (const auto &t : tokens) {
            if (is_ip(t)) {
                log.source_ip = t;
                break;
            }
        }

    
}

/* -------------------- Application Log Parser -------------------- */

static void parse_application(const string &line, NormalizedLog &log) {
    log.log_family = "application";
    log.raw_line = line;

    stringstream ss(line);
    ss >> log.level >> log.logger;

    string rest;
    getline(ss, rest);

    size_t pos = 0;
    while ((pos = rest.find('[')) != string::npos) {
        auto end = rest.find(']', pos);
        if (end == string::npos) break;

        string inside = rest.substr(pos + 1, end - pos - 1);
        rest.erase(pos, end - pos + 1);

        auto sep = inside.find(':');
        if (sep != string::npos) {
            string k = inside.substr(0, sep);
            string v = inside.substr(sep + 1);
            while (!v.empty() && v[0] == ' ') v.erase(v.begin());
            log.metadata[k] = v;
        }
    }

    log.message = rest;
    while (!log.message.empty() && log.message[0] == ' ')
        log.message.erase(log.message.begin());
}

/* -------------------- CSV Writer -------------------- */

static string esc(const string &s) {
    string o = s;
    replace(o.begin(), o.end(), '"', '\'');
    return "\"" + o + "\"";
}

/* -------------------- Main -------------------- */

int main(int argc, char *argv[]) {
    if (argc != 3) {
        cerr << "Usage: " << argv[0] << " input.log output.csv\n";
        return 1;
    }

    ifstream in(argv[1]);
    ofstream out(argv[2]);

    out << "family,timestamp,level,host,process,module,pid,source_ip,"
           "method,url,version,status,size,referer,user_agent,logger,message\n";

    string line;
    while (getline(in, line)) {
        NormalizedLog log;
        auto type = detect_format(line);

        if (type == LogType::SYSLOG) parse_syslog(line, log);
        else if (type == LogType::WEB) parse_web(line, log);
        else if (type == LogType::APPLICATION) parse_application(line, log);
        else {
            log.log_family = "unknown";
            log.raw_line = line;
            log.message = line;
        }

        out << log.log_family << ","
            << esc(log.timestamp) << ","
            << esc(log.level) << ","
            << esc(log.host) << ","
            << esc(log.process) << ","
            << esc(log.module) << ","
            << log.pid << ","
            << esc(log.source_ip) << ","
            << esc(log.http_method) << ","
            << esc(log.url) << ","
            << esc(log.http_version) << ","
            << log.status_code << ","
            << log.response_size << ","
            << esc(log.referer) << ","
            << esc(log.user_agent) << ","
            << esc(log.logger) << ","
            << esc(log.message) << "\n";
    }
}
