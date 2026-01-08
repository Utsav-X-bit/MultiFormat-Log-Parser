#include <iostream>
#include <fstream>
#include <regex>
#include <string>
#include <vector>

using namespace std;

struct LogEntry {
    string ip;
    string method;
    string port;
    string user;
    string user_id;
    string timestamp;
};

string matchRegex(const string& line, const regex& pattern, int group = 1) {
    smatch match;
    if (regex_search(line, match, pattern)) {
        return match[group];
    }
    return "";
}

LogEntry parseLogLine(const string& line) {
    LogEntry entry;

    regex ipPattern(R"(\b(?:\d{1,3}\.){3}\d{1,3}\b)");
    regex methodPattern(R"(\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b)");
    regex portPattern(R"((?:port=|:)(\d{2,5})\b|\b\d{3}\b\s+(\d{3})\b)");
    regex userPattern(R"(\buser=([a-zA-Z0-9_\-]+)\b)");
    regex userIdPattern(R"(\b(?:uid|user_id)=([0-9]+)\b)");
    regex timestampPattern(R"(\[\d{1,2}/[A-Za-z]{3}/\d{4}:[^\]]+\]|\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}?)");

    entry.ip        = matchRegex(line, ipPattern,0);
    entry.method    = matchRegex(line, methodPattern);
    entry.port      = matchRegex(line, portPattern,0);
    entry.user      = matchRegex(line, userPattern);
    entry.user_id   = matchRegex(line, userIdPattern);
    entry.timestamp = matchRegex(line, timestampPattern, 0);

    return entry;
}

int main(int argc, char *argv[]) {
        if (argc != 3) {
            cout << "Usage: " << argv[0] << " input.log output.csv\n";
            return 1;
        }
    ifstream infile(argv[1]);
    ofstream outfile(argv[2]);

    if (!infile.is_open()) {
        cout << "Failed to open logs.txt\n";
        return 1;
    }

    outfile << "ip,method,port,user,user_id,timestamp\n";

    string line;
    while (getline(infile, line)) {
        LogEntry entry = parseLogLine(line);

        outfile << entry.ip << "," << entry.method << "," << entry.port << "," << entry.user << "," << entry.user_id << "," << entry.timestamp << "\n";
    }

    infile.close();
    outfile.close();

    cout << "Logs parsed \n";
    return 0;
}
