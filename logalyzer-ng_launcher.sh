#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"

if [[ ! -f "$ENV_FILE" ]]; then
    echo "Missing $ENV_FILE — copy .env.example and fill in your values."
    exit 1
fi

set -a
# shellcheck source=.env
source "$ENV_FILE"
set +a

FILE=/tmp/logalyzer-tmpfile-mail

## CHECK IF ROOT
if [[ "$EUID" -ne 0 ]]; then
    echo "Only root can start this script!"
    exit 1
fi

#######
# -u : Specify user
# --full : Full log dump for specified user
# -l : Specify log file
# -f : List failures
# -s : List success logs
# -c : List commands by user
# -i : List IP Addresses
#######

html_header() {
    cat <<'EOF'
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  body  { background:#1e1e1e; color:#d4d4d4; font-family:'Courier New',monospace;
          padding:24px; max-width:960px; margin:auto; }
  h1    { color:#569cd6; font-size:1.2em; margin-bottom:4px; }
  .meta { color:#888; font-size:0.85em; margin-bottom:30px; }
  h2    { color:#569cd6; border-left:3px solid #569cd6; padding-left:10px;
          margin-top:36px; margin-bottom:8px; font-size:1em; text-transform:uppercase;
          letter-spacing:1px; }
  pre   { background:#252526; border:1px solid #3c3c3c; border-radius:4px;
          padding:14px; white-space:pre-wrap; word-break:break-all;
          line-height:1.6; font-size:0.9em; margin:0; }
  .ok   { color:#4ec9b0; }
  .err  { color:#f44747; }
  .warn { color:#dcdcaa; }
  .info { color:#9cdcfe; }
</style>
</head>
<body>
EOF
    echo "<h1>VPS Activity Report</h1>"
    echo "<p class='meta'>Generated: $(date '+%Y-%m-%d at %Hh%Mm%Ss')</p>"
}

html_footer() {
    echo "</body></html>"
}

html_escape() {
    sed \
        -e 's/&/\&amp;/g' \
        -e 's/</\&lt;/g' \
        -e 's/>/\&gt;/g'
}

html_section() {
    local title="$1"
    local output="$2"
    echo "<h2>${title}</h2>"
    echo "<pre>${output}</pre>"
}

colorize() {
    sed \
        -e 's/\(\[+\].*\)/<span class="ok">\1<\/span>/g' \
        -e 's/\(\[-\].*\)/<span class="err">\1<\/span>/g' \
        -e 's/\(\[!\].*\)/<span class="warn">\1<\/span>/g' \
        -e 's/\(\[\*\].*\)/<span class="info">\1<\/span>/g'
}

{
    html_header

    html_section "Log file info" \
        "$(python3 "$SCRIPT_DIR/logalyzer-ng.py" -v | html_escape | colorize)"

    html_section "Authenticated IPs — $MONITORED_USER" \
        "$(python3 "$SCRIPT_DIR/logalyzer-ng.py" -i -u "$MONITORED_USER" | html_escape | colorize)"

    html_section "Failed IPs — $MONITORED_USER" \
        "$(python3 "$SCRIPT_DIR/logalyzer-ng.py" -f -i -u "$MONITORED_USER" | html_escape | colorize)"

    html_section "Failure logs — $MONITORED_USER" \
        "$(python3 "$SCRIPT_DIR/logalyzer-ng.py" -f -u "$MONITORED_USER" | html_escape | colorize)"

    html_section "Commands for root user" \
        "$(python3 "$SCRIPT_DIR/logalyzer-ng.py" -u root -c | html_escape | colorize)"

    html_section "Attempted users from attackers" \
        "$(python3 "$SCRIPT_DIR/logalyzer-ng.py" | html_escape | colorize)"

    html_footer
} > "$FILE"

## Send Mail:
{
    echo "To: $MAIL"
    echo "Subject: [VPS]: VPS daily activities summary."
    echo "MIME-Version: 1.0"
    echo "Content-Type: text/html; charset=utf-8"
    echo ""
    cat "$FILE"
} | sendmail -t

rm -rf "$FILE"
