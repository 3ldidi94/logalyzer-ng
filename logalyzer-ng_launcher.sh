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

##############
# -u : Specify user
# --full : Full log dump for specified user
# -l : Specify log file
# -f : List failures
# -s : List success logs
# -c : List commands by user
# -i : List IP Addresses
# -b : Brute-force attempts
# --sudo-fail : Failed sudo attempts
# --su-fail : Failed su
# --accounts : Account events
##############

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
    cat <<'LOGOEOF'
<table cellpadding="0" cellspacing="0" style="background:#252526;border:1px solid #3c3c3c;border-radius:6px;padding:18px 22px;margin-bottom:28px;width:100%;">
  <tr>
    <td style="width:52px;vertical-align:middle;font-size:38px;padding-right:18px;">&#128274;</td>
    <td style="vertical-align:middle;">
      <div style="font-family:'Courier New',monospace;font-size:26px;font-weight:bold;color:#569cd6;letter-spacing:2px;">
        LOGALYZER<span style="color:#dcdcaa;font-size:20px;">-ng</span>
      </div>
      <div style="font-family:'Courier New',monospace;font-size:12px;color:#4ec9b0;letter-spacing:1px;margin-top:5px;border-top:1px solid #3c3c3c;padding-top:5px;">
        SSH Auth Log Analyzer
        <br>&mdash;&mdash;&mdash;&mdash;&mdash;&mdash;&mdash;&mdash;&mdash;&mdash;&mdash;&mdash;&mdash;&mdash;&mdash;&mdash;&mdash;&mdash;&mdash;&mdash;&mdash;<br>
        Security Report
      </div>
    </td>
  </tr>
</table>
LOGOEOF
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
        "$(python3 "$SCRIPT_DIR/logalyzer-ng.py" -a | html_escape | colorize)"

    html_section "Brute-force attempts" \
        "$(python3 "$SCRIPT_DIR/logalyzer-ng.py" -b | html_escape | colorize)"

    html_section "Failed sudo attempts (NOT in sudoers)" \
        "$(python3 "$SCRIPT_DIR/logalyzer-ng.py" --sudo-fail | html_escape | colorize)"

    html_section "Failed su attempts" \
        "$(python3 "$SCRIPT_DIR/logalyzer-ng.py" --su-fail | html_escape | colorize)"

    html_section "Account events (create / modify / delete)" \
        "$(python3 "$SCRIPT_DIR/logalyzer-ng.py" --accounts | html_escape | colorize)"

    html_footer
} > "$FILE"

## Send Mail:
{
    echo "From: VPS Monitoring <$MAIL>"
    echo "To: $MAIL"
    echo "Subject: [VPS]: VPS daily activities summary."
    echo "MIME-Version: 1.0"
    echo "Content-Type: text/html; charset=utf-8"
    echo ""
    cat "$FILE"
} | sendmail -t

rm -rf "$FILE"
