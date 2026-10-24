#!/usr/bin/env python3

"""
DVWA / ModSecurity XXE Tester

Authorized lab workflow:
    Kali/test machine -> DVWA/XXE lab on Ubuntu -> ModSecurity + OWASP CRS

Payload file:
    xxe_payloads_5000.txt

One line = one XML payload.

Records:
    - request ID
    - payload ID
    - source line
    - XML payload
    - HTTP status
    - response time
    - ModSecurity rule alert
    - WAF blocked/not blocked
    - triggered CRS rule IDs/messages
    - whether response indicates entity expansion
"""

import csv
import getpass
import random
import re
import shlex
import time
from pathlib import Path

import paramiko
import requests


# ============================================================
# CONFIGURATION
# ============================================================

REMOTE_HOST = "192.168.56.20"
REMOTE_USER = "linux"

REMOTE_LOG = "/var/log/modsec_audit.log"

DVWA_BASE = f"http://{REMOTE_HOST}/DVWA"

LOGIN_URL = f"{DVWA_BASE}/login.php"

# ------------------------------------------------------------
# IMPORTANT
#
# Change this to the endpoint in your lab that accepts XML.
#
# Example:
# http://192.168.56.20/DVWA/vulnerabilities/xxe/
# ------------------------------------------------------------

XXE_URL = f"{DVWA_BASE}/vulnerabilities/xxe/"


# ============================================================
# FILE LOCATIONS
# ============================================================

SCRIPT_DIR = Path(__file__).resolve().parent

PAYLOAD_FILE = (
    SCRIPT_DIR / "xxe_payloads.txt"
)

RESULT_CSV = (
    SCRIPT_DIR / "xxe_results.csv"
)


# ============================================================
# TEST SETTINGS
# ============================================================

# Use 50 first to confirm your endpoint works.
#
# Set to None for the entire payload file.

PILOT_LIMIT = None

# Number of times to run the corpus.

XXE_ROUNDS = 1

SHUFFLE_PAYLOADS = True

RANDOM_SEED = 20260927

DVWA_SECURITY = "low"

HTTP_TIMEOUT = 30

# Allow ModSecurity time to finish writing the audit record.

LOG_WRITE_DELAY = 0.15

# Delay between test cases.

TEST_DELAY = 0.10


# ============================================================
# TERMINAL OUTPUT
# ============================================================

def print_header():

    print("=" * 78)
    print("DVWA XXE / ModSecurity Tester")
    print("=" * 78)
    print()


def print_success(message):

    print(f"[+] {message}")


def print_info(message):

    print(f"[*] {message}")


def print_warning(message):

    print(f"[!] {message}")


def print_error(message):

    print(f"[-] {message}")


# ============================================================
# SSH CONNECTION
# ============================================================

class UbuntuSSH:

    def __init__(
        self,
        host,
        username,
        password,
        sudo_password
    ):

        self.host = host
        self.username = username
        self.password = password
        self.sudo_password = sudo_password

        self.client = None


    def connect(self):

        self.client = paramiko.SSHClient()

        self.client.set_missing_host_key_policy(
            paramiko.AutoAddPolicy()
        )

        self.client.connect(
            hostname=self.host,
            username=self.username,
            password=self.password,
            timeout=10,
            look_for_keys=False,
            allow_agent=False
        )

        print_success(
            "Ubuntu SSH connection successful"
        )


    def sudo(self, command):

        sudo_command = (
            "sudo -S -p '' bash -c "
            + shlex.quote(command)
        )

        stdin, stdout, stderr = (
            self.client.exec_command(
                sudo_command
            )
        )

        stdin.write(
            self.sudo_password + "\n"
        )

        stdin.flush()

        output = stdout.read().decode(
            "utf-8",
            errors="replace"
        )

        error = stderr.read().decode(
            "utf-8",
            errors="replace"
        )

        exit_code = (
            stdout.channel.recv_exit_status()
        )

        return output, error, exit_code


    def close(self):

        if self.client:

            self.client.close()


# ============================================================
# MODSECURITY LOG
# ============================================================

def get_log_size(ssh):

    output, error, code = ssh.sudo(
        f"wc -c {shlex.quote(REMOTE_LOG)}"
    )

    if code != 0:

        raise Exception(
            "Unable to read ModSecurity log size:\n"
            + error
        )

    match = re.search(
        r"(\d+)",
        output
    )

    if not match:

        raise Exception(
            "Could not determine ModSecurity log size:\n"
            + output
        )

    return int(
        match.group(1)
    )


def read_log_since(
    ssh,
    start_size
):

    current_size = get_log_size(ssh)

    if current_size < start_size:

        print_warning(
            "Audit log became smaller; "
            "rotation/truncation detected."
        )

        start_size = 0

    if current_size == start_size:

        return ""

    start_byte = start_size + 1

    output, error, code = ssh.sudo(
        f"tail -c +{start_byte} "
        f"{shlex.quote(REMOTE_LOG)}"
    )

    if code != 0:

        raise Exception(
            "Unable to read new ModSecurity log data:\n"
            + error
        )

    return output


# ============================================================
# AUDIT TRANSACTION CORRELATION
# ============================================================

def correlate_audit_transaction(log_text, request_id):
    """Return only audit transaction(s) containing our unique test header."""
    if not log_text or not request_id:
        return ""

    # Native ModSecurity serial audit entries end with a --<txid>-Z-- marker.
    # Splitting at Z sections keeps unrelated concurrent requests out of the
    # rule parser while remaining tolerant of extra text/newlines.
    chunks = re.split(r'(?m)(?=--[0-9A-Za-z]+-A--)', log_text)
    matches = [chunk for chunk in chunks if request_id in chunk]

    if matches:
        return "\n".join(matches)

    return ""


def modsecurity_intervened(log_text):
    """Best-effort confirmation of a disruptive ModSecurity action."""
    if not log_text:
        return False

    patterns = (
        r"ModSecurity:\s+Access denied",
        r"Access denied with code \d+",
        r"\[action \"(?:deny|drop|block)\"\]",
        r"\bintervention\b.*\b(?:deny|block|status)\b",
    )
    return any(re.search(p, log_text, re.I) for p in patterns)


# ============================================================
# MODSECURITY RULE PARSER
# ============================================================

def parse_modsecurity_rules(log_text):

    rules = []

    seen = set()

    for line in log_text.splitlines():

        id_match = re.search(
            r'\[id "(\d+)"\]',
            line
        )

        msg_match = re.search(
            r'\[msg "([^"]+)"\]',
            line
        )

        if not id_match or not msg_match:

            continue

        rule_id = id_match.group(1)

        message = msg_match.group(1)

        key = (
            rule_id,
            message
        )

        if key in seen:

            continue

        seen.add(key)

        rules.append({
            "id": rule_id,
            "message": message
        })

    return rules


def format_rules(rules):

    if not rules:

        return "None"

    return " | ".join(
        f'{rule["id"]}: {rule["message"]}'
        for rule in rules
    )


def print_rules(rules):

    if not rules:

        print(
            "[+] ModSecurity rules: None detected"
        )

        return

    print("[+] ModSecurity rules:")

    for rule in rules:

        print(
            f'    {rule["id"]}: '
            f'{rule["message"]}'
        )


# ============================================================
# PAYLOAD LOADING
# ============================================================

def load_payloads(filename):

    payloads = []

    try:

        with open(
            filename,
            "r",
            encoding="utf-8",
            newline=""
        ) as payload_file:

            for source_line, raw_line in enumerate(
                payload_file,
                start=1
            ):

                payload = raw_line.rstrip(
                    "\r\n"
                )

                if payload == "":

                    continue

                payloads.append({

                    "payload_id":
                        f"XXE-{len(payloads) + 1:05d}",

                    "source_line":
                        source_line,

                    "payload":
                        payload
                })

    except FileNotFoundError:

        raise Exception(
            f"Payload file not found: {filename}"
        )

    if not payloads:

        raise Exception(
            f"No XXE payloads found in {filename}"
        )

    if PILOT_LIMIT is not None:

        payloads = payloads[:PILOT_LIMIT]

    return payloads


# ============================================================
# TEST PLAN
# ============================================================

def build_test_plan(
    payloads,
    rounds
):

    rng = random.Random(
        RANDOM_SEED
    )

    plan = []

    for round_number in range(
        1,
        rounds + 1
    ):

        round_payloads = payloads.copy()

        if SHUFFLE_PAYLOADS:

            rng.shuffle(
                round_payloads
            )

        for test in round_payloads:

            plan.append({

                "round":
                    round_number,

                "payload_id":
                    test["payload_id"],

                "source_line":
                    test["source_line"],

                "payload":
                    test["payload"]
            })

    return plan


# ============================================================
# DVWA LOGIN
# ============================================================

def login_dvwa(
    session,
    username,
    password
):

    print_info(
        "Logging into DVWA..."
    )

    response = session.get(
        LOGIN_URL,
        timeout=HTTP_TIMEOUT
    )

    if response.status_code != 200:

        raise Exception(
            "Unable to access DVWA login page: "
            f"HTTP {response.status_code}"
        )

    token_match = re.search(
        r'name="user_token"\s+value="([^"]+)"',
        response.text
    )

    user_token = (
        token_match.group(1)
        if token_match
        else ""
    )

    data = {

        "username":
            username,

        "password":
            password,

        "Login":
            "Login",

        "user_token":
            user_token
    }

    login_response = session.post(
        LOGIN_URL,
        data=data,
        timeout=HTTP_TIMEOUT
    )

    page = login_response.text.lower()

    if (
        "logout.php" not in page
        and
        "dvwa security" not in page
    ):

        print_warning(
            "Could not strongly confirm DVWA login."
        )

    else:

        print_success(
            "DVWA login successful"
        )

    # Remove every existing DVWA security cookie, regardless of domain/path,
    # then install exactly one cookie for this DVWA host.
    for cookie in list(session.cookies):
        if cookie.name.lower() == "security":
            session.cookies.clear(
                domain=cookie.domain,
                path=cookie.path,
                name=cookie.name
            )

    session.cookies.set(
        "security",
        DVWA_SECURITY,
        domain=REMOTE_HOST,
        path="/DVWA"
    )

    security_cookies = [
        c for c in session.cookies
        if c.name.lower() == "security"
    ]

    print_success(
        "DVWA security cookie set to exactly one value: "
        f"{DVWA_SECURITY} "
        f"(count={len(security_cookies)})"
    )


# ============================================================
# XXE ENDPOINT CHECK
# ============================================================

def check_xxe_endpoint(session):

    print_info(
        f"Checking XXE endpoint: {XXE_URL}"
    )

    try:

        response = session.get(
            XXE_URL,
            timeout=HTTP_TIMEOUT
        )

    except Exception as error:

        raise Exception(
            "Unable to connect to XXE endpoint: "
            f"{error}"
        )

    if response.status_code == 404:

        raise Exception(
            "XXE endpoint returned HTTP 404.\n"
            "Change XXE_URL to your actual XML "
            "processing endpoint."
        )

    print_success(
        "XXE endpoint accessible "
        f"(HTTP {response.status_code})"
    )


# ============================================================
# SEND XXE REQUEST
# ============================================================

def send_xxe_request(
    session,
    payload,
    request_id
):

    start = time.perf_counter()

    response = session.post(

        XXE_URL,

        data=payload.encode(
            "utf-8"
        ),

        headers={

            "Content-Type":
                "application/xml",

            "Accept":
                "*/*",

            "X-DVWA-Test-ID":
                request_id
        },

        timeout=HTTP_TIMEOUT,

        allow_redirects=True
    )

    elapsed_ms = (
        time.perf_counter() - start
    ) * 1000

    return response, elapsed_ms


# ============================================================
# XXE-SPECIFIC RULE ANALYSIS
# ============================================================

# Terms used only to distinguish XML/XXE-related ModSecurity messages
# from unrelated CRS alerts (for example, a numeric Host header).
XXE_RULE_IDS = {
    # CRS 941130 contains an ENTITY SYSTEM/PUBLIC signature even though its
    # stock message is XSS-oriented. Count it for this XXE corpus.
    "941130",
}

XXE_RULE_TERMS = (
    "xxe",
    "xml external entity",
    "external entity",
    "doctype",
    "entity declaration",
    "xml parser",
    "xml request body",
)

def get_xxe_relevant_rules(rules):
    relevant = []
    for rule in rules:
        text = f'{rule.get("id", "")} {rule.get("message", "")}'.lower()
        if (
            rule.get("id", "") in XXE_RULE_IDS
            or any(term in text for term in XXE_RULE_TERMS)
        ):
            relevant.append(rule)
    return relevant

def is_disruptive_status(status_code):
    # Common WAF denial responses. Keep the raw HTTP status in the CSV
    # so unusual responses can still be reviewed manually.
    return status_code in {401, 403, 406, 409, 429, 503}

# ============================================================
# RESULT CLASSIFICATION
# ============================================================

def classify_waf_result(
    status_code,
    rules,
    request_error=False
):

    if request_error:

        return "Request error"

    detected = bool(rules)

    if (
        is_disruptive_status(status_code)
        and detected
    ):

        return "Rule alert and blocked"

    if (
        is_disruptive_status(status_code)
        and not detected
    ):

        return "Disruptive HTTP response without parsed rule"

    if (
        status_code == 200
        and detected
    ):

        return "Rule alert but allowed"

    if (
        status_code == 200
        and not detected
    ):

        return "No parsed rule and allowed"

    if detected:

        return (
            "Rule alert with other HTTP status"
        )

    return "Other HTTP response"


# ============================================================
# RESPONSE ANALYSIS
# ============================================================

def infer_requested_resource(payload):
    """Extract a SYSTEM/PUBLIC URI so response evidence can be target-aware."""
    patterns = (
        r'\bSYSTEM\s+[\'"]([^\'"]+)[\'"]',
        r'\bPUBLIC\s+[\'"][^\'"]*[\'"]\s+[\'"]([^\'"]+)[\'"]',
    )
    for pattern in patterns:
        match = re.search(pattern, payload, re.I)
        if match:
            return match.group(1)
    return ""


def analyze_response(response_text, payload):
    """Classify entity-expansion evidence as Confirmed, Possible, or No."""
    if not response_text:
        return "No"

    lower_response = response_text.lower()
    resource = infer_requested_resource(payload).lower()

    # Strong signatures tied to common local resources in this controlled lab.
    if "passwd" in resource and re.search(r'(?m)^root:[^\r\n]*:\d+:\d+:', response_text):
        return "Confirmed"
    if ("win.ini" in resource or "boot.ini" in resource) and (
        "[fonts]" in lower_response
        or "[extensions]" in lower_response
        or "[boot loader]" in lower_response
        or "multi(0)disk(0)" in lower_response
    ):
        return "Confirmed"
    if ("hostname" in resource or "hosts" in resource) and (
        "127.0.0.1" in lower_response or "localhost" in lower_response
    ):
        return "Confirmed"
    if "proc/version" in resource and "linux version" in lower_response:
        return "Confirmed"

    # Generic evidence can still be useful, but is weaker when it cannot be
    # tied confidently to the resource requested by this payload.
    indicators = (
        "root:x:",
        "daemon:x:",
        "localhost",
        "linux version",
        "127.0.0.1",
    )
    if any(indicator in lower_response for indicator in indicators):
        return "Possible"

    return "No"


# ============================================================
# CSV
# ============================================================

RESULT_FIELDS = [

    "request_id",

    "round",

    "payload_id",

    "source_line",

    "payload",

    "http_status",

    "classification",

    "waf_rule_alert",

    "xxe_rule_alert",

    "disruptive_http_response",

    "modsecurity_intervention",

    "waf_blocked",

    "entity_expansion",

    "response_length",

    "time_ms",

    "rules"
]


def open_csv_writer():

    csv_file = open(
        RESULT_CSV,
        "w",
        newline="",
        encoding="utf-8"
    )

    writer = csv.DictWriter(
        csv_file,
        fieldnames=RESULT_FIELDS
    )

    writer.writeheader()

    csv_file.flush()

    return csv_file, writer


# ============================================================
# XXE TESTING
# ============================================================

def run_xxe_tests(
    session,
    ssh,
    payloads
):

    print()

    print("=" * 78)
    print("XXE TESTING")
    print("=" * 78)

    print()

    plan = build_test_plan(
        payloads,
        XXE_ROUNDS
    )

    csv_file, writer = (
        open_csv_writer()
    )

    results = []

    try:

        for index, test in enumerate(
            plan,
            start=1
        ):

            request_id = (
                f"XXE-{index:06d}"
            )

            payload = test["payload"]

            print("=" * 78)

            print(
                f"{request_id}"
                " | "
                f"Round {test['round']}/"
                f"{XXE_ROUNDS}"
                " | "
                f"{test['payload_id']}"
                " | "
                f"{index}/{len(plan)}"
            )

            print(
                f"Payload: {payload}"
            )

            # --------------------------------------------
            # Remember ModSecurity log position
            # --------------------------------------------

            log_start = get_log_size(
                ssh
            )

            request_error = False

            status_code = 0

            elapsed_ms = 0.0

            response_text = ""

            # --------------------------------------------
            # SEND XML
            # --------------------------------------------

            try:

                response, elapsed_ms = (
                    send_xxe_request(
                        session,
                        payload,
                        request_id
                    )
                )

                status_code = (
                    response.status_code
                )

                response_text = (
                    response.text
                )

            except Exception as error:

                request_error = True

                print_error(
                    "HTTP request failed: "
                    f"{error}"
                )

            # --------------------------------------------
            # WAIT FOR MODSECURITY LOG
            # --------------------------------------------

            time.sleep(
                LOG_WRITE_DELAY
            )

            # --------------------------------------------
            # READ MODSECURITY LOG
            # --------------------------------------------

            rules = []
            correlated_log = ""

            try:

                new_log = read_log_since(
                    ssh,
                    log_start
                )

                correlated_log = correlate_audit_transaction(
                    new_log,
                    request_id
                )

                if new_log and not correlated_log:
                    print_warning(
                        "New audit data found, but no transaction matched "
                        f"X-DVWA-Test-ID={request_id}."
                    )

                rules = parse_modsecurity_rules(correlated_log)

            except Exception as error:

                print_warning(
                    "Could not read ModSecurity log: "
                    f"{error}"
                )

            # --------------------------------------------
            # CLASSIFY
            # --------------------------------------------

            classification = (
                classify_waf_result(
                    status_code,
                    rules,
                    request_error
                )
            )

            waf_rule_alert = (
                "Yes"
                if rules
                else "No"
            )

            xxe_rules = get_xxe_relevant_rules(rules)

            xxe_rule_alert = (
                "Yes"
                if xxe_rules
                else "No"
            )

            disruptive_http_response = (
                "Yes" if is_disruptive_status(status_code) else "No"
            )

            confirmed_intervention = modsecurity_intervened(correlated_log)
            modsecurity_intervention = (
                "Yes" if confirmed_intervention else "No"
            )

            # Keep waf_blocked for convenient cross-WAF comparison, but only
            # mark it Yes when the correlated ModSecurity audit transaction
            # confirms a disruptive intervention.
            waf_blocked = modsecurity_intervention

            entity_expansion = analyze_response(
                response_text,
                payload
            )

            response_length = len(
                response_text
            )

            # --------------------------------------------
            # TERMINAL RESULTS
            # --------------------------------------------

            print()

            print_rules(
                rules
            )

            print(
                "[=] HTTP status: "
                f"{status_code}"
            )

            print(
                "[=] Classification: "
                f"{classification}"
            )

            print(
                "[=] XXE-specific rule alert: "
                f"{xxe_rule_alert}"
            )

            print(
                "[=] Disruptive HTTP response: "
                f"{disruptive_http_response}"
            )

            print(
                "[=] Confirmed ModSecurity intervention: "
                f"{modsecurity_intervention}"
            )

            print(
                "[=] WAF blocked (confirmed): "
                f"{waf_blocked}"
            )

            print(
                "[=] Entity expansion: "
                f"{entity_expansion}"
            )

            print(
                "[=] Response length: "
                f"{response_length}"
            )

            print(
                "[=] Response time: "
                f"{elapsed_ms:.2f} ms"
            )

            # --------------------------------------------
            # CSV
            # --------------------------------------------

            row = {

                "request_id":
                    request_id,

                "round":
                    test["round"],

                "payload_id":
                    test["payload_id"],

                "source_line":
                    test["source_line"],

                "payload":
                    payload,

                "http_status":
                    status_code,

                "classification":
                    classification,

                "waf_rule_alert":
                    waf_rule_alert,

                "xxe_rule_alert":
                    xxe_rule_alert,

                "disruptive_http_response":
                    disruptive_http_response,

                "modsecurity_intervention":
                    modsecurity_intervention,

                "waf_blocked":
                    waf_blocked,

                "entity_expansion":
                    entity_expansion,

                "response_length":
                    response_length,

                "time_ms":
                    f"{elapsed_ms:.2f}",

                "rules":
                    format_rules(
                        rules
                    )
            }

            writer.writerow(
                row
            )

            csv_file.flush()

            results.append(
                row
            )

            print()

            time.sleep(
                TEST_DELAY
            )

    finally:

        csv_file.close()

    print_success(
        "XXE results saved to "
        f"{RESULT_CSV}"
    )

    return results


# ============================================================
# SUMMARY
# ============================================================

def print_summary(results):

    total = len(results)

    alerts = sum(
        1
        for row in results
        if row["waf_rule_alert"] == "Yes"
    )

    xxe_alerts = sum(
        1
        for row in results
        if row["xxe_rule_alert"] == "Yes"
    )

    blocked = sum(
        1
        for row in results
        if row["waf_blocked"] == "Yes"
    )

    errors = sum(
        1
        for row in results
        if row["classification"] == "Request error"
    )

    confirmed_expansions = sum(
        1 for row in results
        if row["entity_expansion"] == "Confirmed"
    )

    possible_expansions = sum(
        1 for row in results
        if row["entity_expansion"] == "Possible"
    )

    print()

    print("=" * 78)
    print("XXE SUMMARY")
    print("=" * 78)

    print(
        f"Completed requests : {total}"
    )

    print(
        f"Request errors     : {errors}"
    )

    print(
        f"Any rule alerts    : {alerts}"
    )

    print(
        f"XXE rule alerts    : {xxe_alerts}"
    )

    print(
        f"Blocked            : {blocked}"
    )

    print(
        f"Confirmed expansion: {confirmed_expansions}"
    )

    print(
        f"Possible expansion : {possible_expansions}"
    )

    if total:

        print(
            "Any-alert rate     : "
            f"{alerts / total * 100:.2f}%"
        )

        print(
            "XXE-alert rate     : "
            f"{xxe_alerts / total * 100:.2f}%"
        )

        print(
            "Block rate         : "
            f"{blocked / total * 100:.2f}%"
        )

    print()


# ============================================================
# MAIN
# ============================================================

def main():

    print_header()

    ssh = None

    try:

        # ----------------------------------------------------
        # LOAD PAYLOADS
        # ----------------------------------------------------

        print_info(
            "Loading XXE payloads from "
            f"{PAYLOAD_FILE}"
        )

        payloads = load_payloads(
            PAYLOAD_FILE
        )

        print_success(
            f"Loaded {len(payloads)} XXE payloads"
        )

        if PILOT_LIMIT is not None:

            print_warning(
                "PILOT MODE enabled: "
                f"first {PILOT_LIMIT} payloads only"
            )

        print()

        # ----------------------------------------------------
        # SSH LOGIN
        # ----------------------------------------------------

        ubuntu_password = (
            getpass.getpass(
                f"{REMOTE_USER}@"
                f"{REMOTE_HOST} password: "
            )
        )

        sudo_password = (
            getpass.getpass(
                "Ubuntu sudo password: "
            )
        )

        print_info(
            "Connecting to Ubuntu over SSH..."
        )

        ssh = UbuntuSSH(
            REMOTE_HOST,
            REMOTE_USER,
            ubuntu_password,
            sudo_password
        )

        ssh.connect()

        _, error, code = ssh.sudo(
            "id"
        )

        if code != 0:

            raise Exception(
                "Ubuntu sudo authentication "
                "failed:\n"
                + error
            )

        print_success(
            "Ubuntu sudo access confirmed"
        )

        # ----------------------------------------------------
        # CHECK MODSECURITY LOG
        # ----------------------------------------------------

        log_size = get_log_size(
            ssh
        )

        print_success(
            "ModSecurity audit log accessible "
            f"({log_size} bytes)"
        )

        # ----------------------------------------------------
        # HTTP SESSION
        # ----------------------------------------------------

        session = requests.Session()

        session.headers.update({

            "User-Agent":
                "DVWA-XXE-Research-Tester/1.0"
        })

        # ----------------------------------------------------
        # DVWA LOGIN
        # ----------------------------------------------------

        dvwa_username = input(
            "DVWA username: "
        )

        dvwa_password = (
            getpass.getpass(
                "DVWA password: "
            )
        )

        login_dvwa(
            session,
            dvwa_username,
            dvwa_password
        )

        # ----------------------------------------------------
        # CHECK XXE ENDPOINT
        # ----------------------------------------------------

        check_xxe_endpoint(
            session
        )

        # ----------------------------------------------------
        # RUN TEST
        # ----------------------------------------------------

        print()

        print_warning(
            "Starting XML/XXE lab testing."
        )

        results = run_xxe_tests(
            session,
            ssh,
            payloads
        )

        print_summary(
            results
        )

        print_success(
            "XXE testing completed."
        )

    except KeyboardInterrupt:

        print()

        print_warning(
            "Testing interrupted by user."
        )

    except Exception as error:

        print()

        print_error(
            "Fatal error: "
            f"{error}"
        )

    finally:

        if ssh:

            ssh.close()


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()
