#!/usr/bin/env python3
"""
DVWA XSS / ModSecurity Tester

Authorized lab workflow:
    Kali/test machine -> DVWA on Ubuntu -> ModSecurity + OWASP CRS

This script tests BOTH:
    1. Reflected XSS
    2. Stored XSS

What it records:
    - request ID
    - payload ID
    - payload
    - HTTP status
    - response time
    - whether ModSecurity rules were recorded
    - whether the request was blocked
    - triggered CRS rule IDs/messages
    - whether the reflected payload appears in the response
    - whether the stored payload appears on the stored-XSS page

Important:
    This script measures WAF behavior and reflection/storage.
    It does NOT prove that every allowed XSS payload actually
    executed JavaScript in a browser.

Keep this script and xss_payload.txt in the same folder.
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

REFLECTED_XSS_URL = (
    f"{DVWA_BASE}/vulnerabilities/xss_r/"
)

STORED_XSS_URL = (
    f"{DVWA_BASE}/vulnerabilities/xss_s/"
)


# ============================================================
# FILE LOCATIONS
# ============================================================

SCRIPT_DIR = Path(__file__).resolve().parent

PAYLOAD_FILE = (
    SCRIPT_DIR / "xss_payload.txt"
)

REFLECTED_CSV = (
    SCRIPT_DIR / "xss_reflected_results.csv"
)

STORED_CSV = (
    SCRIPT_DIR / "xss_stored_results.csv"
)


# ============================================================
# TEST SETTINGS
# ============================================================

# Start with 50 payloads first.
#
# After confirming the script works correctly,
# change this:
#
#     PILOT_LIMIT = 50
#
# to:
#
#     PILOT_LIMIT = None
#
# None means use the entire payload file.
PILOT_LIMIT = 5000


# Number of times to repeat the Reflected XSS corpus.
#
# Start with 1.
REFLECTED_ROUNDS = 1


# Stored XSS modifies the guestbook/database.
#
# One round is recommended initially.
STORED_ROUNDS = 1


# Shuffle payload order.
SHUFFLE_PAYLOADS = True


# Fixed seed makes shuffle reproducible.
RANDOM_SEED = 20260901


# Keep DVWA intentionally vulnerable.
DVWA_SECURITY = "low"


# HTTP request timeout.
HTTP_TIMEOUT = 30


# Wait briefly for ModSecurity to finish writing
# its audit-log entry.
LOG_WRITE_DELAY = 0.15


# Delay between requests.
TEST_DELAY = 0.10


# ============================================================
# TERMINAL OUTPUT
# ============================================================

def print_header():

    print("=" * 78)

    print(
        "DVWA XSS / ModSecurity Tester"
    )

    print("=" * 78)

    print()


def print_success(message):

    print(
        f"[+] {message}"
    )


def print_info(message):

    print(
        f"[*] {message}"
    )


def print_warning(message):

    print(
        f"[!] {message}"
    )


def print_error(message):

    print(
        f"[-] {message}"
    )


# ============================================================
# SSH CONNECTION
# ============================================================

class UbuntuSSH:
    """
    Keep one SSH connection open for the
    complete XSS experiment.

    SSH is used to read the ModSecurity
    audit log from Ubuntu.
    """

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
        """
        Connect to Ubuntu over SSH.
        """

        self.client = (
            paramiko.SSHClient()
        )


        # Automatically accept SSH host key.
        #
        # Suitable for an isolated lab VM.
        self.client.set_missing_host_key_policy(
            paramiko.AutoAddPolicy()
        )


        self.client.connect(

            hostname=self.host,

            username=self.username,

            password=self.password,

            timeout=10,

            look_for_keys=False,

            allow_agent=False,

        )


        print_success(
            "Ubuntu SSH connection successful"
        )


    def sudo(
        self,
        command
    ):
        """
        Execute a command remotely using sudo.

        Returns:
            stdout
            stderr
            exit code
        """

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


        return (
            output,
            error,
            exit_code
        )


    def close(self):
        """
        Close SSH connection.
        """

        if self.client:

            self.client.close()


# ============================================================
# MODSECURITY LOG
# ============================================================

def get_log_size(
    ssh
):
    """
    Get the current size of the ModSecurity
    audit log in bytes.

    This lets us remember where the log
    ended before sending each request.
    """

    output, error, code = ssh.sudo(

        f"wc -c "
        f"{shlex.quote(REMOTE_LOG)}"

    )


    if code != 0:

        raise Exception(

            "Unable to read "
            "ModSecurity log size:\n"

            + error

        )


    match = re.search(
        r"(\d+)",
        output
    )


    if not match:

        raise Exception(

            "Could not determine "
            "ModSecurity log size:\n"

            + output

        )


    return int(
        match.group(1)
    )


def read_log_since(
    ssh,
    start_size
):
    """
    Read only the ModSecurity log data
    written AFTER start_size.

    Example:

        Before request:
            log = 100000 bytes

        After request:
            log = 102000 bytes

    We read only:

        100001 -> 102000

    This keeps the full audit log intact.
    """

    current_size = (
        get_log_size(
            ssh
        )
    )


    # The log may have been rotated or cleared.
    if current_size < start_size:

        print_warning(

            "Audit log became smaller; "
            "rotation or truncation detected."

        )

        start_size = 0


    # Nothing new written.
    if current_size == start_size:

        return ""


    start_byte = (
        start_size + 1
    )


    output, error, code = ssh.sudo(

        f"tail -c +{start_byte} "
        f"{shlex.quote(REMOTE_LOG)}"

    )


    if code != 0:

        raise Exception(

            "Unable to read new "
            "ModSecurity log data:\n"

            + error

        )


    return output


# ============================================================
# MODSECURITY RULE PARSER
# ============================================================

def parse_modsecurity_rules(
    log_text
):
    """
    Extract ModSecurity rule IDs and messages.

    Example:

        [id "941100"]

        [msg "XSS Attack Detected via libinjection"]

    becomes:

        941100:
        XSS Attack Detected via libinjection
    """

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


        if (
            not id_match
            or not msg_match
        ):

            continue


        rule_id = (
            id_match.group(1)
        )


        message = (
            msg_match.group(1)
        )


        key = (
            rule_id,
            message
        )


        # Remove duplicate rule/message pairs
        # for the same request.
        if key in seen:

            continue


        seen.add(
            key
        )


        rules.append({

            "id":
                rule_id,

            "message":
                message,

        })


    return rules


def format_rules(
    rules
):
    """
    Convert rules into a CSV-friendly string.
    """

    if not rules:

        return "None"


    return " | ".join(

        f'{rule["id"]}: '
        f'{rule["message"]}'

        for rule in rules

    )


def print_rules(
    rules
):
    """
    Display triggered ModSecurity rules.
    """

    if not rules:

        print(

            "[+] ModSecurity rules: "
            "None detected"

        )

        return


    print(
        "[+] ModSecurity rules:"
    )


    for rule in rules:

        print(

            f'    {rule["id"]}: '
            f'{rule["message"]}'

        )


# ============================================================
# PAYLOAD LOADING
# ============================================================

def load_payloads(
    filename
):
    """
    Read XSS payloads from xss_payload.txt.

    One line = one payload.

    Only newline characters are removed.

    We do NOT use .strip() because spaces
    may be part of a payload.
    """

    payloads = []


    try:

        with open(

            filename,

            "r",

            encoding="utf-8",

            newline=""

        ) as payload_file:


            for (
                source_line,
                raw_line
            ) in enumerate(

                payload_file,

                start=1

            ):


                # Remove only newline characters.
                payload = raw_line.rstrip(
                    "\r\n"
                )


                # Skip only completely empty lines.
                if payload == "":

                    continue


                payloads.append({

                    "payload_id":

                        f"XSS-"
                        f"{len(payloads) + 1:05d}",

                    "source_line":

                        source_line,

                    "payload":

                        payload,

                })


    except FileNotFoundError:

        raise Exception(

            "Payload file not found: "

            f"{filename}"

        )


    if not payloads:

        raise Exception(

            "No XSS payloads found in "

            f"{filename}"

        )


    # Pilot mode.
    if PILOT_LIMIT is not None:

        payloads = (
            payloads[:PILOT_LIMIT]
        )


    return payloads


# ============================================================
# TEST PLAN
# ============================================================

def build_test_plan(
    payloads,
    rounds
):
    """
    Create one or more testing rounds.

    Example:

        payload A
        payload B
        payload C

    Round 1:
        B
        C
        A

    Round 2:
        C
        A
        B
    """

    rng = random.Random(
        RANDOM_SEED
    )


    plan = []


    for round_number in range(

        1,

        rounds + 1

    ):


        round_payloads = (
            payloads.copy()
        )


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
                    test["payload"],

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
    """
    Login to DVWA and keep the PHP session.
    """

    print_info(
        "Logging into DVWA..."
    )


    response = session.get(

        LOGIN_URL,

        timeout=HTTP_TIMEOUT

    )


    if response.status_code != 200:

        raise Exception(

            "Unable to access "
            "DVWA login page: "

            f"HTTP "
            f"{response.status_code}"

        )


    # DVWA normally contains a CSRF token.
    token_match = re.search(

        r'name="user_token"\s+'
        r'value="([^"]+)"',

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
            user_token,

    }


    login_response = session.post(

        LOGIN_URL,

        data=data,

        timeout=HTTP_TIMEOUT

    )


    page = (
        login_response.text.lower()
    )


    if (

        "logout.php" not in page

        and

        "dvwa security" not in page

    ):

        print_warning(

            "Could not strongly confirm "
            "DVWA login."

        )


    else:

        print_success(
            "DVWA login successful"
        )


    # Keep DVWA intentionally vulnerable.
    session.cookies.set(

        "security",

        DVWA_SECURITY,

        path="/"

    )


    print_success(

        "DVWA security cookie "
        f"set to: {DVWA_SECURITY}"

    )


# ============================================================
# PAGE CHECK
# ============================================================

def check_page(
    session,
    url,
    name
):
    """
    Check that a DVWA XSS page is accessible.
    """

    response = session.get(

        url,

        timeout=HTTP_TIMEOUT

    )


    if response.status_code != 200:

        raise Exception(

            f"{name} page returned HTTP "

            f"{response.status_code}"

        )


    print_success(

        f"{name} page accessible"

    )


    return response


# ============================================================
# CSRF TOKEN
# ============================================================

def extract_user_token(
    html
):
    """
    Extract DVWA user_token from a form,
    if one exists.
    """

    token_match = re.search(

        r'name=["\']user_token["\']\s+'
        r'value=["\']([^"\']+)["\']',

        html,

        re.IGNORECASE

    )


    if token_match:

        return token_match.group(1)


    return ""


# ============================================================
# RESULT CLASSIFICATION
# ============================================================

def classify_waf_result(
    status_code,
    rules,
    request_error=False
):
    """
    Separate WAF rule alerts from blocking.

    Examples:

    HTTP 403 + rules:
        Rule alert and blocked

    HTTP 200 + rules:
        Rule alert but allowed

    HTTP 200 + no rules:
        No parsed rule and allowed
    """

    if request_error:

        return "Request error"


    detected = bool(
        rules
    )


    if (
        status_code == 403
        and detected
    ):

        return (
            "Rule alert and blocked"
        )


    if (
        status_code == 403
        and not detected
    ):

        return (
            "HTTP 403 without parsed rule"
        )


    if (
        status_code == 200
        and detected
    ):

        return (
            "Rule alert but allowed"
        )


    if (
        status_code == 200
        and not detected
    ):

        return (
            "No parsed rule and allowed"
        )


    if detected:

        return (
            "Rule alert with other "
            "HTTP status"
        )


    return (
        "Other HTTP response"
    )


# ============================================================
# REFLECTED XSS REQUEST
# ============================================================

def send_reflected_xss(
    session,
    payload,
    request_id
):
    """
    DVWA Reflected XSS normally uses:

        GET /vulnerabilities/xss_r/?name=<payload>

    requests handles the URL encoding.
    """

    start = (
        time.perf_counter()
    )


    response = session.get(

        REFLECTED_XSS_URL,

        params={

            "name":
                payload,

        },

        headers={

            "X-DVWA-Test-ID":
                request_id,

        },

        timeout=HTTP_TIMEOUT

    )


    elapsed_ms = (

        time.perf_counter()

        - start

    ) * 1000


    return (
        response,
        elapsed_ms
    )


# ============================================================
# STORED XSS REQUEST
# ============================================================

def send_stored_xss(
    session,
    payload,
    request_id
):
    """
    Submit one payload to DVWA Stored XSS.

    DVWA commonly uses:

        txtName
        mtmtMessage
        btnSign

    The XSS payload is placed in mtmtMessage.

    A harmless fixed name is used for txtName.
    """

    # First load the form.
    form_page = session.get(

        STORED_XSS_URL,

        timeout=HTTP_TIMEOUT

    )


    if form_page.status_code != 200:

        raise Exception(

            "Unable to load Stored XSS form: "

            f"HTTP "
            f"{form_page.status_code}"

        )


    # Include CSRF token if DVWA requires it.
    user_token = (
        extract_user_token(
            form_page.text
        )
    )


    data = {

        "txtName":
            "xss-test",

        "mtmtMessage":
            payload,

        "btnSign":
            "Sign Guestbook",

    }


    if user_token:

        data["user_token"] = (
            user_token
        )


    start = (
        time.perf_counter()
    )


    response = session.post(

        STORED_XSS_URL,

        data=data,

        headers={

            "X-DVWA-Test-ID":
                request_id,

        },

        timeout=HTTP_TIMEOUT,

        allow_redirects=True

    )


    elapsed_ms = (

        time.perf_counter()

        - start

    ) * 1000


    return (
        response,
        elapsed_ms
    )


# ============================================================
# STORED XSS VERIFICATION
# ============================================================

def check_stored_payload(
    session,
    payload
):
    """
    Reload the Stored XSS page and check whether
    the exact payload text appears in the returned HTML.

    IMPORTANT:

    This confirms that the payload appears to be stored
    in the page source.

    It does NOT prove that JavaScript executed.
    """

    response = session.get(

        STORED_XSS_URL,

        timeout=HTTP_TIMEOUT

    )


    if response.status_code != 200:

        return (
            False,
            response.status_code
        )


    return (

        payload in response.text,

        response.status_code

    )


# ============================================================
# CSV FIELDS
# ============================================================

REFLECTED_FIELDS = [

    "request_id",

    "round",

    "payload_id",

    "source_line",

    "payload",

    "http_status",

    "classification",

    "waf_rule_alert",

    "waf_blocked",

    "payload_reflected",

    "time_ms",

    "rules",

]


STORED_FIELDS = [

    "request_id",

    "round",

    "payload_id",

    "source_line",

    "payload",

    "http_status",

    "classification",

    "waf_rule_alert",

    "waf_blocked",

    "payload_found_after_submission",

    "verification_http_status",

    "time_ms",

    "rules",

]


def open_csv_writer(
    filename,
    fields
):
    """
    Create CSV output file.
    """

    csv_file = open(

        filename,

        "w",

        newline="",

        encoding="utf-8"

    )


    writer = csv.DictWriter(

        csv_file,

        fieldnames=fields

    )


    writer.writeheader()

    csv_file.flush()


    return (
        csv_file,
        writer
    )


# ============================================================
# REFLECTED XSS TESTING
# ============================================================

def run_reflected_tests(
    session,
    ssh,
    payloads
):
    """
    Run all Reflected XSS tests.
    """

    print()

    print("=" * 78)

    print(
        "REFLECTED XSS TESTING"
    )

    print("=" * 78)

    print()


    plan = build_test_plan(

        payloads,

        REFLECTED_ROUNDS

    )


    csv_file, writer = (
        open_csv_writer(

            REFLECTED_CSV,

            REFLECTED_FIELDS

        )
    )


    results = []


    try:

        for (
            index,
            test
        ) in enumerate(

            plan,

            start=1

        ):


            request_id = (

                f"XSSR-"
                f"{index:06d}"

            )


            payload = (
                test["payload"]
            )


            print(
                "=" * 78
            )


            print(

                f"{request_id}"

                " | "

                f"Round "
                f"{test['round']}/"
                f"{REFLECTED_ROUNDS}"

                " | "

                f"{test['payload_id']}"

                " | "

                f"{index}/"
                f"{len(plan)}"

            )


            print(

                "Payload: "

                f"{payload}"

            )


            # Record ModSecurity log position
            # before sending this request.
            log_start = (
                get_log_size(
                    ssh
                )
            )


            request_error = False

            status_code = 0

            elapsed_ms = 0.0

            response_text = ""


            # ================================================
            # SEND REQUEST
            # ================================================

            try:

                response, elapsed_ms = (
                    send_reflected_xss(

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


            # Give ModSecurity time to finish
            # writing the audit log.
            time.sleep(
                LOG_WRITE_DELAY
            )


            # ================================================
            # READ MODSECURITY LOG
            # ================================================

            rules = []


            try:

                new_log = (
                    read_log_since(

                        ssh,

                        log_start

                    )
                )


                rules = (
                    parse_modsecurity_rules(
                        new_log
                    )
                )


            except Exception as error:

                print_warning(

                    "Could not read "
                    "ModSecurity log: "

                    f"{error}"

                )


            # ================================================
            # CLASSIFY
            # ================================================

            classification = (
                classify_waf_result(

                    status_code,

                    rules,

                    request_error

                )
            )


            # Check whether exact payload text
            # appears in returned HTML.
            payload_reflected = (

                "Yes"

                if payload in response_text

                else "No"

            )


            waf_rule_alert = (

                "Yes"

                if rules

                else "No"

            )


            waf_blocked = (

                "Yes"

                if (
                    status_code == 403
                    and rules
                )

                else "No"

            )


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

                "[=] Payload reflected: "

                f"{payload_reflected}"

            )


            print(

                "[=] Response time: "

                f"{elapsed_ms:.2f} ms"

            )


            # ================================================
            # CSV ROW
            # ================================================

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

                "waf_blocked":
                    waf_blocked,

                "payload_reflected":
                    payload_reflected,

                "time_ms":
                    f"{elapsed_ms:.2f}",

                "rules":
                    format_rules(
                        rules
                    ),

            }


            writer.writerow(
                row
            )


            # Save immediately.
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

        "Reflected XSS results saved to "

        f"{REFLECTED_CSV}"

    )


    return results


# ============================================================
# STORED XSS TESTING
# ============================================================

def run_stored_tests(
    session,
    ssh,
    payloads
):
    """
    Run Stored XSS tests.

    NOTE:

    Payloads that are allowed may remain inside
    the DVWA guestbook/database.

    Start with PILOT_LIMIT = 50.
    """

    print()

    print("=" * 78)

    print(
        "STORED XSS TESTING"
    )

    print("=" * 78)

    print()


    plan = build_test_plan(

        payloads,

        STORED_ROUNDS

    )


    csv_file, writer = (
        open_csv_writer(

            STORED_CSV,

            STORED_FIELDS

        )
    )


    results = []


    try:

        for (
            index,
            test
        ) in enumerate(

            plan,

            start=1

        ):


            request_id = (

                f"XSSS-"
                f"{index:06d}"

            )


            payload = (
                test["payload"]
            )


            print(
                "=" * 78
            )


            print(

                f"{request_id}"

                " | "

                f"Round "
                f"{test['round']}/"
                f"{STORED_ROUNDS}"

                " | "

                f"{test['payload_id']}"

                " | "

                f"{index}/"
                f"{len(plan)}"

            )


            print(

                "Payload: "

                f"{payload}"

            )


            # Record log position before submission.
            log_start = (
                get_log_size(
                    ssh
                )
            )


            request_error = False

            status_code = 0

            elapsed_ms = 0.0


            # ================================================
            # SUBMIT STORED PAYLOAD
            # ================================================

            try:

                response, elapsed_ms = (
                    send_stored_xss(

                        session,

                        payload,

                        request_id

                    )
                )


                status_code = (
                    response.status_code
                )


            except Exception as error:

                request_error = True


                print_error(

                    "Stored-XSS submission failed: "

                    f"{error}"

                )


            time.sleep(
                LOG_WRITE_DELAY
            )


            # ================================================
            # READ MODSECURITY LOG
            # ================================================

            rules = []


            try:

                new_log = (
                    read_log_since(

                        ssh,

                        log_start

                    )
                )


                rules = (
                    parse_modsecurity_rules(
                        new_log
                    )
                )


            except Exception as error:

                print_warning(

                    "Could not read "
                    "ModSecurity log: "

                    f"{error}"

                )


            classification = (
                classify_waf_result(

                    status_code,

                    rules,

                    request_error

                )
            )


            # ================================================
            # CHECK WHETHER PAYLOAD WAS STORED
            # ================================================

            stored_found = False

            verify_status = 0


            # Don't check storage if submission failed
            # or was blocked.
            if (

                not request_error

                and

                status_code != 403

            ):

                try:

                    (
                        stored_found,
                        verify_status
                    ) = check_stored_payload(

                        session,

                        payload

                    )


                except Exception as error:

                    print_warning(

                        "Stored payload verification "
                        "failed: "

                        f"{error}"

                    )


            waf_rule_alert = (

                "Yes"

                if rules

                else "No"

            )


            waf_blocked = (

                "Yes"

                if (
                    status_code == 403
                    and rules
                )

                else "No"

            )


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

                "[=] Payload found after submission: "

                f"{'Yes' if stored_found else 'No'}"

            )


            print(

                "[=] Response time: "

                f"{elapsed_ms:.2f} ms"

            )


            # ================================================
            # CSV ROW
            # ================================================

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

                "waf_blocked":
                    waf_blocked,

                "payload_found_after_submission":

                    (
                        "Yes"
                        if stored_found
                        else "No"
                    ),

                "verification_http_status":
                    verify_status,

                "time_ms":
                    f"{elapsed_ms:.2f}",

                "rules":
                    format_rules(
                        rules
                    ),

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

        "Stored XSS results saved to "

        f"{STORED_CSV}"

    )


    return results


# ============================================================
# SUMMARY
# ============================================================

def print_summary(
    name,
    results
):
    """
    Print a simple result summary.
    """

    total = len(
        results
    )


    alerts = sum(

        1

        for row in results

        if row["waf_rule_alert"] == "Yes"

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


    print()

    print("=" * 78)

    print(
        f"{name} SUMMARY"
    )

    print("=" * 78)


    print(

        "Completed requests : "

        f"{total}"

    )


    print(

        "Request errors     : "

        f"{errors}"

    )


    print(

        "Rule alerts        : "

        f"{alerts}"

    )


    print(

        "Blocked            : "

        f"{blocked}"

    )


    if total:


        print(

            "Rule-alert rate    : "

            f"{alerts / total * 100:.2f}%"

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

        # ====================================================
        # LOAD XSS PAYLOADS
        # ====================================================

        print_info(

            "Loading XSS payloads from "

            f"{PAYLOAD_FILE}"

        )


        payloads = (
            load_payloads(
                PAYLOAD_FILE
            )
        )


        print_success(

            "Loaded "

            f"{len(payloads)} "

            "XSS payloads"

        )


        if PILOT_LIMIT is not None:

            print_warning(

                "PILOT MODE enabled: "

                f"first {PILOT_LIMIT} "
                "payloads only"

            )


        print()


        # ====================================================
        # UBUNTU CREDENTIALS
        # ====================================================

        ubuntu_password = (
            getpass.getpass(

                f"{REMOTE_USER}@"
                f"{REMOTE_HOST} "
                "password: "

            )
        )


        sudo_password = (
            getpass.getpass(

                "Ubuntu sudo password: "

            )
        )


        # ====================================================
        # SSH CONNECTION
        # ====================================================

        print_info(

            "Connecting to Ubuntu "
            "over SSH..."

        )


        ssh = UbuntuSSH(

            REMOTE_HOST,

            REMOTE_USER,

            ubuntu_password,

            sudo_password,

        )


        ssh.connect()


        # ====================================================
        # CHECK SUDO
        # ====================================================

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


        # ====================================================
        # CHECK MODSECURITY LOG
        # ====================================================

        log_size = (
            get_log_size(
                ssh
            )
        )


        print_success(

            "ModSecurity audit log accessible "

            f"({log_size} bytes)"

        )


        # ====================================================
        # HTTP SESSION
        # ====================================================

        session = (
            requests.Session()
        )


        session.headers.update({

            "User-Agent":

                "DVWA-XSS-Research-Tester/1.0"

        })


        # ====================================================
        # DVWA LOGIN
        # ====================================================

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


        # ====================================================
        # CHECK XSS PAGES
        # ====================================================

        check_page(

            session,

            REFLECTED_XSS_URL,

            "Reflected XSS"

        )


        check_page(

            session,

            STORED_XSS_URL,

            "Stored XSS"

        )


        # ====================================================
        # REFLECTED XSS
        # ====================================================

        reflected_results = (
            run_reflected_tests(

                session,

                ssh,

                payloads

            )
        )


        print_summary(

            "REFLECTED XSS",

            reflected_results

        )


        # ====================================================
        # STORED XSS
        # ====================================================

        print()


        print_warning(

            "Stored XSS testing will now "
            "submit payloads to the "
            "DVWA guestbook."

        )


       # stored_results = (
        #    run_stored_tests(
#
 #               session,

  #              ssh,

   #             payloads

    #        )
     #   )


      #  print_summary(

       #     "STORED XSS",

        #    stored_results

    #    )


        print_success(

            "XSS testing completed."

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
