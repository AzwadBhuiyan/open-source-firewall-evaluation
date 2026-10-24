#test
#!/usr/bin/env python3
"""
Bulk DVWA SQL Injection / NAXSI Tester

Authorized lab workflow:
    Kali/test machine -> Nginx + NAXSI on Ubuntu -> DVWA

What this version does:
    1. Loads payloads from sqli_payloads.txt, one payload per line.
    2. Repeats normal payloads over multiple controlled rounds.
    3. Keeps time/CPU-heavy payloads to round 1 by default.
    4. Sends requests sequentially so each request can be matched to new
       NAXSI error-log data.
    5. Separates WAF detection from WAF blocking.
    6. Writes every result to CSV immediately.

Keep this .py file and sqli_payloads.txt in the same directory.
"""

import csv
import getpass
import random
import re
import shlex
import time
from pathlib import Path
from urllib.parse import quote_plus

import paramiko
import requests


# ============================================================
# CONFIGURATION
# ============================================================

REMOTE_HOST = "192.168.56.30"
REMOTE_USER = "ubuntu-client"
REMOTE_LOG = "/var/log/nginx/error.log"

DVWA_BASE = f"http://{REMOTE_HOST}:8081/dvwa"
LOGIN_URL = f"{DVWA_BASE}/login.php"
SQLI_URL = f"{DVWA_BASE}/vulnerabilities/sqli/"

# Files are resolved relative to this script,
# not the shell's current folder.
SCRIPT_DIR = Path(__file__).resolve().parent

PAYLOAD_FILE = SCRIPT_DIR / "sqli_payloads.txt"
CSV_FILE = SCRIPT_DIR / "naxsi_sqli_results.csv"


# ============================================================
# TEST SIZE
# ============================================================

# Your payload corpus will be repeated over multiple rounds.
#
# Example:
#
#     500 normal payloads
#     x 20 rounds
#     = about 10,000 requests
#
# Heavy/time-based payloads are treated differently below.
TEST_ROUNDS = 20


# Shuffle the payload order for every round.
#
# This prevents every round from having exactly the same
# request order.
SHUFFLE_EACH_ROUND = True


# A fixed random seed makes the shuffled test plan reproducible.
#
# If you rerun the experiment with the same payload file,
# settings and seed, Python produces the same shuffled order.
RANDOM_SEED = 20260825


# ============================================================
# HEAVY PAYLOAD HANDLING
# ============================================================

# Some payloads contain:
#
#     SLEEP()
#     pg_sleep()
#     WAITFOR DELAY
#     BENCHMARK()
#     RANDOMBLOB()
#
# These can consume database time or CPU if NAXSI
# allows them to reach the application/database.
#
# True:
#     Heavy payloads run only during round 1.
#
# False:
#     Heavy payloads run during every round.
#
# Recommended:
#     Keep True for the main bulk experiment.
HEAVY_PAYLOADS_FIRST_ROUND_ONLY = True


# Your corpus contains very large SQLite RANDOMBLOB payloads.
#
# These can create unnecessary memory/CPU pressure if they
# reach the database.
#
# True:
#     Skip those particular extreme payloads completely.
#
# False:
#     Include them.
SKIP_EXTREME_RESOURCE_PAYLOADS = True


# ============================================================
# URL ENCODING
# ============================================================

# Some payloads you collected already contain encoded values:
#
#     %00
#     %2c
#     %20
#
# Normal requests encoding could change:
#
#     %2c
#
# into:
#
#     %252c
#
# This option preserves valid existing %XX sequences.
PRESERVE_EXISTING_PERCENT_ENCODING = True


# ============================================================
# DVWA SETTINGS
# ============================================================

# For the WAF experiment, DVWA itself should normally stay
# intentionally vulnerable while NAXSI acts as the
# defensive control.
DVWA_SECURITY = "low"


# ============================================================
# TIMEOUTS / DELAYS
# ============================================================

# Some collected payloads intentionally wait for
# 5, 10, or 30 seconds.
#
# Therefore the old 10-second timeout would be too short.
HTTP_TIMEOUT = 60


# After a request finishes, wait briefly for NAXSI
# to complete its audit-log entry.
LOG_WRITE_DELAY = 0.12


# Small delay between requests.
#
# Requests remain sequential so log attribution stays cleaner.
TEST_DELAY = 0.10


# ============================================================
# HEAVY PAYLOAD MARKERS
# ============================================================

HEAVY_PAYLOAD_MARKERS = (
    "sleep(",
    "pg_sleep(",
    "waitfor delay",
    "benchmark(",
    "randomblob(",
)


# These are the especially large RANDOMBLOB payloads
# from your current collection.
EXTREME_RESOURCE_MARKERS = (
    "randomblob(500000000",
    "randomblob(1000000000",
)


def is_heavy_payload(payload):
    """
    Return True if a payload contains a time-based
    or computationally expensive SQL function.
    """

    lower = payload.lower()

    return any(
        marker in lower
        for marker in HEAVY_PAYLOAD_MARKERS
    )


def is_extreme_resource_payload(payload):
    """
    Return True for the largest RANDOMBLOB payloads.
    """

    lower = payload.lower()

    return any(
        marker in lower
        for marker in EXTREME_RESOURCE_MARKERS
    )


# ============================================================
# TERMINAL OUTPUT
# ============================================================

def print_header():

    print("=" * 78)

    print(
        "Bulk DVWA SQL Injection / "
        "NAXSI Tester"
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
    Maintain one SSH connection to the Ubuntu VM
    for the complete experiment.

    You enter the Ubuntu SSH password and sudo
    password once.

    The stored sudo password is then supplied
    automatically whenever the script needs to
    read the NAXSI log.
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
        Open the SSH connection.
        """

        self.client = paramiko.SSHClient()


        # Automatically accept the VM SSH host key.
        #
        # This is acceptable for an isolated lab VM.
        #
        # A production system should verify host keys.
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
        Execute one command remotely through sudo.

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


        # Supply the sudo password programmatically.
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
        Close the SSH connection.
        """

        if self.client:

            self.client.close()


# ============================================================
# NAXSI ERROR LOG
# ============================================================

def get_log_size(
    ssh
):
    """
    Return the current NAXSI/Nginx error-log
    size in bytes.

    This lets us remember where the log ended
    before each HTTP request.
    """

    output, error, code = ssh.sudo(

        f"wc -c "
        f"{shlex.quote(REMOTE_LOG)}"

    )


    if code != 0:

        raise Exception(
            "Unable to read NAXSI "
            "log size:\n"
            + error
        )


    match = re.search(
        r"(\d+)",
        output
    )


    if not match:

        raise Exception(
            "Could not determine "
            "NAXSI log size:\n"
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
    Read only the audit-log bytes that appeared
    AFTER start_size.

    OLD approach:

        clear entire log
        send request
        read whole log

    NEW approach:

        remember current byte position
        send request
        read only new bytes

    This preserves the complete NAXSI/Nginx error
    log instead of destroying it before every test.
    """

    current_size = get_log_size(
        ssh
    )


    # If the file suddenly becomes smaller,
    # something outside this script may have
    # rotated or truncated the audit log.
    if current_size < start_size:

        print_warning(
            "Audit log became smaller; "
            "rotation/truncation detected."
        )

        start_size = 0


    # Nothing new was written.
    if current_size == start_size:

        return ""


    # GNU tail uses one-based byte positions.
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
            "NAXSI log data:\n"
            + error
        )


    return output


# ============================================================
# NAXSI RULE PARSER
# ============================================================

def parse_modsecurity_rules(
    log_text
):
    """
    Extract NAXSI rule IDs and useful metadata from newly appended
    NAXSI_FMT records. The historical function name is retained so
    the rest of the original experiment workflow remains unchanged.
    """

    rules = []

    seen = set()


    for line in log_text.splitlines():
        if "NAXSI_FMT:" not in line:
            continue

        fields = dict(re.findall(r'(\w+)=([^&\s,]+)', line))
        score_names = [
            value
            for key, value in fields.items()
            if re.fullmatch(r'cscore\d+', key)
        ]
        score_text = ",".join(score_names) if score_names else "NAXSI"

        for id_match in re.finditer(r'(?:^|&)id(\d+)=([^&\s,]+)', line):
            index = id_match.group(1)
            rule_id = id_match.group(2)
            zone = fields.get(f"zone{index}", "unknown")
            variable = fields.get(f"var_name{index}", "unknown")
            message = f"{score_text}; zone={zone}; variable={variable}"
            key = (rule_id, message)

            if key in seen:
                continue

            seen.add(key)
            rules.append({"id": rule_id, "message": message})


    return rules


def format_rules(
    rules
):
    """
    Convert rules to a CSV-friendly string.
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
    Display NAXSI rules for
    the current request.
    """

    if not rules:

        print(
            "[+] NAXSI rules: "
            "None detected"
        )

        return


    print(
        "[+] NAXSI rules:"
    )


    for rule in rules:

        print(
            f'    {rule["id"]}: '
            f'{rule["message"]}'
        )


# ============================================================
# DVWA LOGIN
# ============================================================

def login_dvwa(
    session,
    username,
    password
):
    """
    Log into DVWA and keep the resulting
    PHP session cookies.
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

            "Unable to access DVWA "
            "login page: "

            f"HTTP "
            f"{response.status_code}"

        )


    # DVWA normally includes a CSRF token.
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


    # Look for common successful-login indicators.
    if (

        "logout.php" not in page

        and

        "dvwa security" not in page

    ):

        print_warning(
            "Could not strongly confirm "
            "DVWA login from page content."
        )

    else:

        print_success(
            "DVWA login successful"
        )


    # Make the application security setting
    # consistent between experimental runs.
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
# DVWA CHECKS
# ============================================================

def get_sql_page(
    session
):
    """
    Check that the DVWA SQL Injection
    page is reachable.
    """

    response = session.get(

        SQLI_URL,

        timeout=HTTP_TIMEOUT

    )


    if response.status_code != 200:

        raise Exception(

            "SQLi page returned HTTP "

            f"{response.status_code}"

        )


    print_success(
        "SQLi page accessible"
    )


def baseline_request(
    session
):
    """
    Send one normal non-SQLi request first.

    This confirms that DVWA is working before
    the SQL injection experiment begins.
    """

    response = session.get(

        SQLI_URL,

        params={

            "id":
                "1",

            "Submit":
                "Submit",

        },

        timeout=HTTP_TIMEOUT

    )


    print_success(

        "Baseline request returned "

        f"HTTP "
        f"{response.status_code}"

    )


# ============================================================
# PAYLOAD FILE LOADING
# ============================================================

def load_test_cases(
    filename
):
    """
    Load SQL injection payloads from
    sqli_payloads.txt.

    FORMAT:

        One payload per line.

    IMPORTANT:

        We remove ONLY:

            CR
            LF

        newline characters.

        We DO NOT use:

            .strip()

        because spaces can be meaningful
        inside SQL injection payloads.

    Example:

         OR 1=1

    should not automatically become:

        OR 1=1
    """

    tests = []


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
                #
                # Preserve:
                #
                #     spaces
                #     tabs
                #     quotes
                #     comments
                #     percent signs
                payload = raw_line.rstrip(
                    "\r\n"
                )


                # Ignore truly empty lines.
                #
                # A line containing spaces is NOT
                # considered empty.
                if payload == "":

                    continue


                tests.append({

                    "payload_id":

                        f"SQLI-"
                        f"{len(tests) + 1:04d}",

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


    except Exception as error:

        raise Exception(

            "Unable to load "
            "payload file: "

            f"{error}"

        )


    if not tests:

        raise Exception(

            "No payloads were found in "

            f"{filename}"

        )


    return tests


# ============================================================
# CREATE THE MULTI-ROUND TEST PLAN
# ============================================================

def build_test_plan(
    payload_tests
):
    """
    Convert the payload corpus into a much
    larger HTTP request plan.

    Example:

        Round 1
            payload A
            payload B
            payload C

        Round 2
            payload B
            payload C
            payload A

        Round 3
            payload C
            payload A
            payload B

    Normal payloads run every round.

    Heavy/time-based payloads run only in
    round 1 when:

        HEAVY_PAYLOADS_FIRST_ROUND_ONLY = True

    Extreme RANDOMBLOB payloads are skipped
    when:

        SKIP_EXTREME_RESOURCE_PAYLOADS = True
    """

    rng = random.Random(
        RANDOM_SEED
    )


    test_plan = []

    request_number = 1


    for round_number in range(

        1,

        TEST_ROUNDS + 1

    ):


        # Make a copy so shuffling does not
        # modify the original payload list.
        round_tests = (
            payload_tests.copy()
        )


        if SHUFFLE_EACH_ROUND:

            rng.shuffle(
                round_tests
            )


        for test in round_tests:

            payload = (
                test["payload"]
            )


            # Skip the largest RANDOMBLOB tests
            # completely by default.
            if (

                SKIP_EXTREME_RESOURCE_PAYLOADS

                and

                is_extreme_resource_payload(
                    payload
                )

            ):

                continue


            # Heavy payloads run in round 1 only.
            if (

                HEAVY_PAYLOADS_FIRST_ROUND_ONLY

                and

                round_number > 1

                and

                is_heavy_payload(
                    payload
                )

            ):

                continue


            test_plan.append({

                "request_id":

                    f"REQ-"
                    f"{request_number:06d}",

                "round":

                    round_number,

                "payload_id":

                    test["payload_id"],

                "source_line":

                    test["source_line"],

                "payload":

                    payload,

            })


            request_number += 1


    if not test_plan:

        raise Exception(
            "Generated test plan is empty."
        )


    return test_plan


# ============================================================
# URL ENCODING
# ============================================================

def encode_payload(
    payload
):
    """
    URL encode a payload.

    Example:

        '

    becomes:

        %27

    But if your payload file already contains:

        %2c

    this function can preserve it as:

        %2c

    instead of double encoding it to:

        %252c

    A standalone '%' is still safely encoded.
    """

    encoded = quote_plus(

        payload,

        safe=""

    )


    if PRESERVE_EXISTING_PERCENT_ENCODING:

        encoded = re.sub(

            r"%25([0-9A-Fa-f]{2})",

            r"%\1",

            encoded

        )


    return encoded


def build_request_url(
    payload
):
    """
    Build the exact URL that will be
    sent to DVWA.
    """

    encoded_payload = (
        encode_payload(
            payload
        )
    )


    exact_url = (

        f"{SQLI_URL}"

        f"?id="
        f"{encoded_payload}"

        f"&Submit=Submit"

    )


    return exact_url


# ============================================================
# SEND HTTP REQUEST
# ============================================================

def send_sqli_request(
    session,
    exact_url,
    request_id
):
    """
    Send one SQL injection request.

    A unique X-DVWA-Test-ID header is added.

    Example:

        X-DVWA-Test-ID: REQ-000001

    This can help you identify requests later
    if you manually inspect raw audit logs.
    """

    start_time = (
        time.perf_counter()
    )


    response = session.get(

        exact_url,

        headers={

            "X-DVWA-Test-ID":
                request_id,

        },

        timeout=HTTP_TIMEOUT

    )


    elapsed_ms = (

        time.perf_counter()

        - start_time

    ) * 1000


    return (
        response,
        elapsed_ms
    )


# ============================================================
# RESULT CLASSIFICATION
# ============================================================

def classify_result(
    status_code,
    rules,
    request_error=False
):
    """
    Separate WAF detection from blocking.

    This is important.

    Example 1:

        HTTP 403
        NAXSI rules found

        = Detected and blocked


    Example 2:

        HTTP 200
        NAXSI rules found

        = Detected but allowed


    Example 3:

        HTTP 200
        no NAXSI rules

        = Not detected and allowed


    Therefore HTTP 200 does NOT automatically
    mean that NAXSI failed to detect
    the request.
    """

    if request_error:

        return (
            "Request error"
        )


    detected = bool(
        rules
    )


    if (
        status_code == 403
        and detected
    ):

        return (
            "Detected and blocked"
        )


    if (
        status_code == 403
        and not detected
    ):

        return (
            "HTTP 403 without "
            "parsed NAXSI rule"
        )


    if (
        status_code == 200
        and detected
    ):

        return (
            "Detected but allowed"
        )


    if (
        status_code == 200
        and not detected
    ):

        return (
            "Not detected and allowed"
        )


    if detected:

        return (
            "Detected with other "
            "HTTP status"
        )


    return (
        "Other HTTP response"
    )


# ============================================================
# CSV
# ============================================================

CSV_FIELDS = [

    "request_id",

    "round",

    "payload_id",

    "source_line",

    "payload",

    "request_url",

    "http_status",

    "classification",

    "waf_detected",

    "waf_blocked",

    "time_ms",

    "rules",

]


def open_csv_writer(
    filename
):
    """
    Open the CSV file.

    A new CSV is created for every script run.
    """

    csv_file = open(

        filename,

        "w",

        newline="",

        encoding="utf-8"

    )


    writer = csv.DictWriter(

        csv_file,

        fieldnames=CSV_FIELDS

    )


    writer.writeheader()


    # Immediately write the header to disk.
    csv_file.flush()


    return (
        csv_file,
        writer
    )


# ============================================================
# FINAL SUMMARY
# ============================================================

def print_summary(
    results
):
    """
    Print overall results from the completed tests.
    """

    total = len(
        results
    )


    errors = sum(

        row["classification"]
        == "Request error"

        for row in results

    )


    detected = sum(

        row["waf_detected"]
        == "Yes"

        for row in results

    )


    blocked = sum(

        row["waf_blocked"]
        == "Yes"

        for row in results

    )


    detected_allowed = sum(

        row["classification"]
        == "Detected but allowed"

        for row in results

    )


    not_detected_allowed = sum(

        row["classification"]
        == "Not detected and allowed"

        for row in results

    )


    print()

    print("=" * 78)

    print(
        "TEST SUMMARY"
    )

    print("=" * 78)


    print(
        f"Completed requests       : "
        f"{total}"
    )


    print(
        f"Request errors           : "
        f"{errors}"
    )


    print(
        f"WAF detections           : "
        f"{detected}"
    )


    print(
        f"WAF blocks               : "
        f"{blocked}"
    )


    print(
        f"Detected but allowed     : "
        f"{detected_allowed}"
    )


    print(
        f"Not detected and allowed : "
        f"{not_detected_allowed}"
    )


    if total:

        detection_rate = (

            detected
            / total

        ) * 100


        block_rate = (

            blocked
            / total

        ) * 100


        print(

            "Detection rate           : "

            f"{detection_rate:.2f}%"

        )


        print(

            "Block rate               : "

            f"{block_rate:.2f}%"

        )


    print()


# ============================================================
# MAIN PROGRAM
# ============================================================

def main():

    print_header()


    ssh = None

    csv_file = None

    results = []


    try:

        # ====================================================
        # LOAD PAYLOAD CORPUS
        # ====================================================

        # Do this first.
        #
        # If the payload file is missing,
        # the program fails before asking for
        # Ubuntu/DVWA passwords.
        print_info(

            "Loading payloads from: "

            f"{PAYLOAD_FILE}"

        )


        payload_tests = (
            load_test_cases(
                PAYLOAD_FILE
            )
        )


        # ====================================================
        # BUILD MULTI-ROUND REQUEST PLAN
        # ====================================================

        test_plan = (
            build_test_plan(
                payload_tests
            )
        )


        heavy_count = sum(

            is_heavy_payload(
                test["payload"]
            )

            for test in payload_tests

        )


        extreme_count = sum(

            is_extreme_resource_payload(
                test["payload"]
            )

            for test in payload_tests

        )


        print_success(

            "Loaded "

            f"{len(payload_tests)} "

            "payload lines"

        )


        print_info(

            "Heavy/time-based payloads: "

            f"{heavy_count}"

        )


        print_info(

            "Extreme resource payloads: "

            f"{extreme_count}"

        )


        print_success(

            "Prepared "

            f"{len(test_plan)} "

            "HTTP requests across "

            f"{TEST_ROUNDS} rounds"

        )


        if (

            SKIP_EXTREME_RESOURCE_PAYLOADS

            and extreme_count

        ):

            print_warning(

                "Extreme RANDOMBLOB "
                "payloads are skipped."

            )


        if (

            HEAVY_PAYLOADS_FIRST_ROUND_ONLY

            and heavy_count

        ):

            print_info(

                "Heavy/time-based payloads "
                "run only in round 1."

            )


        print()


        # ====================================================
        # UBUNTU CREDENTIALS
        # ====================================================

        ubuntu_password = getpass.getpass(

            f"{REMOTE_USER}@"
            f"{REMOTE_HOST} "
            "password: "

        )


        sudo_password = getpass.getpass(

            "Ubuntu sudo password: "

        )


        print()


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

        print_info(

            "Checking Ubuntu "
            "sudo access..."

        )


        _, error, code = ssh.sudo(
            "id"
        )


        if code != 0:

            raise Exception(

                "Ubuntu sudo "
                "authentication failed:\n"

                + error

            )


        print_success(

            "Ubuntu sudo access confirmed"

        )


        # ====================================================
        # CHECK NAXSI LOG
        # ====================================================

        print_info(

            "Checking NAXSI "
            "error log..."

        )


        log_size = (
            get_log_size(
                ssh
            )
        )


        print_success(

            "Audit log accessible "

            f"({log_size} bytes)"

        )


        # ====================================================
        # HTTP SESSION
        # ====================================================

        # One requests.Session() is reused for
        # the entire test.
        #
        # This preserves the DVWA login cookies.
        session = requests.Session()


        session.headers.update({

            "User-Agent":

                "DVWA-SQLi-Research-"
                "Tester/2.0"

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
        # CHECK DVWA SQLi PAGE
        # ====================================================

        print_info(

            "Checking SQL Injection "
            "page..."

        )


        get_sql_page(
            session
        )


        # ====================================================
        # NORMAL BASELINE REQUEST
        # ====================================================

        baseline_request(
            session
        )


        # ====================================================
        # OPEN CSV
        # ====================================================

        csv_file, csv_writer = (
            open_csv_writer(
                CSV_FILE
            )
        )


        print_success(

            "CSV output: "

            f"{CSV_FILE}"

        )


        print()

        print(
            "[+] Starting SQLi tests..."
        )

        print()


        # ====================================================
        # RUN ALL TESTS
        # ====================================================

        # IMPORTANT:
        #
        # Requests remain sequential.
        #
        # We intentionally do not use:
        #
        #     threading
        #     multiprocessing
        #     asyncio concurrency
        #
        # because we want NAXSI log data
        # to be attributable to one request at
        # a time.
        for (
            index,
            test
        ) in enumerate(

            test_plan,

            start=1

        ):


            request_id = (
                test["request_id"]
            )


            round_number = (
                test["round"]
            )


            payload_id = (
                test["payload_id"]
            )


            source_line = (
                test["source_line"]
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
                f"{round_number}/"
                f"{TEST_ROUNDS}"

                " | "

                f"{payload_id}"

                " | "

                f"Plan "
                f"{index}/"
                f"{len(test_plan)}"

            )


            print(

                "Payload: "

                f"{payload}"

            )


            # ================================================
            # RECORD AUDIT-LOG START POSITION
            # ================================================

            # Remember where the NAXSI error log
            # ends before this request.
            try:

                log_start_size = (
                    get_log_size(
                        ssh
                    )
                )


            except Exception as error:

                print_warning(

                    "Could not record "
                    "log position: "

                    f"{error}"

                )


                log_start_size = None


            # ================================================
            # PREPARE HTTP RESULT VARIABLES
            # ================================================

            request_error = False

            status_code = 0

            elapsed_ms = 0.0


            # Build the URL before sending.
            #
            # This means the URL is still stored in
            # the CSV even if the request times out.
            exact_url = (
                build_request_url(
                    payload
                )
            )


            # ================================================
            # SEND SQLi REQUEST
            # ================================================

            try:

                response, elapsed_ms = (
                    send_sqli_request(

                        session,

                        exact_url,

                        request_id

                    )
                )


                status_code = (
                    response.status_code
                )


            except Exception as error:

                request_error = True


                print_error(

                    "HTTP request failed: "

                    f"{error}"

                )


            # ================================================
            # DISPLAY HTTP INFORMATION
            # ================================================

            print()


            print(
                "[>] HTTP request sent:"
            )


            print(

                f"    GET "
                f"{exact_url}"

            )


            print()


            print(

                "[<] HTTP response: "

                f"{status_code}"

            )


            print(

                "[<] Response time: "

                f"{elapsed_ms:.2f} ms"

            )


            # ================================================
            # WAIT FOR NAXSI LOG ENTRY
            # ================================================

            time.sleep(
                LOG_WRITE_DELAY
            )


            rules = []


            # ================================================
            # READ ONLY NEW AUDIT-LOG DATA
            # ================================================

            if log_start_size is not None:

                try:

                    new_log_text = (
                        read_log_since(

                            ssh,

                            log_start_size

                        )
                    )


                    rules = (
                        parse_modsecurity_rules(
                            new_log_text
                        )
                    )


                except Exception as error:

                    print_warning(

                        "Could not read new "
                        "audit-log data: "

                        f"{error}"

                    )


            # ================================================
            # DISPLAY DETECTED RULES
            # ================================================

            print()


            print_rules(
                rules
            )


            # ================================================
            # CLASSIFY RESULT
            # ================================================

            classification = (
                classify_result(

                    status_code,

                    rules,

                    request_error=(
                        request_error
                    )

                )
            )


            waf_detected = (

                "Yes"

                if rules

                else "No"

            )


            # We call it confirmed WAF blocking only
            # when both conditions are present:
            #
            #     HTTP 403
            #     parsed NAXSI rule
            waf_blocked = (

                "Yes"

                if (
                    status_code == 403
                    and bool(rules)
                )

                else "No"

            )


            print()


            print(

                "[=] Classification: "

                f"{classification}"

            )


            # ================================================
            # PREPARE RESULT ROW
            # ================================================

            result_row = {

                "request_id":

                    request_id,

                "round":

                    round_number,

                "payload_id":

                    payload_id,

                "source_line":

                    source_line,

                "payload":

                    payload,

                "request_url":

                    exact_url,

                "http_status":

                    status_code,

                "classification":

                    classification,

                "waf_detected":

                    waf_detected,

                "waf_blocked":

                    waf_blocked,

                "time_ms":

                    f"{elapsed_ms:.2f}",

                "rules":

                    format_rules(
                        rules
                    ),

            }


            # ================================================
            # STORE RESULT IN MEMORY
            # ================================================

            results.append(
                result_row
            )


            # ================================================
            # WRITE RESULT TO CSV IMMEDIATELY
            # ================================================

            # This is important for a large experiment.
            #
            # If you stop the program after thousands
            # of requests, the previous rows have
            # already been saved.
            csv_writer.writerow(
                result_row
            )


            csv_file.flush()


            print()


            # Small gap before the next sequential test.
            time.sleep(
                TEST_DELAY
            )


        # ====================================================
        # FINAL SUMMARY
        # ====================================================

        print_summary(
            results
        )


        print_success(

            "Results saved to "

            f"{CSV_FILE}"

        )


        print_success(

            "Testing completed."

        )


    # ========================================================
    # CTRL+C
    # ========================================================

    except KeyboardInterrupt:

        print()


        print_warning(

            "Testing interrupted by user."

        )


        if results:

            print_summary(
                results
            )


        if CSV_FILE.exists():

            print_info(

                "Partial results remain "
                "saved in "

                f"{CSV_FILE}"

            )


    # ========================================================
    # OTHER FATAL ERRORS
    # ========================================================

    except Exception as error:

        print()


        print_error(

            "Fatal error: "

            f"{error}"

        )


        if results:

            print_summary(
                results
            )


    # ========================================================
    # CLEANUP
    # ========================================================

    finally:

        if csv_file:

            csv_file.close()


        if ssh:

            ssh.close()


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()
