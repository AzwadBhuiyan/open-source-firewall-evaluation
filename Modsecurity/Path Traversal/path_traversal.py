#!/usr/bin/env python3

"""
DVWA Path Traversal / ModSecurity Tester

Authorized laboratory use only.

Workflow:

    path_traversal_patterns.txt
            +
    path_traversal_target.txt
            ↓
    Generate final traversal payloads
            ↓
    Select reproducible sample
            ↓
    Run multiple rounds
            ↓
    Send requests to DVWA
            ↓
    ModSecurity + OWASP CRS inspect request
            ↓
    Read audit log
            ↓
    Save results to CSV


Keep these files in the same folder:

    path_traversal_tester.py
    path_traversal_patterns.txt
    path_traversal_target.txt
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
# BASIC CONFIGURATION
# ============================================================

REMOTE_HOST = "192.168.56.20"

REMOTE_USER = "linux"

REMOTE_LOG = "/var/log/modsec_audit.log"


# ============================================================
# DVWA CONFIGURATION
# ============================================================

DVWA_BASE = (
    f"http://{REMOTE_HOST}/DVWA"
)

LOGIN_URL = (
    f"{DVWA_BASE}/login.php"
)


# DVWA File Inclusion page.
#
# DVWA normally uses:
#
#     vulnerabilities/fi/
#
# with:
#
#     ?page=<value>
#
# This is suitable for path traversal / file inclusion testing.
PATH_TRAVERSAL_URL = (
    f"{DVWA_BASE}/vulnerabilities/fi/"
)


DVWA_SECURITY = "low"


# ============================================================
# FILE LOCATIONS
# ============================================================

SCRIPT_DIR = (
    Path(__file__).resolve().parent
)


PATTERN_FILE = (
    SCRIPT_DIR
    / "path_traversal_patterns.txt"
)


TARGET_FILE = (
    SCRIPT_DIR
    / "path_traversal_target.txt"
)


CSV_FILE = (
    SCRIPT_DIR
    / "path_traversal_results.csv"
)


# ============================================================
# EXPERIMENT SETTINGS
# ============================================================

# Maximum number of unique pattern + target combinations
# used for the experiment.
#
# Your full combination set is very large,
# so we take a controlled sample.
SAMPLE_SIZE = 5000


# YES, you can use two rounds.
#
# Same selected payload corpus is tested twice.
TEST_ROUNDS = 1


# Shuffle request order independently in each round.
SHUFFLE_EACH_ROUND = True


# Fixed seed gives reproducible sampling/shuffling.
RANDOM_SEED = 20260908


# HTTP timeout.
HTTP_TIMEOUT = 30


# Give ModSecurity time to finish writing logs.
LOG_WRITE_DELAY = 0.15


# Small delay between requests.
TEST_DELAY = 0.10


# ============================================================
# OUTPUT HELPERS
# ============================================================

def print_header():

    print("=" * 78)

    print(
        "DVWA Path Traversal / ModSecurity Tester"
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

        self.client = (
            paramiko.SSHClient()
        )


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


    def sudo(
        self,
        command
    ):

        sudo_command = (

            "sudo -S -p '' bash -c "

            + shlex.quote(
                command
            )

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

        if self.client:

            self.client.close()


# ============================================================
# LOAD UNIQUE LINES
# ============================================================

def load_unique_lines(
    filename
):

    """
    Load unique non-empty lines.

    Exact duplicates are removed automatically.
    """

    values = []

    seen = set()


    with open(
        filename,
        "r",
        encoding="utf-8",
        newline=""
    ) as file:


        for raw_line in file:


            value = (
                raw_line.rstrip(
                    "\r\n"
                )
            )


            if value == "":

                continue


            if value in seen:

                continue


            seen.add(
                value
            )


            values.append(
                value
            )


    return values


# ============================================================
# TARGET NORMALISATION
# ============================================================

def normalise_target(
    target
):

    """
    Remove leading slash so:

        ../../../{FILE}

    plus:

        /etc/passwd

    becomes:

        ../../../etc/passwd

    instead of:

        ../../..//etc/passwd
    """

    target = (
        target.strip()
    )


    while target.startswith("/"):

        target = target[1:]


    return target


# ============================================================
# BUILD ALL UNIQUE COMBINATIONS
# ============================================================

def build_payload_combinations(
    patterns,
    targets
):

    """
    Combine:

        pattern + target

    Example:

        ../../../{FILE}

    with:

        etc/passwd

    becomes:

        ../../../etc/passwd
    """

    combinations = []

    seen_payloads = set()


    for pattern in patterns:


        if "{FILE}" not in pattern:

            continue


        for target in targets:


            clean_target = (
                normalise_target(
                    target
                )
            )


            if not clean_target:

                continue


            payload = (
                pattern.replace(
                    "{FILE}",
                    clean_target
                )
            )


            # Remove duplicate final payloads.
            if payload in seen_payloads:

                continue


            seen_payloads.add(
                payload
            )


            combinations.append({

                "pattern":
                    pattern,

                "target_file":
                    clean_target,

                "payload":
                    payload

            })


    return combinations


# ============================================================
# SAMPLE PAYLOADS
# ============================================================

def select_sample(
    combinations
):

    """
    Randomly select a reproducible subset.

    If SAMPLE_SIZE is bigger than total combinations,
    all combinations are used.
    """

    rng = random.Random(
        RANDOM_SEED
    )


    if SAMPLE_SIZE is None:

        selected = (
            combinations.copy()
        )


    elif SAMPLE_SIZE >= len(combinations):

        selected = (
            combinations.copy()
        )


    else:

        selected = (
            rng.sample(
                combinations,
                SAMPLE_SIZE
            )
        )


    # Assign stable payload IDs.
    tests = []


    for index, item in enumerate(
        selected,
        start=1
    ):


        tests.append({

            "payload_id":
                f"PT-{index:05d}",

            "pattern":
                item["pattern"],

            "target_file":
                item["target_file"],

            "payload":
                item["payload"]

        })


    return tests


# ============================================================
# BUILD TWO-ROUND TEST PLAN
# ============================================================

def build_test_plan(
    selected_tests
):

    """
    Same selected payload corpus is used
    in every round.

    Each round gets a shuffled order.
    """

    rng = random.Random(
        RANDOM_SEED
    )


    plan = []

    request_number = 0


    for round_number in range(
        1,
        TEST_ROUNDS + 1
    ):


        round_tests = (
            selected_tests.copy()
        )


        if SHUFFLE_EACH_ROUND:

            rng.shuffle(
                round_tests
            )


        for test in round_tests:


            request_number += 1


            plan.append({

                "request_id":

                    f"PTR-"
                    f"{request_number:06d}",


                "round":

                    round_number,


                "payload_id":

                    test["payload_id"],


                "pattern":

                    test["pattern"],


                "target_file":

                    test["target_file"],


                "payload":

                    test["payload"]

            })


    return plan


# ============================================================
# MODSECURITY LOG
# ============================================================

def get_log_size(
    ssh
):

    output, error, code = (
        ssh.sudo(

            f"wc -c "
            f"{shlex.quote(REMOTE_LOG)}"

        )
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
            "ModSecurity log size"

        )


    return int(
        match.group(1)
    )


def read_log_since(
    ssh,
    start_size
):

    current_size = (
        get_log_size(
            ssh
        )
    )


    if current_size < start_size:

        print_warning(

            "Audit log was rotated "
            "or truncated."

        )

        start_size = 0


    if current_size == start_size:

        return ""


    start_byte = (
        start_size + 1
    )


    output, error, code = (
        ssh.sudo(

            f"tail -c +{start_byte} "
            f"{shlex.quote(REMOTE_LOG)}"

        )
    )


    if code != 0:

        raise Exception(

            "Unable to read "
            "ModSecurity log:\n"

            + error

        )


    return output


# ============================================================
# PARSE MODSECURITY RULES
# ============================================================

def parse_modsecurity_rules(
    log_text
):

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


        if key in seen:

            continue


        seen.add(
            key
        )


        rules.append({

            "id":
                rule_id,

            "message":
                message

        })


    return rules


def format_rules(
    rules
):

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

    if not rules:

        print(
            "[+] ModSecurity rules: None"
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
# LOGIN TO DVWA
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

            "Unable to access "
            "DVWA login page"

        )


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
            user_token

    }


    login_response = session.post(

        LOGIN_URL,

        data=data,

        timeout=HTTP_TIMEOUT

    )


    if login_response.status_code != 200:

        print_warning(

            "Unexpected DVWA "
            "login HTTP response"

        )


    session.cookies.set(

        "security",

        DVWA_SECURITY,

        path="/"

    )


    print_success(
        "DVWA login completed"
    )


    print_success(

        "DVWA security level: "

        f"{DVWA_SECURITY}"

    )


# ============================================================
# CHECK PATH TRAVERSAL PAGE
# ============================================================

def check_path_traversal_page(
    session
):

    response = session.get(

        PATH_TRAVERSAL_URL,

        timeout=HTTP_TIMEOUT

    )


    if response.status_code != 200:

        raise Exception(

            "Path traversal page "
            "not accessible: "

            f"HTTP "
            f"{response.status_code}"

        )


    print_success(

        "DVWA File Inclusion / "
        "Path Traversal page accessible"

    )


# ============================================================
# SEND PATH TRAVERSAL REQUEST
# ============================================================

def send_path_traversal_request(
    session,
    payload,
    request_id
):

    """
    DVWA File Inclusion uses:

        ?page=<payload>
    """

    start = (
        time.perf_counter()
    )


    response = session.get(

        PATH_TRAVERSAL_URL,

        params={

            "page":
                payload

        },

        headers={

            "X-DVWA-Test-ID":
                request_id

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
# CLASSIFICATION
# ============================================================

def classify_result(
    status_code,
    rules,
    request_error=False
):

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
            "Rule alert with other HTTP status"
        )


    return (
        "Other HTTP response"
    )


# ============================================================
# CSV CONFIGURATION
# ============================================================

CSV_FIELDS = [

    "request_id",

    "round",

    "payload_id",

    "pattern",

    "target_file",

    "payload",

    "http_status",

    "classification",

    "waf_rule_alert",

    "waf_blocked",

    "target_string_in_response",

    "time_ms",

    "rules"

]


def open_csv_writer():

    csv_file = open(

        CSV_FILE,

        "w",

        newline="",

        encoding="utf-8"

    )


    writer = csv.DictWriter(

        csv_file,

        fieldnames=CSV_FIELDS

    )


    writer.writeheader()

    csv_file.flush()


    return (
        csv_file,
        writer
    )


# ============================================================
# SUMMARY
# ============================================================

def print_summary(
    results
):

    total = len(
        results
    )


    errors = sum(

        1

        for row in results

        if row["classification"]
        == "Request error"

    )


    alerts = sum(

        1

        for row in results

        if row["waf_rule_alert"]
        == "Yes"

    )


    blocked = sum(

        1

        for row in results

        if row["waf_blocked"]
        == "Yes"

    )


    allowed = sum(

        1

        for row in results

        if row["http_status"]
        == 200

    )


    print()

    print("=" * 78)

    print(
        "PATH TRAVERSAL SUMMARY"
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


    print(

        "HTTP 200 allowed   : "

        f"{allowed}"

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

    csv_file = None

    results = []


    try:

        # ====================================================
        # LOAD PATTERNS
        # ====================================================

        print_info(

            "Loading traversal patterns..."

        )


        patterns = (
            load_unique_lines(
                PATTERN_FILE
            )
        )


        print_success(

            f"Unique patterns loaded: "
            f"{len(patterns)}"

        )


        # ====================================================
        # LOAD TARGETS
        # ====================================================

        print_info(

            "Loading target files..."

        )


        raw_targets = (
            load_unique_lines(
                TARGET_FILE
            )
        )


        # Normalise and deduplicate again
        # after removing leading slash.
        targets = []

        seen_targets = set()


        for target in raw_targets:


            clean_target = (
                normalise_target(
                    target
                )
            )


            if not clean_target:

                continue


            if clean_target in seen_targets:

                continue


            seen_targets.add(
                clean_target
            )


            targets.append(
                clean_target
            )


        print_success(

            f"Unique targets loaded: "
            f"{len(targets)}"

        )


        # ====================================================
        # GENERATE COMBINATIONS
        # ====================================================

        print_info(

            "Generating unique "
            "path traversal combinations..."

        )


        combinations = (
            build_payload_combinations(

                patterns,

                targets

            )
        )


        print_success(

            "Unique final payloads generated: "

            f"{len(combinations)}"

        )


        # ====================================================
        # SELECT SAMPLE
        # ====================================================

        selected_tests = (
            select_sample(
                combinations
            )
        )


        print_success(

            "Selected payloads for experiment: "

            f"{len(selected_tests)}"

        )


        # ====================================================
        # BUILD ROUNDS
        # ====================================================

        test_plan = (
            build_test_plan(
                selected_tests
            )
        )


        print_success(

            "Testing rounds: "

            f"{TEST_ROUNDS}"

        )


        print_success(

            "Total planned requests: "

            f"{len(test_plan)}"

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
        # SSH
        # ====================================================

        ssh = UbuntuSSH(

            REMOTE_HOST,

            REMOTE_USER,

            ubuntu_password,

            sudo_password

        )


        ssh.connect()


        # Check log access.
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
        # DVWA SESSION
        # ====================================================

        session = (
            requests.Session()
        )


        session.headers.update({

            "User-Agent":

                "DVWA-Path-Traversal-Research-Tester/1.0"

        })


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


        check_path_traversal_page(
            session
        )


        # ====================================================
        # CSV
        # ====================================================

        csv_file, writer = (
            open_csv_writer()
        )


        # ====================================================
        # TEST LOOP
        # ====================================================

        for (
            index,
            test
        ) in enumerate(

            test_plan,

            start=1

        ):


            print("=" * 78)


            print(

                f"{test['request_id']}"

                " | "

                f"Round "
                f"{test['round']}/"
                f"{TEST_ROUNDS}"

                " | "

                f"{test['payload_id']}"

                " | "

                f"{index}/"
                f"{len(test_plan)}"

            )


            print(

                "Pattern: "

                f"{test['pattern']}"

            )


            print(

                "Target: "

                f"{test['target_file']}"

            )


            print(

                "Payload: "

                f"{test['payload']}"

            )


            # =================================================
            # RECORD LOG POSITION
            # =================================================

            log_start = (
                get_log_size(
                    ssh
                )
            )


            request_error = False

            status_code = 0

            elapsed_ms = 0.0

            response_text = ""


            # =================================================
            # SEND REQUEST
            # =================================================

            try:

                response, elapsed_ms = (
                    send_path_traversal_request(

                        session,

                        test["payload"],

                        test["request_id"]

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

                    "Request failed: "

                    f"{error}"

                )


            # Wait for ModSecurity log write.
            time.sleep(
                LOG_WRITE_DELAY
            )


            # =================================================
            # READ MODSECURITY LOG
            # =================================================

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

                    "Unable to read "
                    "ModSecurity log: "

                    f"{error}"

                )


            # =================================================
            # CLASSIFY
            # =================================================

            classification = (
                classify_result(

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


            waf_blocked = (

                "Yes"

                if (
                    status_code == 403
                    and rules
                )

                else "No"

            )


            # Basic response check.
            #
            # This does NOT prove the target file
            # was successfully read.
            #
            # It only checks whether the target name
            # appears somewhere in the HTML.
            target_string_in_response = (

                "Yes"

                if test["target_file"]
                in response_text

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

                "[=] Target string in response: "

                f"{target_string_in_response}"

            )


            print(

                "[=] Response time: "

                f"{elapsed_ms:.2f} ms"

            )


            # =================================================
            # SAVE CSV
            # =================================================

            row = {

                "request_id":

                    test["request_id"],


                "round":

                    test["round"],


                "payload_id":

                    test["payload_id"],


                "pattern":

                    test["pattern"],


                "target_file":

                    test["target_file"],


                "payload":

                    test["payload"],


                "http_status":

                    status_code,


                "classification":

                    classification,


                "waf_rule_alert":

                    waf_rule_alert,


                "waf_blocked":

                    waf_blocked,


                "target_string_in_response":

                    target_string_in_response,


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


    except KeyboardInterrupt:


        print()


        print_warning(

            "Testing interrupted."

        )


        if results:

            print_summary(
                results
            )


        print_warning(

            "Completed CSV rows "
            "have been retained."

        )


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
