
from share import session_clean, session_create_database
import sys
import time


def run_periodically():

    while True:
        try:
            print("Cleaning sessions", file=sys.stderr)
            session_clean()
        except Exception as e:
            print(e, file=sys.stderr)

        # Run daily
        time.sleep(86400)


if __name__ == "__main__":
    session_create_database()
    run_periodically()
