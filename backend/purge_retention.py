"""Run periodically as an operator job; expired data is also purged after each analysis."""
from db.connection import _get_raw_db
from workflow_c import purge_expired

def run():
    purge_expired(_get_raw_db())

if __name__ == '__main__':
    run()
