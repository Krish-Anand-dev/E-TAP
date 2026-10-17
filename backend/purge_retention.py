"""Run periodically as an operator job; expired data is also purged on owner requests."""
from db.connection import _get_raw_db
from db.scoped import ScopedDatabase
from workflow_c import purge_expired

def run():
    db = _get_raw_db()
    for owner in db['analyzed_emails'].distinct('owner_id'):
        if owner and owner != '__quarantine__':
            purge_expired(ScopedDatabase(db, owner))

if __name__ == '__main__':
    run()
