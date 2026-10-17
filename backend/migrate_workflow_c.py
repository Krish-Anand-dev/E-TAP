"""Offline operator migration. Back up first; never assigns legacy data to a user."""
from db.connection import _get_raw_db
from db.schema import ensure_indexes

def migrate(db):
    for name in ('analyzed_emails', 'emails', 'campaigns', 'counters'):
        collection = db[name]
        for doc in collection.find({}):
            if not doc.get('owner_id'):
                collection.update_one({'_id': doc['_id']}, {'$set': {'owner_id': '__quarantine__'}})
    for name, index in [('analyzed_emails', 'message_id_1'), ('campaigns', 'campaign_id_1')]:
        collection = db[name]
        if index in collection.index_information():
            collection.drop_index(index)
    ensure_indexes(db)

if __name__ == '__main__':
    migrate(_get_raw_db())
