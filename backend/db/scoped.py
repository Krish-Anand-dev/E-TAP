"""Small allowlisted Mongo adapter: every supported operation carries owner_id.

Unknown operations fail closed. Raw database handles belong to offline admin tools.
"""
from copy import deepcopy
from .fake_mongo import _get_path

class ScopedCollection:
    def __init__(self, collection, owner, name):
        self._collection, self.owner, self.name = collection, owner, name

    def _filter(self, query=None):
        query = dict(query or {})
        if 'owner_id' in query and query['owner_id'] != self.owner:
            raise ValueError('Owner scope cannot be overridden')
        query['owner_id'] = self.owner
        if self.name == 'counters' and '_id' in query:
            query['_id'] = self.owner + ':' + str(query['_id'])
        return query

    def find(self, query=None, projection=None):
        return self._collection.find(self._filter(query), projection).limit(5000)

    def find_one(self, query=None, projection=None):
        return self._collection.find_one(self._filter(query), projection)

    def insert_one(self, doc):
        doc = deepcopy(doc)
        doc['owner_id'] = self.owner
        if self.name == 'analyzed_emails':
            from datetime import datetime, timedelta, timezone
            doc.setdefault('expires_at', datetime.now(timezone.utc) + timedelta(days=30))
        return self._collection.insert_one(doc)

    def _update(self, update):
        update = deepcopy(update)
        for fields in update.values():
            if any(k == 'owner_id' or k.startswith('owner_id.') for k in fields):
                raise ValueError('Owner is immutable')
        return update

    def update_one(self, query, update, **kwargs):
        return self._collection.update_one(self._filter(query), self._update(update), **kwargs)

    def find_one_and_update(self, query, update, **kwargs):
        return self._collection.find_one_and_update(self._filter(query), self._update(update), **kwargs)

    def delete_many(self, query):
        return self._collection.delete_many(self._filter(query))

    def count_documents(self, query=None):
        return self._collection.count_documents(self._filter(query))

    def distinct(self, field):
        values = []
        for doc in self.find():
            value = _get_path(doc, field)
            for item in value if isinstance(value, list) else [value]:
                if item is not None and item not in values:
                    values.append(item)
        return values

    def aggregate(self, pipeline):
        pipeline = deepcopy(pipeline)
        if not pipeline or '$vectorSearch' not in pipeline[0] or any(set(s) - {'$vectorSearch', '$project'} for s in pipeline):
            raise ValueError('Unsupported scoped aggregation')
        pipeline[0]['$vectorSearch']['filter'] = {'owner_id': self.owner}
        return self._collection.aggregate(pipeline)

class ScopedDatabase:
    def __init__(self, db, owner):
        self._db, self.owner = db, owner

    def __getitem__(self, name):
        if name not in {'analyzed_emails', 'emails', 'campaigns', 'counters', 'preferences'}:
            raise ValueError('Collection is not enabled for owner access')
        return ScopedCollection(self._db[name], self.owner, name)
