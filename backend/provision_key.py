"""Offline operator utility. Prints a new secret once; never writes it to the repo."""
import argparse
import hashlib
import json
import secrets

if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--owner',required=True)
    parser.add_argument('--role',choices=['reporter','analyst','admin'],default='reporter')
    args=parser.parse_args()
    if not args.owner or args.owner == '__quarantine__':
        parser.error('Choose a non-quarantined owner identifier')
    key=secrets.token_urlsafe(32)
    print('Personal key (deliver privately; never commit):',key)
    print('Append this digest entry to the server ETAP_API_KEYS array:')
    print(json.dumps({'owner_id':args.owner,'role':args.role,'sha256':hashlib.sha256(key.encode()).hexdigest()}))
