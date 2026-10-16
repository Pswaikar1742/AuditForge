"""Disk-backed exact cardinality and bounded stratified evaluation."""
import sqlite3
import tempfile
from pathlib import Path


class UniqueCounts:
    """Exact digest membership on temporary disk, fixed SQLite page cache (~2 MiB)."""
    def __init__(self):
        self.hashable_submissions = 0
        self.directory = tempfile.TemporaryDirectory(prefix='attacklab-unique-')
        self.path = Path(self.directory.name) / 'unique.sqlite'
        self.db = sqlite3.connect(self.path)
        self.db.execute('PRAGMA cache_size=-2048')
        self.db.execute('PRAGMA journal_mode=OFF')
        self.db.execute('CREATE TABLE payloads (digest BLOB PRIMARY KEY, evaluated INTEGER NOT NULL) WITHOUT ROWID')

    def add(self, digest, evaluated=False):
        if not evaluated:
            self.hashable_submissions += 1
        self.db.execute('INSERT INTO payloads VALUES (?, ?) ON CONFLICT(digest) DO UPDATE SET evaluated=MAX(evaluated,excluded.evaluated)', (digest, int(evaluated)))

    def report(self, submitted):
        count, evaluated = self.db.execute('SELECT COUNT(*), COALESCE(SUM(evaluated),0) FROM payloads').fetchone()
        self.db.commit()
        return {'unique_payloads': count, 'unique_evaluated_payloads': evaluated,
                'hashable_submissions': self.hashable_submissions,
                'duplicate_ratio': 1 - count / self.hashable_submissions if self.hashable_submissions else None,
                'cardinality_method': 'exact disk-backed SHA-256 membership; not an in-memory set',
                'temporary_disk_bytes': self.path.stat().st_size}

    def close(self):
        self.db.close()
        self.directory.cleanup()


def size_band(size):
    for limit in (256, 1024, 8192, 65536, 131072):
        if size <= limit:
            return f'<= {limit} bytes'
    return '> 131072 bytes'


def uncertainty():
    return {'confidence_intervals': None,
            'reason': 'Finite designed-corpus census, not independent random draws from a target population. Repeated and combinatorial variants share construction. Binomial intervals would imply unsupported independence. Held-out set is small and author-reviewed, not a population sample.',
            'scope': 'Descriptive accuracy only; no inferential precision, recall or F1 interval claimed.'}
