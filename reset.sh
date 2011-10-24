#!/bin/sh
mv data.db tmp/old_data.db
cat doc/structure.sql | sqlite3 data.db
perl simp.pl
perl rimp.pl
