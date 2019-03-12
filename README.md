contrail-db-anonymise
=====================

Tool to anonymise a CSV dump of contrail DB.

It will hash resource names and randomize public IPs. The dump is still usable
after and can be loaded by contrail API.

## Making the dump

    export CASSANDRA_IP=...
    mkdir -p /tmp/cassandra-dump
    cqlsh $CASSANDRA_IP -e "DESC SCHEMA" > /tmp/cassandra-dump/schema.cql
    for t in obj_uuid_table obj_fq_name_table; do
      echo "COPY config_db_uuid.$t TO '/tmp/cassandra-dump/config_db_uuid.$t.csv';" | cqlsh $CASSANDRA_IP
    done

## Anonymising the dump

    $ mkdir /tmp/anon
    $ contrail-db-anonymise config_db_uuid.obj_fq_name_table.csv config_db_uuid.obj_uuid_table.csv /tmp/anon
    $ ls -l /tmp/anon/
    .rw-r--r-- 3.9M 12 Mar 17:59 config_db_uuid.obj_fq_name_table.csv
    .rw-r--r--  27M 12 Mar 17:59 config_db_uuid.obj_uuid_table.csv
