# gevent_snmp
Asynchronous SNMP via gevent.

## Introduction

Main characteristics as bullet point list:

* Gives you an 'AsyncSession' object, which works inside a gevent greenlet.
* Very speedy, ~8000 GET requests per second.
* It uses the libnetsnmp.so directly via cython (Cython>=0.21 is required).
* It requires a patched libnetsnmp.so. See implementation notes.
* Uses the "high level" API of libnetsnmp => Easily use the features provided by libnetsnmp.
* Tested with gevent 0.13.8
* Tested with libnetsnmp 5.4.X

## API

The API does no oid translation for you.
An oid must be given as a tuple of integers.
For example `system.sysDescr.0` must be convertet to `(1, 3, 6, 1, 2, 1, 1, 1, 0)`

The output is always a dictionary containing the varbind list from the response pdu.
This varbind list is converted to a dictionary where the keys are the oids (as
tuples) and the values the corresponding value from the response pdu.

### SNMP-GET
* *Input:* List of oid tuples.
* *Output:* Dictionary

Example:
```python
oids = [
    (1, 3, 6, 1, 2, 1, 1, 1, 0),
    (1, 3, 6, 1, 2, 1, 1, 3, 0),
]

result = session.get(oids)

print 'system description', result[(1, 3, 6, 1, 2, 1, 1, 1, 0)]
print 'system uptime', result[(1, 3, 6, 1, 2, 1, 1, 3, 0)]
```

### SNMP-GETNEXT
* *Input:* A single oid tuple
* *Output* Dictionary with the next oid

Example:
```python
oid = (1, 3, 6, 1, 2, 1, 1, 1, 0)
result = session.get_next(oid)
if result:
    next_oid, next_value = result.items()[0]
    print 'next oid is', next_oid
    print 'value for this id', next_value
```

### SNMP-GETBULK
* *Input:* List of oid tuples, non repeaters, max repetitions
* *Output:* Dictionary

Example:
```python
oids = [
    (1, 3, 6, 1, 2, 1, 1, 1, 0),
    (1, 3, 6, 1, 2, 1, 1, 3, 0),
    (1, 3, 6, 1, 2, 1, 2, 2, 1, 2)
]

# Get
# - system description
# - system uptime
# - The first 5 interface names
result = session.get_bulk(oids, nonrepeaters=2, maxrepetitions=5)

print 'system description', result.pop((1, 3, 6, 1, 2, 1, 1, 1, 0))
print 'system uptime', result.pop((1, 3, 6, 1, 2, 1, 1, 3, 0))

for oid, ifname in result.items():
    print 'oid', oid
    print 'interface name', ifname
```

### WALK
* *Input*: A single oid tuple
* *Output* Dictionary having all oids which are childs of the input oid

This walk uses only `snmp-getnext` to traverse the tree.

Example:
```python
root_id = (1, 3, 6, 1, 2, 1, 1)
result = session.walk(root_id)
for oid in sorted(result):
    print 'oid', oid, result[oid]
```

### WALK with GETBULK
* *Input*: A single oid tuple, how much oids to retrieve in a single `getbulk`
* *Output* Dictionary having all (full) oids which are childs of the input oid

The main difference to `walk` is the usage of the `snmp-getbulk` operation to traverse the tree.

Example:
```python
root_id = (1, 3, 6, 1, 2, 1, 1)
result = session.walk_with_get_bulk(root_id, maxrepetitions=10)
for oid in sorted(result):
    print 'oid', oid, result[oid]
```

### SET
* *Input:* Dictionary with oid tuples as keys. The values are tuples again,
    where the first element is the value to set as a string and the second parameter a type
    specifiction. The type specification is used to encode the value correctly
    inside the pdu. Have a look here for the possible type specifications.
    https://linux.die.net/man/1/snmpset
    The library takes care to encode the value string according to the type
    specification.

Example:
```python
# Set a new location.
to_set = {
    (1, 3, 6, 1, 2, 1, 1, 1, 0): ('new location', 's')
}

result = session.set_oids(to_set)
```


## Implementation Notes

*Why the patch ?*
gevent_snmp works by replacing the calls to 'select()' inside libnetsnmp.
So if libnetsnmp would call 'select()', gevent.socket.wait_read is called insted.
Per default libnetsnmp does not allow to replace/override the calls to select.
The patch to libnetsnmp just adds another function where the select could be
replaced via a callback.
The advantage of this patch is, that we can still use the synchronous
'high level' API of libnetsnmp. This synchronous 'high levell' is way more
easier to use than the asynchronous 'low level' API.
For example we get retry and timeout handling for free, because the synchronous
'high level' API implements them. Whereas the asynchronous 'low level' API does
not support retry/timeout.

Have a look at netsnmp_patch.diff, its fairly easy and not intrusive at all.
