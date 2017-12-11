# gevent_snmp
Asynchronous SNMP via gevent.

## Introduction

Main characteristics as bullet point list:

* Gives you an 'AsyncSession' object, which works inside a gevent greenlet.
* Very speedy, ~8000 GET requests per second.
* It uses the libnetsnmp.so directly via cython (Cython>=0.21 is required).
* It requires a patched libnetsnmp.so. See implementation notes.
* Uses the "high level" API of libnetsnmp => Easily use the features provided by libnetsnmp.
* Tested with gevent 1.1
* Tested with libnetsnmp 5.7.X

## API

The API does no oid translation for you.
An oid must be given as a tuple of integers.
For example `system.sysDescr.0` must be convertet to `(1, 3, 6, 1, 2, 1, 1, 1, 0)`

The output is always a dictionary containing the varbind list from the response pdu.
This varbind list is converted to a dictionary where the keys are the oids (as
tuples) and the values the corresponding value from the response pdu.

### Create A Session
```python
from async_session import AsyncSession

config = {
    'peername': '127.0.0.1',
    'version': '2c',
    'community': 'public',
    'retries': 5,
    'timeout': 3
}

session = AsyncSession(config)
session.open_session()
```

### oid_str_to_tuple
Converts a oid string of digits into a tuple of integers.

Example:
```python
ret = async_session.oid_str_to_tuple("1.3.6.1.2.1.1.1.0")
assert ret == (1, 3, 6, 1, 2, 1, 1, 1, 0)
```

### oid_tuple_to_str
Converts a tuple of integers to a string with digits and dots.

Example:
```python
ret = async_session.oid_tuple_to_str((1, 3, 6, 1, 2, 1, 1, 1, 0))
assert ret == "1.3.6.1.2.1.1.1.0"
```

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
### Error Handling

The APIs mentioned above may raise the following exceptions.
* SNMPTimeoutError
* SNMPResponseError

#### SNMPTimeoutError
This exception is raised if there is no SNMP-Response within the configured time constraints.

#### SNMPResponseError
This exception is raised if something with the response is wrong. It has the following attributes:
* ```code```: Which is the error status from the response PDU
* ```index```: Which is the error index from the response PDU
* ```message```: String representation of the error

```python
try:
    session.set_oids(to_set)
except SNMPResponseError as error:
    print error.code
    print error.index
    print error.message
```

### Flags
The following methods have an additional ```py_flags``` parameter to control how
the response is parsed. 
* walk
* walk_with_get_bulk
* get
* get_next
* get_bulk

This parameter is a python dictionary which allows the following flags.

#### get_var_type
Each entry in the varbind list of a SNMP response contains ```type``` and ```value```.
Per default the API takes automatically care to convert the value into the
corresponding python object. However it is also possible to get the ```type```
for each entry. Is ```get_var_type``` given and set to ```True``` the value for the returned
dictionary will be a tuple. Where the first element is the ```type``` and the second
element the ```value``` as a python object.

For example:
```python

for oid, (asn_type, asn_value) for session.walk(oid, {'get_var_type': True}).items():
    print oid, asn_type, asn_value
```

#### get_end_of_mib
If given and set to ```True``` each single varbind of type
```SNMP_ENDOFMIBVIEW``` will be encode to the special object
```async_session.END_OF_MIB```. If this flag is not set 'end of mib view'
is converted to ```None```.

#### get_no_such_object
If given and set to ```True``` each single varbind of type
```SNMP_NOSUCHOBJECT:``` will be encode to the special object
```async_session.NO_SUCH_OBJECT```. If this flag is not set 'no such object'
is converted to ```None```.

#### get_no_such_instance
If given and set to ```True``` each single varbind of type
```SNMP_NOSUCHINSTANCE``` will be encode to the special object
```async_session.NO_SUCH_INSTANCE```. If this flag is not set 'no such instance'
is converted to ```None```.

### Clone
Use this call to clone an existing session.
* *Input:* Config options for the new session. Options not mentioned here are
    cloned from the existing session. The overriding options must be given as
    keyword arguments.
* *Output:* Contextmanager which delivers the cloned session.
    For this clone `open_session` has been already called.

Example:
```python
with sess.clone_session(community='private') as priv_sess:
    print priv_sess.set_oids(oids)
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
