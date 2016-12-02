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

## Quick Usage Guide

## Detailed API

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
