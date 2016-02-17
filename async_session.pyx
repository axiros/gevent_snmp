cimport cython
from cython.operator cimport dereference as deref
from libc.stdlib cimport free as libc_free
from posix.time cimport timeval

import gevent
from gevent.socket import wait_read as gevent_wait_read
from gevent.socket import timeout as TimeoutError

ctypedef unsigned char u_char
ctypedef unsigned long oid

ctypedef int (*select_func)(void*, int, void*, void*, void*, timeval*)

cdef extern from "<net-snmp/net-snmp-config.h>":
    pass

cdef extern from "<net-snmp/net-snmp-includes.h>":
    pass

cdef extern from *:
    ## PDU interface ##

    cdef enum:
        SNMP_MSG_GET
        SNMP_MSG_GETNEXT
        SNMP_MSG_GETBULK

        MAX_OID_LEN

    cdef enum:
        ASN_OCTET_STR
        ASN_INTEGER
        ASN_NULL
        ASN_OBJECT_ID
        ASN_BIT_STR
        ASN_IPADDRESS
        ASN_COUNTER
        ASN_GAUGE
        ASN_TIMETICKS
        ASN_COUNTER64
        ASN_APP_FLOAT
        ASN_APP_DOUBLE
        SNMP_ENDOFMIBVIEW

    cdef struct counter64:
        unsigned long high
        unsigned long low

    cdef union netsnmp_vardata:
        long* integer
        u_char* string
        oid* objid
        u_char* bitstring
        counter64* counter64
        float* floatVal
        double* doubleVal

    ctypedef struct netsnmp_variable_list:
        netsnmp_variable_list* next_variable
        oid *name
        size_t name_length
        u_char var_type "type"
        netsnmp_vardata val
        size_t val_len

    ctypedef struct netsnmp_pdu:
        long errstat
        long errindex
        netsnmp_variable_list* variables

    netsnmp_pdu* snmp_pdu_create(int)
    void snmp_add_null_var(netsnmp_pdu*, const oid*, size_t)
    void snmp_free_pdu(netsnmp_pdu*)

    ## Session interface ##
    cdef enum:
        SNMP_VERSION_1
        SNMP_VERSION_2c

    cdef struct netsnmp_transport_s:
        int sock

    ctypedef struct netsnmp_session:
        long version
        int retries
        long timeout
        char* peername
        u_char* community
        size_t community_len
        int s_snmp_errno
        unsigned long flags

    void snmp_sess_init(netsnmp_session*)
    void* snmp_sess_open(netsnmp_session*)
    void snmp_error(netsnmp_session*, int*, int*, char**)

    # Works on the session pointer returned by snmp_sess_open
    int snmp_sess_synch_response(void*, netsnmp_pdu*, netsnmp_pdu**)
    int snmp_sess_synch_response_with_select(
        void *sessp,
        netsnmp_pdu *pdu,
        netsnmp_pdu **response,
        select_func,
        void* ctx)

    netsnmp_transport_s* snmp_sess_transport(void*)
    void snmp_sess_error(void*, int*, int*, char**)
    int snmp_sess_close(void*)

@cython.internal
cdef class EndOfMib(object):
    def __str__(self):
        return "<END_OF_MIB>"

    def __repr__(self):
        return str(self)


END_OF_MIB = EndOfMib()

class SNMPError(Exception):
    pass


cdef object error_from_session(msg, netsnmp_session* session):
    cdef int p_errno
    cdef int p_snmp_errno
    cdef char* error_str

    snmp_error(
        session,
        cython.address(p_errno),
        cython.address(p_snmp_errno),
        cython.address(error_str))

    try:
        return SNMPError("%s: %s" % (msg, error_str))
    finally:
        libc_free(error_str)


cdef object error_from_session_ptr(msg, void* sp):
    cdef int p_errno
    cdef int p_snmp_errno
    cdef char* error_str

    snmp_sess_error(
        sp,
        cython.address(p_errno),
        cython.address(p_snmp_errno),
        cython.address(error_str))

    try:
        return SNMPError("%s: %s" % (msg, error_str))
    finally:
        libc_free(error_str)


cdef int my_select(
    void* ctx,
    int fdnum,
    void* readfds,
    void* writefds,
    void* errorfds,
    timeval* timeout):

    # Error handling:
    # If there is an exception in gevent_wait_read I CAN NOT just 'return -1'.
    # It looks like netsnmp has a memory leak if 'select()' fails.
    # Sometimes netsnmp frees the request pdu on error and sometimes not. And
    # the user of the API has no chance to know if its already freed or not.
    # So I can choose between memory leak or double free.

    # For that reason I tell netsnmp that a timeout has happend.
    # To still get the error message, the 'async_session' object has a variable
    # called 'error_in_my_select'. As soon as this is not None an exception
    # happend in 'gevent_wait_read' => The collection will fail.

    cdef AsyncSession async_session = <AsyncSession>(ctx)
    cdef int sock = snmp_sess_transport(async_session.sp).sock
    py_timeout = timeout.tv_sec + (<double>(timeout.tv_usec) / 10**6)

    # As soon as error_in_my_select don't wait for the socket.
    # Return 0, which means timeout has happend
    # Need to sleep, otherwise netsnmp calls select in a busy loop
    if async_session.error_in_my_select is not None:
        try:
            gevent.sleep(py_timeout)
        except Exception:
            pass
        return 0

    try:
        gevent_wait_read(sock, py_timeout)
    except TimeoutError:
        return 0
    except Exception as error:
        # As said above, tell netsnmp a timeout happend, but keep the error.
        async_session.error_in_my_select = error
        return 0
    else:
        return 1


@cython.final
cdef class AsyncSession(object):
    # Need to keep a reference to the used strings like community and peername.
    cdef object args

    # Pointer to the snmp session object created via snmp_sess_open.
    cdef void* sp

    # If my_select raises an excpetion, keep the latest here.
    cdef object error_in_my_select

    def __cinit__(self, args):
        self.sp = NULL

    def __dealloc__(self):
        if self.sp != NULL:
            snmp_sess_close(self.sp)

    def __init__(self, args):
        self.args = args
        self.error_in_my_select = None

    def open_session(self):
        cdef netsnmp_session sess_cfg

        snmp_sess_init(cython.address(sess_cfg))

        sess_cfg.community = <bytes?>(self.args['community'])
        sess_cfg.community_len = len(self.args['community'])
        sess_cfg.peername = <bytes?>(self.args['peername'])
        sess_cfg.retries = self.args['retries']
        sess_cfg.timeout = self.args['timeout'] * 1000000
        sess_cfg.flags |= 0x100000

        if self.args['version'] == '1':
            sess_cfg.version = SNMP_VERSION_1
        elif self.args['version'] == '2c':
            sess_cfg.version = SNMP_VERSION_2c
        else:
            raise Exception("Unkown snmp version: %s" % self.args['version'])

        self.sp = snmp_sess_open(cython.address(sess_cfg))
        if self.sp == NULL:
            raise error_from_session("Can not open", cython.address(sess_cfg))

    ## These are 'higher level' functions.
    def walk(self, root):
        """Walks a tree by succesive calling get_next."""
        final_result = {}
        oid = root

        while True:
            result = self.get_next(oid)
            oid = self._handle_walk_result(root, oid, result, final_result)
            if oid is None:
                return final_result


    def walk_with_get_bulk(self, root, maxrepetitions=10):
        """Walks a *single* subtree by succesive calling get_bulk.

        It does not walk multiple columns at the same time, its just are more
        effienct implementation of walk() =>
        The API (input params and output) is nearly identical to walk()
        """
        final_result = {}
        oid = root

        while True:
            result = self.get_bulk([oid], 0, maxrepetitions)
            oid = self._handle_walk_result(root, oid, result, final_result)
            if oid is None:
                return final_result

    # This is the private API for the 'high level' calls.
    cdef _handle_walk_result(self, root, prev_oid, result, final_result):
        """Handles the results for walks.

        Adds (oid, value) pairs from result to final_result
        It returns the 'next' oid to query on.
        It returns None if processing should stop
        """

        if not result:
            return None

        for next_oid, value in sorted(result.items()):
            if next_oid == prev_oid:
                return None

            if value is END_OF_MIB:
                return None

            if not self._is_in_subtree(root, next_oid):
                return None

            final_result[next_oid] = value

        return next_oid

    ## These are the 'low level' snmp functions.
    def get(self, oids):
        cdef netsnmp_pdu* req = snmp_pdu_create(SNMP_MSG_GET)
        for py_oid in oids:
            self._add_oid(req, py_oid)
        return self._do_snmp(req)

    def get_next(self, py_oid):
        cdef netsnmp_pdu* req = snmp_pdu_create(SNMP_MSG_GETNEXT)
        self._add_oid(req, py_oid)
        return self._do_snmp(req)

    def get_bulk(self, oids, nonrepeaters=0, maxrepetitions=10):
        cdef netsnmp_pdu* req = snmp_pdu_create(SNMP_MSG_GETBULK)
        req.errstat = nonrepeaters
        req.errindex = maxrepetitions
        for py_oid in oids:
            self._add_oid(req, py_oid)
        return self._do_snmp(req)

    ## This is private API for the 'low level' calls.
    cdef _is_in_subtree(self, root, oid):
        if len(oid) < len(root):
            return False

        for index in range(len(root)):
            if root[index] != oid[index]:
                return False
        return True

    cdef _do_snmp(self, netsnmp_pdu* req):
        if self.sp == NULL:
            snmp_free_pdu(req)
            raise SNMPError("Session is not open")

        cdef netsnmp_pdu* response
        self.error_in_my_select = None

        cdef int rc = snmp_sess_synch_response_with_select(
            self.sp,
            req,
            cython.address(response),
            my_select,
            <void*>self)

        if rc == 0:
            try:
                return self.parse_response(response)
            finally:
                snmp_free_pdu(response)

        elif self.error_in_my_select is not None:
            raise SNMPError("Error in query: %s" % self.error_in_my_select)

        else:
            raise error_from_session_ptr("Error in query", self.sp)

    cdef _add_oid(self, netsnmp_pdu* req, object py_oid):
        cdef oid param[MAX_OID_LEN]
        cdef size_t param_size = len(py_oid)
        for index, value in enumerate(py_oid):
            param[index] = value

        snmp_add_null_var(req, param, param_size)

    cdef object parse_response(self, netsnmp_pdu* response):
        cdef netsnmp_variable_list* entry = NULL
        cdef dict parsed = {}

        entry = response.variables
        while (entry != NULL):
            key = tuple([int(entry.name[i]) for i in range(entry.name_length)])
            value = self.parse_var(entry)
            parsed[key] = value
            entry = entry.next_variable

        return parsed

    cdef object parse_var(self, netsnmp_variable_list* var):
        if var.var_type == ASN_OCTET_STR:
            return var.val.string[:var.val_len]

        elif var.var_type == ASN_INTEGER:
            return deref(var.val.integer)

        elif var.var_type == ASN_NULL:
            return None

        elif var.var_type == ASN_OBJECT_ID:
            return [var.val.objid[i] for i in range(var.val_len / cython.sizeof(oid))]

        elif var.var_type == ASN_BIT_STR:
            return var.val.bitstring[:var.val_len]

        elif var.var_type == ASN_IPADDRESS:
            return '.'.join([str(ord(x)) for x in var.val.bitstring[:4]])

        elif var.var_type == ASN_COUNTER:
            return deref(var.val.integer)

        elif var.var_type == ASN_GAUGE:
            return deref(var.val.integer)

        elif var.var_type == ASN_TIMETICKS:
            return deref(var.val.integer)

        elif var.var_type == ASN_COUNTER64:
            return (long(var.val.counter64.high) << 32L) + var.val.counter64.low

        elif var.var_type == ASN_APP_FLOAT:
            return deref(var.val.floatVal)

        elif var.var_type == ASN_APP_DOUBLE:
            return deref(var.val.doubleVal)

        elif var.var_type == SNMP_ENDOFMIBVIEW:
            return END_OF_MIB

        else:
            return None
