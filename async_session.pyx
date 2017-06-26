cimport cython
from cython.operator cimport dereference as deref
from libc.stdlib cimport free as libc_free
from posix.time cimport timeval
from libc.stdint cimport uint64_t

import gevent
from gevent.socket import wait_read as gevent_wait_read
from gevent.socket import timeout as TimeoutError

ctypedef unsigned int u_int
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
        SNMP_MSG_SET

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
    int snmp_add_var(netsnmp_pdu*, const oid*, size_t, char, const char*)
    void snmp_free_pdu(netsnmp_pdu*)

    ## Session interface ##
    cdef enum:
        SNMP_VERSION_1
        SNMP_VERSION_2c
        SNMP_VERSION_3

    # V3 related defines.
    cdef enum:
        SNMP_SEC_LEVEL_NOAUTH
        SNMP_SEC_LEVEL_AUTHNOPRIV
        SNMP_SEC_LEVEL_AUTHPRIV
        SNMP_SEC_MODEL_USM
        SNMP_FLAGS_DONT_PROBE

    # V3 related constats.
    cdef oid* usmHMACMD5AuthProtocol
    cdef size_t USM_AUTH_PROTO_MD5_LEN
    cdef oid* usmHMACSHA1AuthProtocol
    cdef size_t USM_AUTH_PROTO_SHA_LEN
    cdef oid* usmDESPrivProtocol
    cdef size_t USM_PRIV_PROTO_DES_LEN
    cdef oid* usmAESPrivProtocol
    cdef size_t USM_PRIV_PROTO_AES_LEN
    cdef size_t USM_AUTH_KU_LEN
    cdef size_t USM_PRIV_KU_LEN

    cdef struct netsnmp_transport_s:
        int sock
        unsigned int flags

    ctypedef struct netsnmp_session:
        long version
        int retries
        long timeout
        char* peername
        u_char* community
        size_t community_len
        int s_snmp_errno
        unsigned long flags

        # v3 security options
        int securityModel
        int securityLevel
        char* securityName
        size_t securityNameLen

        oid* securityAuthProto
        size_t securityAuthProtoLen
        oid* securityPrivProto
        size_t securityPrivProtoLen

        u_char* securityAuthKey
        size_t securityAuthKeyLen
        u_char* securityPrivKey
        size_t securityPrivKeyLen

        u_char* securityEngineID
        size_t securityEngineIDLen

        u_char* contextEngineID
        size_t contextEngineIDLen


    # v3 functions -- start
    cdef int SNMPERR_SUCCESS

    int generate_Ku(
        # hashtype
        const oid *,
        # hashtype_len
        u_int,
        # password
        u_char*,
        # password len
        size_t,
        # KU
        u_char*,
        # KU len
        size_t*)

    u_int binary_to_hex(u_char*, size_t, char**)
    int hex_to_binary2(u_char*, size_t, char**)

    # v3 functions -- end

    void snmp_sess_init(netsnmp_session*)
    void* snmp_sess_open(netsnmp_session*)
    void snmp_error(netsnmp_session*, int*, int*, char**)

    # Works on the session pointer returned by snmp_sess_open
    int snmp_sess_synch_response(void*, netsnmp_pdu*, netsnmp_pdu**)
    int snmp_sess_synch_response_with_select(
        void* sessp,
        netsnmp_pdu *pdu,
        netsnmp_pdu **response,
        select_func,
        void* ctx)

    # 0: error
    # 1: ok
    int snmpv3_engineID_probe_with_select(
        void* sessp,
        netsnmp_session* in_session,
        select_func,
        void* ctx)

    netsnmp_transport_s* snmp_sess_transport(void*)
    netsnmp_session* snmp_sess_session(void*)
    void snmp_sess_error(void*, int*, int*, char**)
    int snmp_sess_close(void*)
    const char* snmp_errstring(int)
    const char* snmp_api_errstring(int snmp_errnumber)

    void init_snmp(char*)

    cdef enum:
        STAT_SUCCESS
        SNMP_ERR_NOERROR
        SNMPERR_TIMEOUT


# SNMP version 3 works only if this method is called once.
# Otherwise you get 'no such security service available' errors.
def init_snmplib():
    init_snmp('async_session')


@cython.internal
cdef class EndOfMib(object):
    def __str__(self):
        return "<END_OF_MIB>"

    def __repr__(self):
        return str(self)


END_OF_MIB = EndOfMib()

class SNMPError(Exception):
    pass

class SNMPTimeoutError(SNMPError):
    pass

class SNMPResponseError(SNMPError):
    def __init__(self, code, message):
        self.code = code
        super(SNMPResponseError, self).__init__("%s: %s" % (code, message))


def oid_str_to_tuple(oid_str):
    """Converts a string like '1.2.3' to a tuple of integers like (1, 2, 3)"""
    return tuple([int(idx) for idx in oid_str.split('.')])


def oid_tuple_to_str(oid_tuple):
    """Converts a tuple of integers like (1, 2, 3) to a sting like '1.2.3'"""
    return '.'.join(map(str, oid_tuple))


# These are the type specifications allowed by 'snmp_add_var'
# 'snmp_add_var' reads all the values as a *string* and parses them.
# shortcout, long name, (C type, ASN type)
# 'i'  'INTEGER' (long, ASN_INTEGER)
# 'u'  'Unsigned32' (unsigned long, ASN_UNSIGNED)
# '3'  'UInteger32' (unsigned long, ASN_UINTEGER)
# 'c'  'Counter32'  (unsigned long, ASN_COUNTER)
# 'C'  'Counter64'  (struct, ASN_COUNTER64)
# 't'  'TimeTicks'  (unsigned long, ASN_TIMETICKS)
# 'a'  'IpAddress'  (struct,  ASN_IPADDRESS) => Ip as string is parsed
# 'o'  'Object'     (oid, ASN_OBJECT_ID)
# 's'  'Octet str'  (char*, ASN_OCTET_STR)
# 'd'  'decimal'    (..., ASN_OCTET_STR) => decimal number is parsed
# 'x'  'hex'        (..., ASN_OCTET_STR) => hex string is parsed
# 'n'  'null'       (..., ASN_NULL)
# 'b'  'Bits'       (..., ASN_OCTET_STR)
# 'U'               (struct, ASN_OPAQUE_U64
# 'I'               (struct, ASN_OPAQUE_I64
# 'F'               (float, ASN_OPAQUE_FLOAT)
# 'D'               (double, ASN_OPAQUE_DOUBLE)


VALID_VALUE_TYPES = set('iu3cCtaosdxnbUIFD')
VALUE_TYPE_TO_INT = {key: ord(key) for key in VALID_VALUE_TYPES}


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
        if p_snmp_errno == SNMPERR_TIMEOUT:
            return SNMPTimeoutError("%s: %s" % (msg, error_str))
        else:
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
        if p_snmp_errno == SNMPERR_TIMEOUT:
            return SNMPTimeoutError("%s: %s" % (msg, error_str))
        else:
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

    # Counts how many SNMP interactions/packets were done on this session.
    cdef uint64_t query_count

    def __cinit__(self, args):
        self.sp = NULL
        self.query_count = 0

    def __dealloc__(self):
        if self.sp != NULL:
            snmp_sess_close(self.sp)

    def __init__(self, args):
        self.args = args
        self.error_in_my_select = None

    # Read only access to snmp_interactions
    property snmp_query_count:
        def __get__(self):
            return self.query_count

    # Returns the securityEngineID as hex.
    # Returns None if the id is not present.
    property security_engine_id:
        def __get__(self):
            if self.sp == NULL:
                return None

            if snmp_sess_session(self.sp).securityEngineIDLen == 0:
                return None

            return binary_to_hex_pystring(
                snmp_sess_session(self.sp).securityEngineID,
                snmp_sess_session(self.sp).securityEngineIDLen)

    # Returns the contextEngineID as hex.
    # Returns None if the id is not present.
    property context_engine_id:
        def __get__(self):
            if self.sp == NULL:
                return None

            if snmp_sess_session(self.sp).contextEngineIDLen == 0:
                return None

            return binary_to_hex_pystring(
                snmp_sess_session(self.sp).contextEngineID,
                snmp_sess_session(self.sp).contextEngineIDLen)

    def open_session(self):
        cdef netsnmp_session sess_cfg

        snmp_sess_init(cython.address(sess_cfg))

        sess_cfg.peername = <bytes?>(self.args['peername'])
        sess_cfg.retries = self.args['retries']
        sess_cfg.timeout = self.args['timeout'] * 1000000
        # Ignores the fd_set within the snmp-api.
        sess_cfg.flags |= 0x100000

        if self.args['version'] == '1':
            sess_cfg.version = SNMP_VERSION_1
            self._set_community(cython.address(sess_cfg))

        elif self.args['version'] == '2c':
            sess_cfg.version = SNMP_VERSION_2c
            self._set_community(cython.address(sess_cfg))

        elif self.args['version'] == '3':
            sess_cfg.version = SNMP_VERSION_3
            self._set_version_three_auth(cython.address(sess_cfg))

        else:
            raise Exception("Unkown snmp version: %s" % self.args['version'])

        # snmpV3 needs an engineID to work.
        # Typically this engineID is not known => seperate 'probe' query needed
        # Per default the netsnmp library does this 'probe' on its own.
        # Unfortunately this implicit probe by the netsnmp library happens
        # *synchronous*, => A single probe in one session could block the WHOLE
        # gevent event-loop.
        # The following code avoids the implicit synchronous probe, instead we
        # do a ASYNChronous probe ourself.

        # Forbid probing in snmp_sess_open (has no effect on v1 or v2c).
        sess_cfg.flags |= SNMP_FLAGS_DONT_PROBE

        self.sp = snmp_sess_open(cython.address(sess_cfg))
        if self.sp == NULL:
            raise error_from_session("Can not open", cython.address(sess_cfg))

        # Ignores the fd_set within the snmp-api.
        snmp_sess_transport(self.sp).flags |= 0x100000

        if sess_cfg.version == SNMP_VERSION_3 and sess_cfg.securityEngineIDLen == 0:
            # engine_id is not known, probe it.
            self._do_snmpv3_engine_id_probe(cython.address(sess_cfg))

    cdef _set_community(self, netsnmp_session* sess_cfg):
        sess_cfg.community = <bytes?>(self.args['community'])
        sess_cfg.community_len = len(self.args['community'])

    cdef _set_version_three_auth(self, netsnmp_session* sess_cfg):
        cdef int res = 0
        # For V3 the USM model is used.
        sess_cfg.securityModel = SNMP_SEC_MODEL_USM

        # Configure one of the three types of security supported.
        security_level = self.args['security_level']
        if security_level == 'noAuthNoPriv':
            sess_cfg.securityLevel = SNMP_SEC_LEVEL_NOAUTH
        elif security_level == 'authNoPriv':
            sess_cfg.securityLevel = SNMP_SEC_LEVEL_AUTHNOPRIV
        elif security_level == 'authPriv':
            sess_cfg.securityLevel = SNMP_SEC_LEVEL_AUTHPRIV
        else:
            raise Exception("Unknown security_level: %s" % security_level)

        # Username is mandatory.
        sess_cfg.securityName = <bytes?>(self.args['security_name'])
        sess_cfg.securityNameLen = len(self.args['security_name'])

        # If auth is used, the protocol must be given.
        if security_level == 'authNoPriv' or security_level == 'authPriv':
            auth_proto = self.args['auth_proto']
            if auth_proto == 'MD5':
                sess_cfg.securityAuthProto = usmHMACMD5AuthProtocol
                sess_cfg.securityAuthProtoLen = USM_AUTH_PROTO_MD5_LEN
            elif auth_proto == 'SHA':
                sess_cfg.securityAuthProto = usmHMACSHA1AuthProtocol
                sess_cfg.securityAuthProtoLen = USM_AUTH_PROTO_SHA_LEN
            else:
                raise Exception("Unknown auth protocol: %s" % auth_proto)

            sess_cfg.securityAuthKeyLen = USM_AUTH_KU_LEN
            res = generate_Ku(
                    sess_cfg.securityAuthProto,
                    sess_cfg.securityAuthProtoLen,
                    <bytes?>(self.args['auth_key']),
                    len(self.args['auth_key']),
                    sess_cfg.securityAuthKey,
                    cython.address(sess_cfg.securityAuthKeyLen))

            if res != SNMPERR_SUCCESS:
                raise Exception("Can't generate KU for auth_key: %i" % res)

        # if priv is used, the protocol must be given.
        if security_level == 'authPriv':
            priv_proto = self.args['priv_proto']
            if priv_proto == 'DES':
                sess_cfg.securityPrivProto = usmDESPrivProtocol
                sess_cfg.securityPrivProtoLen = USM_PRIV_PROTO_DES_LEN
            elif priv_proto == 'AES':
                sess_cfg.securityPrivProto = usmAESPrivProtocol
                sess_cfg.securityPrivProtoLen = USM_PRIV_PROTO_AES_LEN
            else:
                raise Exception("Unknown priv protocol: %s" % priv_proto)

            sess_cfg.securityPrivKeyLen = USM_PRIV_KU_LEN
            res = generate_Ku(
                    sess_cfg.securityAuthProto,
                    sess_cfg.securityAuthProtoLen,
                    <bytes?>(self.args['priv_key']),
                    len(self.args['priv_key']),
                    sess_cfg.securityPrivKey,
                    cython.address(sess_cfg.securityPrivKeyLen))

            if res != SNMPERR_SUCCESS:
                raise Exception("Can't generate KU for priv_key: %i" % res)

        # security_engine_id is assumed as 'hex' format, but binary is needed.
        if 'security_engine_id' in self.args:
            bin_val = self.args['security_engine_id'].decode('hex')
            # Need to store it somewhere, to keep reference to memory.
            self.args['security_engine_id_binary'] = bin_val
            sess_cfg.securityEngineID = <bytes?>(bin_val)
            sess_cfg.securityEngineIDLen = len(bin_val)

        # context_engine_id is assumed as 'hex' format, but binary is needed.
        if 'context_engine_id' in self.args:
            bin_val = self.args['context_engine_id'].decode('hex')
            self.args['context_engine_id_binary'] = bin_val
            sess_cfg.contextEngineID = <bytes?>(bin_val)
            sess_cfg.contextEngineIDLen = len(bin_val)

    cdef _do_snmpv3_engine_id_probe(self, netsnmp_session* sess_cfg):
        cdef int res = 0

        # Ensure that probe is enabled.
        snmp_sess_session(self.sp).flags &= (~SNMP_FLAGS_DONT_PROBE)
        res = snmpv3_engineID_probe_with_select(
            self.sp,
            sess_cfg,
            my_select,
            <void*>(self))

        if res == 0:
            raise error_from_session("Cannot probe v3 engineID", sess_cfg)

        # Probe was successful, don't do it again.
        snmp_sess_session(self.sp).flags |= SNMP_FLAGS_DONT_PROBE

    def clone_session(self, **override_args):
        return CloneSession(self, override_args)

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

    def set_oids(self, oids):
        cdef netsnmp_pdu* req = snmp_pdu_create(SNMP_MSG_SET)

        try:
            for py_oid, (value, value_type) in oids.iteritems():
                self._add_oid_set(req, py_oid, value, value_type)
        except Exception:
            snmp_free_pdu(req)
            raise
        else:
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

        self.query_count += 1
        cdef int rc = snmp_sess_synch_response_with_select(
            self.sp,
            req,
            cython.address(response),
            my_select,
            <void*>self)

        if rc == STAT_SUCCESS:
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

    cdef object _add_oid_set(self, netsnmp_pdu* req, py_oid, val, val_type):
        cdef int rc
        cdef char c_val_type
        cdef oid param[MAX_OID_LEN]
        cdef size_t param_size = len(py_oid)
        for index, value, in enumerate(py_oid):
            param[index] = value

        if not val_type in VALUE_TYPE_TO_INT:
            raise Exception("Unknown value type '%s'" % val_type)

        c_val_type = VALUE_TYPE_TO_INT[val_type]

        rc = snmp_add_var(req, param, param_size, c_val_type, val)
        if rc != 0:
            msg = "Cannot set oid(%s) with val(%s) and type(%s): %s"
            raise Exception(msg % (py_oid, val, val_type, snmp_api_errstring(rc)))

    cdef object parse_response(self, netsnmp_pdu* response):
        cdef netsnmp_variable_list* entry = NULL
        cdef dict parsed = {}

        if not (response.errstat == SNMP_ERR_NOERROR):
            raise SNMPResponseError(
                response.errstat,
                snmp_errstring(response.errstat))

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


cdef object binary_to_hex_pystring(u_char* data, size_t data_size):
    cdef char* output
    cdef u_int hex_len = binary_to_hex(data, data_size, cython.address(output))
    try:
        return output[:hex_len]
    finally:
        libc_free(output)


@cython.final
@cython.internal
cdef class CloneSession(object):
    cdef object args
    cdef object session

    def __cinit__(self, AsyncSession other_session, args):
        new_args = other_session.args.copy()
        new_args.update(args)

        self.args = new_args
        self.session = None

    def __enter__(self):
        self.session = AsyncSession(self.args)
        self.session.open_session()
        return self.session

    def __exit__(self, exc_type, exc_value, traceback):
        # Close is triggered via garbage collector.
        self.session = None
