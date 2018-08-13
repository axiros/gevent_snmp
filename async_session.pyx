cimport cython
from cython.operator cimport dereference as deref
from libc.stdlib cimport free as libc_free
from posix.time cimport timeval
from libc.stdint cimport uint64_t
from libc.errno cimport EAGAIN
from cpython.dict cimport PyDict_Size
from cpython.bytes cimport PyBytes_FromStringAndSize

import gevent
from gevent.socket import wait_read as gevent_wait_read
from gevent.socket import wait_write as gevent_wait_write
from gevent.socket import timeout as TimeoutError
from collections import OrderedDict

ctypedef unsigned int u_int
ctypedef unsigned char u_char
ctypedef unsigned long oid

ctypedef int (*select_func)(void*, timeval*)
cdef struct ax_async_ctx_t:
    select_func func
    void* ctx

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
        SNMP_NOSUCHOBJECT
        SNMP_NOSUCHINSTANCE

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

        ax_async_ctx_t* myvoid


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

    # 0: error
    # 1: ok
    int snmpv3_engineID_probe(void*, netsnmp_session*)

    netsnmp_transport_s* snmp_sess_transport(void*)
    netsnmp_session* snmp_sess_session(void*)
    void snmp_sess_error(void*, int*, int*, char**)
    int snmp_sess_close(void*)
    const char* snmp_errstring(int)
    const char* snmp_api_errstring(int snmp_errnumber)

    void init_snmp(char*)

    # varbind API
    int snprint_value(
        char *buf,
        size_t buf_len,
        const oid * objid,
        size_t objidlen,
        const netsnmp_variable_list * variable)


    int sprint_realloc_value(
        u_char ** buf,
        size_t * buf_len,
        size_t * out_len,
        int allow_realloc,
        const oid * objid,
        size_t objidlen,
        const netsnmp_variable_list * variable)

    void* snmp_out_toggle_options(char *options)

    cdef enum:
        STAT_SUCCESS
        SNMP_ERR_NOERROR
        SNMPERR_TIMEOUT
        SNMPERR_BAD_SENDTO


# SNMP version 3 works only if this method is called once.
# Otherwise you get 'no such security service available' errors.
# It is also needed to format values according to MIB,
# because it loads all the MIBS.
def init_snmplib():
    init_snmp('async_session')


def toggle_netsnmp_format_options(options):
    for opt in options:
        if snmp_out_toggle_options(opt) != NULL:
            raise Exception("Option (%s) is not a valid format option" % opt)


@cython.internal
cdef class EndOfMib(object):
    def __str__(self):
        return "<END_OF_MIB>"

    def __repr__(self):
        return str(self)

@cython.internal
cdef class NoSuchObject(object):
    def __str__(self):
        return "<No Such Object>"

    def __repr__(self):
        return str(self)


@cython.internal
cdef class NoSuchInstance(object):
    def __str__(self):
        return "<No Such Instance>"

    def __repr__(self):
        return str(self)




END_OF_MIB = EndOfMib()
NO_SUCH_OBJECT = NoSuchObject()
NO_SUCH_INSTANCE = NoSuchInstance()

class SNMPError(Exception):
    pass

class SNMPTimeoutError(SNMPError):
    pass

class SNMPResponseError(SNMPError):
    def __init__(self, code, index, message):
        self.code = code
        self.index = index
        super(SNMPResponseError, self).__init__(
            "Error at index(%s) with code(%s): %s" % (index, code, message))


@cython.internal
cdef class WriteWouldBlock(Exception):
    pass


def oid_str_to_tuple(oid_str):
    """Converts a string like '1.2.3' to a tuple of integers like (1, 2, 3)"""
    return tuple([int(idx) for idx in oid_str.split('.')])


def oid_tuple_to_str(oid_tuple):
    """Converts a tuple of integers like (1, 2, 3) to a sting like '1.2.3'"""
    return '.'.join(map(str, oid_tuple))

cpdef is_in_subtree(root, oid):
    if len(oid) < len(root):
        return False

    for index in range(len(root)):
        if root[index] != oid[index]:
            return False
    return True

# These are the type specifications allowed by 'snmp_add_var'
# 'snmp_add_var' reads all the values as a *string* and parses them.
# shortcout, long name, (C type, ASN type, alias)
# 'i'  'INTEGER'    (long, ASN_INTEGER)
# 'u'  'Unsigned32' (unsigned long, ASN_UNSIGNED, TYPE_GAUGE)
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

VAR_TYPE_TO_STRING = {
    ASN_OCTET_STR: "OCTET_STR",
    ASN_INTEGER: "INTEGER",
    ASN_NULL: "NULL",
    ASN_OBJECT_ID: "OBJECT_ID",
    ASN_BIT_STR: "BIT_STR",
    ASN_IPADDRESS: "IPADDRESS",
    ASN_COUNTER: "COUNTER",
    ASN_GAUGE: "GAUGE",
    ASN_TIMETICKS: "TIMETICKS",
    ASN_COUNTER64: "COUNTER64",
    ASN_APP_FLOAT: "APP_FLOAT",
    ASN_APP_DOUBLE: "APP_DOUBLE"
}


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
        NULL)

    if p_snmp_errno == SNMPERR_BAD_SENDTO and p_errno == EAGAIN:
        return WriteWouldBlock()

    # Only construct the error string if needed.
    snmp_sess_error(sp, NULL, NULL, cython.address(error_str))

    try:
        if p_snmp_errno == SNMPERR_TIMEOUT:
            return SNMPTimeoutError("%s: %s" % (msg, error_str))
        else:
            return SNMPError("%s: %s" % (msg, error_str))
    finally:
        libc_free(error_str)


cdef int my_select(void* ctx, timeval* timeout):

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

    cdef ax_async_ctx_t ax_async_ctx

    def __cinit__(self, args):
        self.sp = NULL
        self.query_count = 0

    def __dealloc__(self):
        if self.sp != NULL:
            snmp_sess_close(self.sp)

    def __init__(self, args):
        self.args = args
        self.error_in_my_select = None

        self.ax_async_ctx.func = my_select
        self.ax_async_ctx.ctx = <void*>(self)

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

        # Uses the 'async select' from session->myvoid.
        sess_cfg.flags |= 0x200000

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

        snmp_sess_session(self.sp).myvoid = cython.address(self.ax_async_ctx)

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
        res = snmpv3_engineID_probe(self.sp, sess_cfg)

        if res == 0:
            raise error_from_session("Cannot probe v3 engineID", sess_cfg)

        # Probe was successful, don't do it again.
        snmp_sess_session(self.sp).flags |= SNMP_FLAGS_DONT_PROBE

    def clone_session(self, **override_args):
        return CloneSession(self, override_args)

    ## These are 'higher level' functions.
    def walk(self, root, py_flags={}):
        """Walks a tree by succesive calling get_next."""
        cdef uint64_t flags = AsyncSession.gen_flags(py_flags)
        final_result = {}
        oid = root

        while True:
            oid = self._handle_walk_result(
                self._send_getnext(oid),
                root,
                oid,
                final_result,
                flags)

            if oid is None:
                return final_result

    def walk_with_get_bulk(self, root, maxrepetitions=10, py_flags={}):
        """Walks a *single* subtree by succesive calling get_bulk.

        It does not walk multiple columns at the same time, its just are more
        effienct implementation of walk() =>
        The API (input params and output) is nearly identical to walk()
        """
        cdef uint64_t flags = AsyncSession.gen_flags(py_flags)
        final_result = {}
        oid = root

        while True:
            oid = self._handle_walk_result(
                self._send_getbulk([oid], 0, maxrepetitions),
                root,
                oid,
                final_result,
                flags)

            if oid is None:
                return final_result

    # This is the private API for the 'high level' calls.
    cdef _handle_walk_result(
            self,
            netsnmp_pdu* response,
            root,
            prev_oid,
            final_result,
            uint64_t flags):
        """Handles the results for walks.

        Adds (oid, value) pairs from result to final_result
        It returns the 'next' oid to query on.
        It returns None if processing should stop
        """

        next_oid = None
        cdef netsnmp_variable_list* entry = NULL

        try:
            self._raise_on_response_error(response)
            entry = response.variables
            while (entry != NULL):
                next_oid = self.parse_var_key(entry)
                if next_oid == prev_oid:
                    return None

                if entry.var_type == SNMP_ENDOFMIBVIEW:
                    return None

                if not is_in_subtree(root, next_oid):
                    return None

                final_result[next_oid] = self._parse_varbind(entry, flags)
                entry = entry.next_variable

            return next_oid

        finally:
            snmp_free_pdu(response)

    ## These are the 'low level' snmp functions.
    def get(self, oids, py_flags={}):
        cdef uint64_t flags = AsyncSession.gen_flags(py_flags)

        try:
            response = self._send_req(self._gen_get_pdu(oids))
            return self._handle_response(response, flags)
        except WriteWouldBlock:
            self._wait_for_write()
            response = self._send_req(self._gen_get_pdu(oids))
            return self._handle_response(response, flags)

    def get_next(self, py_oid, py_flags={}):
        cdef uint64_t flags = AsyncSession.gen_flags(py_flags)
        response = self._send_getnext(py_oid)
        return self._handle_response(response, flags)

    def get_bulk(
            self,
            oids,
            nonrepeaters=0,
            maxrepetitions=10,
            py_flags={}):

        cdef uint64_t flags = AsyncSession.gen_flags(py_flags)
        response = self._send_getbulk(oids, nonrepeaters, maxrepetitions)
        return self._handle_response(response, flags)

    def set_oids(self, oids, py_flags={}):
        cdef uint64_t flags = AsyncSession.gen_flags(py_flags)

        try:
            response = self._send_req(self._gen_set_pdu(oids))
            return self._handle_response(response, flags)
        except WriteWouldBlock:
            response = self._send_req(self._gen_set_pdu(oids))
            return self._handle_response(response, flags)

    ## Handling the flags
    @staticmethod
    cdef uint64_t gen_flags(dict py_flags) except -1:
        cdef uint64_t flags = 0

        if not PyDict_Size(py_flags):
            return flags

        if py_flags.get('get_var_type'):
            flags = AsyncSession.set_get_vartype(flags)

        if py_flags.get('get_end_of_mib'):
            flags = AsyncSession.set_get_endofmib(flags)

        if py_flags.get('get_no_such_object'):
            flags = AsyncSession.set_get_nosuchobject(flags)

        if py_flags.get('get_no_such_instance'):
            flags = AsyncSession.set_get_nosuchinstance(flags)

        if py_flags.get('as_ordered_dict'):
            flags = AsyncSession.set_as_ordered_dict(flags)

        if py_flags.get('get_netsnmp_string'):
            flags = AsyncSession.set_get_netsnmp_string(flags)

        return flags

    # If the return value should have the low level ASN type included
    @staticmethod
    cdef inline uint64_t set_get_vartype(uint64_t flags):
        return flags | (1 << 0)

    @staticmethod
    cdef inline uint64_t get_get_vartype(uint64_t flags):
        return flags & (1 << 0)

    # If we return the EndOfMib object or None
    @staticmethod
    cdef inline uint64_t set_get_endofmib(uint64_t flags):
        return flags | (1 << 1)

    @staticmethod
    cdef inline uint64_t get_get_endofmib(uint64_t flags):
        return flags & (1 << 1)

    # If we return the NoSuchObject object or None
    @staticmethod
    cdef inline uint64_t set_get_nosuchobject(uint64_t flags):
        return flags | (1 << 2)

    @staticmethod
    cdef inline uint64_t get_get_nosuchobject(uint64_t flags):
        return flags & (1 << 2)

    # If we return the NoSuchInstance object or None
    @staticmethod
    cdef inline uint64_t set_get_nosuchinstance(uint64_t flags):
        return flags | (1 << 3)

    @staticmethod
    cdef inline uint64_t get_get_nosuchinstance(uint64_t flags):
        return flags & (1 << 3)

    # If the results should be ordered
    @staticmethod
    cdef inline uint64_t set_as_ordered_dict(uint64_t flags):
        return flags | (1 << 4)

    @staticmethod
    cdef inline uint64_t get_as_ordered_dict(uint64_t flags):
        return flags & (1 << 4)

    # If the values should be formated by netsnmp
    @staticmethod
    cdef inline uint64_t set_get_netsnmp_string(uint64_t flags):
        return flags | (1 << 5)

    @staticmethod
    cdef inline uint64_t get_get_netsnmp_string(uint64_t flags):
        return flags & (1 << 5)

    ## This is private API for the 'low level' calls.
    cdef netsnmp_pdu* _gen_get_pdu(self, oids) except NULL:
        cdef netsnmp_pdu* req = snmp_pdu_create(SNMP_MSG_GET)
        if req == NULL:
            raise MemoryError()

        for py_oid in oids:
            self._add_oid(req, py_oid)
        return req

    cdef netsnmp_pdu* _send_getnext(self, py_oid) except NULL:
        try:
            return self._send_req(self._gen_getnext_pdu(py_oid))
        except WriteWouldBlock:
            self._wait_for_write()
            return self._send_req(self._gen_getnext_pdu(py_oid))

    cdef netsnmp_pdu* _gen_getnext_pdu(self, py_oid) except NULL:
        cdef netsnmp_pdu* req = snmp_pdu_create(SNMP_MSG_GETNEXT)
        if req == NULL:
            raise MemoryError()

        self._add_oid(req, py_oid)
        return req

    cdef netsnmp_pdu* _send_getbulk(self, oids, nonrepeaters, maxrepetitions) except NULL:
        try:
            req = self._gen_getbulk_pdu(oids, nonrepeaters, maxrepetitions)
            return self._send_req(req)
        except WriteWouldBlock:
            self._wait_for_write()
            req = self._gen_getbulk_pdu(oids, nonrepeaters, maxrepetitions)
            return self._send_req(req)

    cdef netsnmp_pdu* _gen_getbulk_pdu(self, oids, nonrepeaters, maxrepetitions) except NULL:
        cdef netsnmp_pdu* req = snmp_pdu_create(SNMP_MSG_GETBULK)
        if req == NULL:
            raise MemoryError()

        req.errstat = nonrepeaters
        req.errindex = maxrepetitions
        for py_oid in oids:
            self._add_oid(req, py_oid)
        return req

    cdef netsnmp_pdu* _gen_set_pdu(self, oids) except NULL:
        cdef netsnmp_pdu* req = snmp_pdu_create(SNMP_MSG_SET)
        if req == NULL:
            raise MemoryError()

        try:
            for py_oid, (value, value_type) in oids.iteritems():
                self._add_oid_set(req, py_oid, value, value_type)
        except Exception:
            snmp_free_pdu(req)
            raise
        else:
            return req

    cdef _wait_for_write(self):
        gevent_wait_write(
            snmp_sess_transport(self.sp).sock,
            self.args['timeout']
        )

    cdef netsnmp_pdu* _send_req(self, netsnmp_pdu* req) except NULL:
        if self.sp == NULL:
            snmp_free_pdu(req)
            raise SNMPError("Session is not open")

        cdef netsnmp_pdu* response
        self.error_in_my_select = None

        self.query_count += 1
        cdef int rc = snmp_sess_synch_response(
            self.sp,
            req,
            cython.address(response))

        if rc == STAT_SUCCESS:
            return response

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

    cdef object _handle_response(self, netsnmp_pdu* response, uint64_t flags):
        try:
            self._raise_on_response_error(response)
            return self._parse_varbinds(response, flags)
        finally:
            snmp_free_pdu(response)

    cdef object _raise_on_response_error(self, netsnmp_pdu* response):
        if not (response.errstat == SNMP_ERR_NOERROR):
            raise SNMPResponseError(
                response.errstat,
                response.errindex,
                snmp_errstring(response.errstat))

    cdef object _parse_varbinds(self, netsnmp_pdu* response, uint64_t flags):
        cdef netsnmp_variable_list* entry = NULL
        result = OrderedDict() if AsyncSession.get_as_ordered_dict(flags) else {}

        entry = response.variables
        while (entry != NULL):
            key = self.parse_var_key(entry)
            result[key] = self._parse_varbind(entry, flags)
            entry = entry.next_variable

        return result

    cdef _parse_varbind(self, netsnmp_variable_list* entry, uint64_t flags):
        value = self.parse_var_value(entry, flags)
        if AsyncSession.get_get_vartype(flags) and AsyncSession.get_get_netsnmp_string(flags):
            return (self.parse_var_type(entry), value, self.format_varbind(entry))

        elif AsyncSession.get_get_vartype(flags):
            return (self.parse_var_type(entry), value)

        elif AsyncSession.get_get_netsnmp_string(flags):
            return (value, self.format_varbind(entry))

        else:
            return value

    cdef object parse_var_key(self, netsnmp_variable_list* var):
        return tuple([int(var.name[i]) for i in range(var.name_length)])

    cdef object parse_var_value(
            self,
            netsnmp_variable_list* var,
            uint64_t flags):

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
            return END_OF_MIB if AsyncSession.get_get_endofmib(flags) else None

        elif var.var_type == SNMP_NOSUCHINSTANCE:
            return NO_SUCH_INSTANCE if AsyncSession.get_get_nosuchinstance(flags) else None

        elif var.var_type == SNMP_NOSUCHOBJECT:
            return NO_SUCH_OBJECT if AsyncSession.get_get_nosuchobject(flags) else None

        else:
            return None

    cdef object format_varbind(self, netsnmp_variable_list* var):
        cdef object result

        # Variables used for sprint_realloc_value
        cdef u_char* dyn_buff = NULL
        cdef size_t dyn_buff_len = 0
        cdef size_t dyn_out_len = 0

        # variables used for snprint_value
        cdef char fixed_buff[512]
        cdef int rc

        rc = snprint_value(
            fixed_buff,
            cython.sizeof(fixed_buff),
            var.name,
            var.name_length,
            var)

        if rc != -1:
            result = PyBytes_FromStringAndSize(fixed_buff, rc)

        else:
            # 512 bytes was not enough. Now let netsnmp allocate dynamically.
            sprint_realloc_value(
                cython.address(dyn_buff),
                cython.address(dyn_buff_len),
                cython.address(dyn_out_len),
                1,
                var.name,
                var.name_length,
                var)

            result = PyBytes_FromStringAndSize(<char*>dyn_buff, dyn_out_len)
            libc_free(dyn_buff)

        return result

    cdef object parse_var_type(self, netsnmp_variable_list* var):
        cdef object var_type = var.var_type

        if var_type not in VAR_TYPE_TO_STRING:
            return "UNKNOWN"

        return VAR_TYPE_TO_STRING[var_type]


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
