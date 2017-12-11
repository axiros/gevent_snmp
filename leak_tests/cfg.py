good_read = {
    'community': 'public',
    'peername': '127.0.0.1',
    'version': '2c',
    'retries': 10,
    'timeout': 3
}

timeout_read = dict(good_read)
timeout_read['peername'] = '188.0.0.1'
timeout_read['retries'] = 2
timeout_read['timeout'] = 0.05

sleep_time = 0.05

read_oids = [
    '1.3.6.1.2.1.1.1.0',
    '1.3.6.1.2.1.1.2.0',
    '1.3.6.1.2.1.1.3.0',
    '1.3.6.1.2.1.1.7.0',
    '1.3.6.1.2.1.2.2.1.5.1',
    '1.3.6.1.2.1.2.2.1.6.2',
    '1.3.6.1.2.1.4.21.1.1.0.0.0.0',
    '1.3.6.1.2.1.31.1.1.1.6.1',
    '1.3.6.1.2.1.31.1.1.1.2.2',
    '1.3.6.9999'
]
