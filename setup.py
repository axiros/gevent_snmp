import os
from setuptools import setup
from distutils.extension import Extension

libname = os.getenv('NETSNMP_LIBNAME', 'netsnmp')

try:
    from Cython.Build import cythonize
except ImportError:
    def cythonize(extensions): return extensions
    sources = ['async_session.c']
else:
    if os.path.exists('async_session.pyx'):
        sources = ['async_session.pyx']
    else:
        def cythonize(extensions): return extensions
        sources = ['async_session.c']


mod1 = Extension(
    'async_session',
    sources,
    libraries=[libname, 'dl'],
    extra_compile_args=['-O3']
)

setup(
    name='gevent_snmp',
    version='0.17.3',
    ext_modules=cythonize([mod1])
)
