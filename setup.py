from setuptools import setup
from distutils.extension import Extension


try:
    from Cython.Build import cythonize
except ImportError:
    def cythonize(extensions): return extensions
    sources = ['async_session.c']
else:
    sources = ['async_session.pyx']


mod1 = Extension(
    'async_session',
    sources,
    libraries=['netsnmp'],
    extra_compile_args=['-O3']
)

setup(
    name='gevent_snmp',
    version='0.6',
    ext_modules=cythonize([mod1])
)
