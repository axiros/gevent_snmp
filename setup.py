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
    libraries=['snmp']
)

setup(
    name='async_snmp_session',
    version='0.1',
    ext_modules=cythonize([mod1])
)
