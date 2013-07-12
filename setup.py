from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext

setup(
    cmdclass = {'build_ext': build_ext},
    ext_modules = [Extension("md5.impl", ["md5/impl.pyx", "md5/reference.c", "md5/my_md5.c"])]
)
