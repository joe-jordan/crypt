from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext

setup(
    cmdclass = {'build_ext': build_ext},
    ext_modules = [Extension("home_crypto.md5.impl", [
        "home_crypto/md5/impl.pyx",
        "home_crypto/md5/reference.c",
        "home_crypto/md5/my_md5.c"
    ]
    #, define_macros = [('DEBUG', '1')]
    )]
)
