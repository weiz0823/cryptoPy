import distutils.core

module1 = distutils.core.Extension("cryptohash", sources=["cryptohash.c"])

distutils.core.setup(name="cryptohash", ext_modules=[module1])
