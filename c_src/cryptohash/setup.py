import distutils.core

module1 = distutils.core.Extension(
    "cryptohash",
    sources=["cryptohash.c", "md5.c", "sha1.c", "sha2_32.c", "sha2_64.c", "sha3.c"],
)

distutils.core.setup(name="cryptohash", ext_modules=[module1])
