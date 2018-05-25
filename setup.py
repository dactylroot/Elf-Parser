from setuptools import setup
from os import path

with open('README.rst') as f:
    long_description = f.read()

version = '1.0.0'

setup(name='unix-elf'
    , version=version
    , description='An ELF binary parser'
    , long_description=long_description
    , author = 'Michael Stewart'
    , author_email = 'statueofmike@gmail.com'
    , url='https://github.com/statueofmike/Elf-Parser'
    , download_url="https://github.com/statueofmike/Elf-Parser/archive/{0}.tar.gz".format(version)
    , license='MIT'
    , packages=['unix-elf']
    , classifiers=[
        'Development Status :: 5 - Production/Stable',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
        'Topic :: Software Development :: Compilers',
        'Topic :: Software Development :: Disassemblers',
      ]
    , keywords='elf binary'
    , install_requires=[]
    , python_requires='>=2.6'
    )
