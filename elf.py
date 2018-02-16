#!/usr/bin/python
""" 32- and 64-bit ELF parsing.

    See https://en.wikipedia.org/wiki/Executable_and_Linkable_Format for general reference.

    Features:
      * ELF class for convenient abstraction
      * ElfBytes class for byte-level operations
      * Summary inspection
      * Dynamic linking dependency lookup
"""


class Elf:
    """ Abstract interface for convenient Elf file description and analysis.
        Byte-level operations are handled by ElfBytes class. """

    @property
    def byteFile(self):
        return self._elf

    @property
    def bus(self):
        return self.byteFile.ei_class

    @property
    def dependencies(self):
        return self.byteFile.dependencies

    @property
    def header(self):
        return self.byteFile.elfhead

    @property
    def name(self):
        return self.byteFile.name

    @property
    def closed(self):
        return self.byteFile.closed

    def __init__(self,filepath):
        self._elf = ElfBytes(filepath,'rb')

    def __enter__(self):
        return self

    def __exit__(self,*args,**kwargs):
        self.byteFile.__exit__(*args,**kwargs)

    def inspect(self):
        """ Print general information about the Elf """
        print("File: {}".format(self.name))
        print(" Bus: {}".format(self.bus))
        if self.dependencies:
            print("Dynamic linking dependencies: "+','.join(self.dependencies))
        else:
            print("Dynamic linking dependencies: <none>")

    def close(self):
        self.byteFile.close()


class ElfBytes:
    """ Extension of file class constructor with byte iterators and word-object accessors.
        Automatically checks if the file is an ELF, parses ELF header, and looks up dependency names.
        Throws a RuntimeException if the Elf parsing fails.
        Allows for normal byte read/write operations.

        This class encodes almost the entire ELF specification using spec terminology, so should be easy to extend. """

    @property
    def name(self):
        return self._file.name

    @property
    def closed(self):
        return self._file.closed

    def __init__(self,*args,**kwargs):
        self._args   = args
        self._kwargs = kwargs
        self.__enter__()

    def __enter__(self):
        self._file = open(*self._args,**self._kwargs)
        #print("opened file {}".format(self._args[0]))

        def little_endian_reader(n):
            """ Return a function that reads n bytes, little-endian, as an integer.

                Though it will become a member function of this class,
                le_n() doesn't need an instance as first parameter
                because python uses a "bound method" wrapper on the object.
                The local class instance is implicitly stored inside. """

            def le_n():
                le = self._file.read(n)
                if not le:
                    return 0

                # Python2&3-friendly little-endian byte reading
                if not isinstance(le[0],int):
                    le = [ord(x) for x in le]

                return sum([x[1] << (8 * x[0]) \
                    for x in list(reversed(list(enumerate(le))))])
            le_n.__doc__ = 'Return {} bytes, little-endian, as an int.'.format(n)
            return le_n


        try:
            # parse the file header here to define accessor functions for this file
            self._check_magick()

            if self.ei_class == '32-bit':
                self.le_half = little_endian_reader(2)
                self.le_word = self.le_addr = self.le_sword = self.le_offset \
                             = self.le_xword = self.le_sxword = little_endian_reader(4)

            elif self.ei_class == '64-bit':
                self.le_half = little_endian_reader(2)
                self.le_word = self.le_sword = little_endian_reader(4)
                self.le_addr = self.le_offset = self.le_xword \
                             = self.le_sxword = little_endian_reader(8)
            self._parse_header()
            self.dependencies = self._find_dependency_libraries()

            self._file.seek(0,0)
        except Error as e:
            print("Input file '{0}' does not follow ELF specification".format(self._file.name))
            print("Unexpected error: {}".format(sys.exc_info()[0]))
            raise

        return self

    def __exit__(self, *args, **kwargs):
        #print("closing file")
        exit = getattr(self._file, '__exit__', getattr(self._file, 'close', None))
        if exit:
            return exit(*args, **kwargs)

    def close(self):
        self.__exit__()

    def read_to_null(self):
        """ Read until null byte delimiter is reached. Returns byte string. """
        res = b''
        byt = self._file.read(1)
        while byt != b'\x00' and byt != '':
            res += byt
            byt = self._file.read(1)
        return res

    def next_byte_gen(self):
        cur = self._file.tell() ; self._file.seek(0,2)
        end = self._file.tell() ; self._file.seek(cur,0)
        while self._file.tell() < end:
            yield self._file.read(1)

    def prev_byte_gen(self):
        while self._file.tell() > 1:
            self._file.seek(-1,1)
            byte = self._file.read(1)
            self._file.seek(-1,1)
            yield byte

    def prev_byte(self):
        return self.prev_byte_gen.next()

    def _check_magick(self):
        """ Parse information from elf identity bytes.

            Will store magic bytes and architecture as ei_magic and ei_class
            within the file.
            ei_magic can be used to check if file is a valid ELF."""

        self._file.seek(0,0)
        self.ei_magic = self._file.read(4)
        classes = {0:'Invalid',1:'32-bit',2:'64-bit'}

        if  self.ei_magic != b'\x7fELF':
            raise RuntimeError("input {0} doesn't contain supported ELF header".format(self.name))

        self.ei_class = classes[ord(self._file.read(1))]

    def _parse_header(self):
        """ Parse information from elf header and section header.

            If file is ELF, values go in new fields in the given file object. """

        if  self.ei_magic != b'\x7fELF':
            return

        self._file.seek(16,0)
        reading = {'h': self.le_half, 'w': self.le_word,'a': self.le_addr,
                   'o': self.le_offset, 'x': self.le_xword}
        labels = ('type', 'machine', 'version', 'entry', 'phoff', \
                  'shoff', 'flags', 'ehsize', 'phentsize', 'phnum',\
                  'shentsize','shnum','shstrndx')
        htypes = ('h','h','w','a','o','o','w','h','h','h','h','h','h')

        # Retrieve ELF header
        self.elfhead = dict(zip(labels,[reading[t]() for t in htypes]))

        # Retrieve section header string table.
        # sh: name, type, flags, addr, offset, size, link, info, addralign, entsize
        self._file.seek((self.elfhead['shentsize'] * self.elfhead['shstrndx'])\
                                             + self.elfhead['shoff'], 0)

        labels = ('name', 'type', 'flags', 'addr', 'offset', \
                  'size', 'link', 'info', 'addralign', 'entsize')

        shtypes = ('w','w','x','a','o','x','w','w','x','x')

        sh_strtableh = dict(zip(labels,[reading[t]() for t in shtypes]))
        self._file.seek(sh_strtableh['offset'],0)
        self.sh_strtableh = sh_strtableh

        # Now the section header is known, can retrieve dynamic string table
        self.dynstrh = self._find_section('.dynstr')

    def _find_section(self,sectionname):
        """ For elf file, return header representation for given section name.

            Returns dict:
            {name, type, flags, addr, offset, size, link, info, addralign, entsize}
        """
        # Find the section header
        theaderoffset = None
        self._file.seek(self.elfhead['shoff'],0)
        for i in range(self.elfhead['shnum']):
            nameindex = self.le_word()
            self._file.seek(self.sh_strtableh['offset'] + nameindex,0)
            name = self.read_to_null()
            if name == sectionname:
             theaderoffset = self.elfhead['shoff'] + (i * self.elfhead['shentsize'])
            self._file.seek(self.elfhead['shoff'] + ((i+1) * self.elfhead['shentsize']),0)

        if theaderoffset == None:
            return None
        self._file.seek(theaderoffset)
        reading = {'w': self.le_word, 'a': self.le_addr, 'o': self.le_offset,
                   'x': self.le_xword}
        labels = ('name', 'type', 'flags', 'addr', 'offset', \
                  'size', 'link', 'info', 'addralign', 'entsize')

        shtypes = ('w','w','x','a','o','x','w','w','x','x')

        return dict(zip(labels,[reading[i]() for i in shtypes]))

    def _find_dependency_libraries(self):
        """ Give ELF dependency lib names for binary-mode file.

            Return list of strings which are library names as found in the file.
            No paths or context outside the file is given. """

        libs = []
        # Find the .dynamic section
        dsectionh = self._find_section('.dynamic')
        if dsectionh == None:
            return libs

        # compile list of needed libraries
        self._file.seek(dsectionh['offset'],0)
        for i in xrange(0,dsectionh['size'],dsectionh['entsize']):
            # tag value of 1 means the resource is 'needed'
            self._file.seek(dsectionh['offset'] + i,0)
            tag = self.le_sxword()
            if tag == 1:
                # Next is string table index of needed library name
                # union(word,addr) in 32-bit, union(xword,addr) in 64-bit
                strndx = self.le_addr()
                self._file.seek(self.dynstrh['offset']+strndx,0)
                libs.append(self.read_to_null())

        return libs

if __name__ == "__main__":
    import sys
    try:
        elf_path = sys.argv[1]
    except:
        print("usage\n  elf.py <input ELF filename>")
        sys.exit(1)

    with Elf(elf_path) as _elf:
        _elf.inspect()

