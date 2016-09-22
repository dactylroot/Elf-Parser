#!/usr/bin/python
""" ELF file parsing class.

    Currently supports look up of dependency lib names from 32- & 64-bit ELF.

    See find_dependency_libraries() or open an ELF file with open_e() """

class open_e(file):
    """ Extension of file class constructor with byte iterators and word-object accessors.
        Automatically checks if the file is an ELF, parses ELF header, and looks up dependency names.
        Throws a RuntimeException if the ELF parsing fails """

    def __init__(self,*args,**kwargs):
        file.__init__(self,*args,**kwargs)

        def little_endian_reader(n):
            """ Return a function that reads n bytes, little-endian, as an integer.

                Though it will become a member function of open_e,
                le_n() doesn't need an open_e instance as first parameter
                because python uses a "bound method" wrapper on the object.
                The local class instance is implicitly stored inside. """

            def le_n():
                le = self.read(n)
                return sum([ord(x[1]) << (8 * x[0]) for x in \
                       list(reversed(list(enumerate(le))))])
            le_n.__doc__ = 'Return '+str(n)+' bytes, little-endian, as an int.'
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

            self.seek(0,0)
        except:
            raise RuntimeError("Input file '{0}' does not follow ELF specification".format(self.name))

    def read_to_null(self):
        """ Read until null byte delimiter is reached. Returns byte string. """
        res = ''
        byt = self.read(1)
        while byt != '\x00' and byt != '':
            res += byt
            byt = self.read(1)
        return res

    def next_byte_gen(self):
        cur = self.tell() ; self.seek(0,2)
        end = self.tell() ; self.seek(cur,0)
        while self.tell() < end:
            yield self.read(1)

    def prev_byte_gen(self):
        while self.tell() > 1:
            self.seek(-1,1)
            byte = self.read(1)
            self.seek(-1,1)
            yield byte

    def prev_byte(self):
        return self.prev_byte_gen.next()

    def _check_magick(self):
        """ Parse information from elf identity bytes.

            Will store magic bytes and architecture as ei_magic and ei_class
            within the file.
            ei_magic can be used to check if file is a valid ELF."""

        self.seek(0,0)
        self.ei_magic = self.read(4)
        classes = {0:'Invalid',1:'32-bit',2:'64-bit'}
        if  self.ei_magic != '\x7fELF':
            raise RuntimeError("input {0} doesn't contain supported ELF header".format(self.name))

        self.ei_class = classes[ord(self.read(1))]

    def _parse_header(self):
        """ Parse information from elf header and section header.

            If file is ELF, values go in new fields in the given file object. """

        if  self.ei_magic != '\x7fELF':
            return

        self.seek(16,0)
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
        self.seek((self.elfhead['shentsize'] * self.elfhead['shstrndx'])\
                                             + self.elfhead['shoff'], 0)

        labels = ('name', 'type', 'flags', 'addr', 'offset', \
                  'size', 'link', 'info', 'addralign', 'entsize')

        shtypes = ('w','w','x','a','o','x','w','w','x','x')

        sh_strtableh = dict(zip(labels,[reading[t]() for t in shtypes]))
        self.seek(sh_strtableh['offset'],0)
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
        self.seek(self.elfhead['shoff'],0)
        for i in range(self.elfhead['shnum']):
            nameindex = self.le_word()
            self.seek(self.sh_strtableh['offset'] + nameindex,0)
            name = self.read_to_null()
            if name == sectionname:
             theaderoffset = self.elfhead['shoff'] + (i * self.elfhead['shentsize'])
            self.seek(self.elfhead['shoff'] + ((i+1) * self.elfhead['shentsize']),0)

        if theaderoffset == None:
            return None
        self.seek(theaderoffset)
        reading = {'w': self.le_word, 'a': self.le_addr, 'o': self.le_offset,
                   'x': self.le_xword}
        labels = ('name', 'type', 'flags', 'addr', 'offset', \
                  'size', 'link', 'info', 'addralign', 'entsize')

        shtypes = ('w','w','x','a','o','x','w','w','x','x')

        return dict(zip(labels,[reading[i]() for i in shtypes]))

    def _find_dependency_libraries(self):
        """ Give ELF dependency lib names for ELF open_e binary-mode file.

            Return list of strings which are library names as found in the file.
            No paths or context outside the file is given. """

        libs = []
        # Find the .dynamic section
        dsectionh = self._find_section('.dynamic')
        if dsectionh == None:
            return libs

        # compile list of needed libraries
        self.seek(dsectionh['offset'],0)
        for i in xrange(0,dsectionh['size'],dsectionh['entsize']):
            # tag value of 1 means the resource is 'needed'
            self.seek(dsectionh['offset'] + i,0)
            tag = self.le_sxword()
            if tag == 1:
                # Next is string table index of needed library name
                # union(word,addr) in 32-bit, union(xword,addr) in 64-bit
                strndx = self.le_addr()
                self.seek(self.dynstrh['offset']+strndx,0)
                libs.append(self.read_to_null())

        return libs

if __name__ == "__main__":
    import sys
    from pprint import pprint

    try:
        elf = sys.argv[1]
    except:
        print "usage\n  elf.py <input ELF filename>"
        sys.exit(1)

    elf = open_e(elf,'rb')

    pprint(elf.dependencies)

