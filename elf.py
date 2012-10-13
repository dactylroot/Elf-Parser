#!/usr/bin/python
""" ELF file parsing class. 

    Currently supports look up of dependency lib names from 32- & 64-bit ELF."""

class _open_b(file):
    """ Extension of file class constructor with byte iterators and accessors. 
        Automatically checks if the file is an ELF and parses ELF header. """

    def __init__(self,*args,**kwargs):
        file.__init__(self,*args,**kwargs)
        self.prev_gen = self.prev_byte_gen()
        _check_magick(self)
        
        def little_endian_reader(n):
            """ Return a function that reads n bytes, little-endian, as an integer. 
                
                Though it will become a member function of _open_b, 
                le_n() doesn't need an _open_b instance as first parameter
                because python uses a "bound method" wrapper on the object.
                The local class instance is implicitly stored inside. """

            def le_n():
                le = self.read(n)
                return sum([ord(x[1]) << (8 * x[0]) for x in \
                       list(reversed(list(enumerate(le))))])
            le_n.__doc__ = 'Return '+str(n)+' bytes, little-endian, as an int.'
            return le_n
            
        if self.ei_class == '32-bit':
            self.le_half = little_endian_reader(2)
            self.le_word = self.le_addr = self.le_sword = self.le_offset \
                         = self.le_xword = self.le_sxword = little_endian_reader(4)
            
        elif self.ei_class == '64-bit':
            self.le_half = little_endian_reader(2)
            self.le_word = self.le_sword = little_endian_reader(4)
            self.le_addr = self.le_offset = self.le_xword \
                         = self.le_sxword = little_endian_reader(8)
        
        _parse_header(self)
        self.seek(0,0)
    
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
        return self.prev_gen.next()

def _check_magick(bile):
    """ Parse information from elf identity bytes. 
        
        Will store magic bytes and architecture as ei_magic and ei_class 
        within the file.
        ei_magic can be used to check if file is a valid ELF."""

    bile.seek(0,0)
    bile.ei_magic = bile.read(4)
    classes = {0:'Invalid',1:'32-bit',2:'64-bit'}
    if  bile.ei_magic != '\x7fELF':
        return
    bile.ei_class = classes[ord(bile.read(1))]

def _parse_header(bile):
    """ Parse information from elf header and section header. 
        
        If file is ELF, values go in new fields in the given file object. """
    
    if  bile.ei_magic != '\x7fELF':
        return
    
    bile.seek(16,0)
    reading = {'h': bile.le_half, 'w': bile.le_word,'a': bile.le_addr, 
               'o': bile.le_offset, 'x': bile.le_xword}
    labels = ('type', 'machine', 'version', 'entry', 'phoff', \
              'shoff', 'flags', 'ehsize', 'phentsize', 'phnum',\
              'shentsize','shnum','shstrndx')
    htypes = ('h','h','w','a','o','o','w','h','h','h','h','h','h')
    
    bile.elfhead = dict(zip(labels,[reading[t]() for t in htypes]))
    
    # Retrieve section header string table.
    # sh: name, type, flags, addr, offset, size, link, info, addralign, entsize
    bile.seek((bile.elfhead['shentsize'] * bile.elfhead['shstrndx'])\
                                         + bile.elfhead['shoff'], 0)
    
    labels = ('name', 'type', 'flags', 'addr', 'offset', \
              'size', 'link', 'info', 'addralign', 'entsize')
    
    shtypes = ('w','w','x','a','o','x','w','w','x','x')
    
    sh_strtableh = dict(zip(labels,[reading[t]() for t in shtypes]))
    bile.seek(sh_strtableh['offset'],0)
    bile.sh_strtableh = sh_strtableh
    
    # Now the section header is known, can retrieve dynamic string table
    bile.dynstrh = _find_section(bile,'.dynstr')

def _find_section(bile,sectionname):
    """ For elf bile, return header representation for given section name. 
    
        Returns dict:
        {name, type, flags, addr, offset, size, link, info, addralign, entsize}
    """
    # Find the section header
    theaderoffset = None
    bile.seek(bile.elfhead['shoff'],0)
    for i in range(bile.elfhead['shnum']):
        nameindex = bile.le_word()
        bile.seek(bile.sh_strtableh['offset'] + nameindex,0)
        name = bile.read_to_null()
        if name == sectionname:
         theaderoffset = bile.elfhead['shoff'] + (i * bile.elfhead['shentsize'])
        bile.seek(bile.elfhead['shoff'] + ((i+1) * bile.elfhead['shentsize']),0)
    
    if theaderoffset == None:
        return None
    bile.seek(theaderoffset)
    reading = {'w': bile.le_word, 'a': bile.le_addr, 'o': bile.le_offset,
               'x': bile.le_xword}
    labels = ('name', 'type', 'flags', 'addr', 'offset', \
              'size', 'link', 'info', 'addralign', 'entsize')
    
    shtypes = ('w','w','x','a','o','x','w','w','x','x')

    return dict(zip(labels,[reading[i]() for i in shtypes]))

def find_dependency_libraries(bile):
    """ Give ELF dependency lib names for ELF _open_b bile. 
        
        Return list of strings which are library names as found in the file.
        No paths or context outside the file is given. """
    if type(bile) != _open_b and type(bile) == file:
        bile = bile.name
    if isinstance(bile,str):
        bile = _open_b(bile,'rb')
    
    if bile.ei_magic != '\x7fELF':
        return []
    
    libs = []
    # Find the .dynamic section
    dsectionh = _find_section(bile,'.dynamic')
    if dsectionh == None:
        return libs
    
    # compile list of needed libraries
    bile.seek(dsectionh['offset'],0)
    for i in xrange(0,dsectionh['size'],dsectionh['entsize']):
        # tag value of 1 means the resource is 'needed'
        bile.seek(dsectionh['offset'] + i,0)
        tag = bile.le_sxword()
        if tag == 1:
            # Next is string table index of needed library name
            # union(word,addr) in 32-bit, union(xword,addr) in 64-bit
            strndx = bile.le_addr() 
            bile.seek(bile.dynstrh['offset']+strndx,0)
            libs.append(bile.read_to_null())
     
    return libs
