"""MyProxy Web Service security utilities module
"""
__author__ = "P J Kershaw"
__date__ = "24/09/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import re


class X509SubjectNameError(Exception):
    '''Base class for X509SubjectName class errors'''
    
    
class X509SubjectNameParseError(X509SubjectNameError):
    '''Parsing error for X509SubjectName class'''
    
    
class X509SubjectNameConfigError(X509SubjectNameError):
    '''Configuration related error for X509SubjectName class'''
    
    
class X509SubjectName(object):
    '''Class to handle X.509 subject names'''
    SHORT_NAME_LOOKUP = {
        'commonName':               'CN',
        'organisationalUnitName':   'OU',
        'organisation':             'O',
        'countryName':                'C',
        'emailAddress':             'EMAILADDRESS',
        'localityName':                'L',
        'stateOrProvinceName':        'ST',
        'streetAddress':            'STREET',
        'domainComponent':            'DC',
        'userid':                    'UID'
    }
    SLASH_PARSER_RE_STR = '/(%s)=' % '|'.join(SHORT_NAME_LOOKUP.keys() + 
                                              SHORT_NAME_LOOKUP.values())    
    SLASH_PARSER_RE = re.compile(SLASH_PARSER_RE_STR)

    COMMA_PARSER_RE_STR = '[,]?\s*(%s)=' % '|'.join(SHORT_NAME_LOOKUP.keys() + 
                                                    SHORT_NAME_LOOKUP.values())    
    COMMA_PARSER_RE = re.compile(COMMA_PARSER_RE_STR)
            
    VALID_SEPARATORS = ('/', ',')
    
    def __init__(self):
        self._dn = {}
        
    @classmethod
    def from_string(cls, dn, separator=None):
        obj = cls()
        obj._dn = cls.parse(dn, separator)
        
        return obj
        
    @classmethod
    def parse(cls, dn, separator=None):
        '''Parse string distinguished name into a dictionary for fields.  Where 
        multiple entries exist for a field, values are set as a tuple
        '''
        if separator in ('/', None):
            parser_re = cls.SLASH_PARSER_RE
        elif separator == ',':
            parser_re = cls.COMMA_PARSER_RE
        else:
            raise X509SubjectNameConfigError('Invalid field separator %r' %
                                             separator)
        
        dn_fields = parser_re.split(dn)
        if len(dn_fields) < 2:
            raise X509SubjectNameConfigError('Error parsing DN string: \"%s\"' %
                                             dn)
            
        items = zip(dn_fields[1::2], dn_fields[2::2])
        
        # Strip leading and trailing space chars and convert into a
        # dictionary
        parsed_dn = {}
        for key, val in items:
            key = key.strip()
            if key in parsed_dn:
                if isinstance(parsed_dn[key], tuple):
                    parsed_dn[key] = tuple(list(parsed_dn[key]) + [val])
                else:
                    parsed_dn[key] = (parsed_dn[key], val)
            else:
                parsed_dn[key] = val
            
        return parsed_dn

    def serialize(self, *args, **kwargs):
        '''Serialize subject name iterable into a string'''
        return self.__class__.Serialize(self._dn, *args, **kwargs)
    
    @classmethod
    def Serialize(cls, dn, separator='/', sort=True):
        '''Classmethod implementation - Serialize subject name iterable into a 
        string'''
        
        if separator not in cls.VALID_SEPARATORS:
            raise X509SubjectNameConfigError('Invalid field separator %r' %
                                             separator)

        # If using '/' then prepend DN with an initial '/' char
        if separator == '/':
            s_dn = separator
        else:
            s_dn = ''
     
        dn_list = []
        for key, val in dn.items():
            if val:
                if isinstance(val, tuple):
                    kv_pairs = ["%s=%s" % (key, val_sub) for val_sub in val]
                    dn_list += [separator.join(kv_pairs)]
                else:
                    dn_list += ["%s=%s" % (key, val)]
             
        if sort:
            dn_list.sort()
               
        s_dn += separator.join(dn_list)
                                
        return s_dn
