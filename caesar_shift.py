import string
import cgi

def shift_letter(letter, case):
    return chr(ord(case)+(ord(letter)+13-ord(case))%26)

def unescape(s):
    s = s.replace("&lt;", "<")
    s = s.replace("&gt;", ">")
    # this has to be last:
    s = s.replace("&quot;",'"')
    s = s.replace("&amp;", "&")
    return s


def shift(text):

    t_in = unescape(text)
    t_out =""""""

    for i in t_in:
        if i in string.ascii_lowercase:
            t_out += shift_letter(i,'a')
        elif i in string.ascii_uppercase:
            t_out += shift_letter(i,'A')
        else:
            t_out += i

    return cgi.escape(t_out)