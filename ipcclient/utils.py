import re


def shorten(s):
    for i in ('nn::sf::hipc::detail::', 'nn::sf::hipc::client::', 'nn::sf::cmif::client::', 'nn::sf::cmif::detail::',
              'std::__1::', 'nn::sf::'):
        s = s.replace(i, '')
    return s


def hexify(s):
    def matchfunc(o):
        v = int(o.group(1))
        if v < 10:
            return '%d' % v
        else:
            return '0x%X' % v

    return re.sub('([0-9]+)u?l?', matchfunc, s)
