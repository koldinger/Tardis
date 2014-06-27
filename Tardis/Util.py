def fmtSize(num, base=1024):
    fmt = "%d %s"
    for x in ['bytes','KB','MB','GB']:
        #if num < base and num > -base:
        if -base < num < base:
            return fmt % (num, x)
        num /= base
        fmt = "%3.1f %s"
    return fmt % (num, 'TB')
