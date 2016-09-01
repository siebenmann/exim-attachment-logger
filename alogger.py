#!/usr/bin/python
#
# Log information about attachments received in email messages.
# Arguments are:
#       $message_exim_id $mime_content_type $mime_content_disposition $mime_filename $mime_decoded_filename
#
# $mime_decoded_filename is the actual decoded on-disk file to scan.
#
# This is invoked from the Exim MIME scanning ACL, which means it gets
# run separately for *each* 'interesting' MIME part in a message. You
# may need to glue multiple log records back together to get a full picture
# of a given message.
#
# This is written in Python because the shell script logic was getting crazy.
#
# Note that we deliberately don't log some information because we
# feel it's too privacy sensitive. For example, we don't log the actual
# MIME filename from an attachment, just its extension, and similarly we
# deliberately re-order and summarize even the extensions in a ZIP file.
#
# What is and isn't an attachment is unfortunately subject to a lot of
# heuristics because mail clients are on good drugs. Some of them declare
# everything as 'content-disposition: inline', some of them attach MIME
# filenames to inline content, etc etc. See
#
import sys, zipfile, tarfile, os.path, syslog, argparse
import cStringIO

hasrar = False
try:
    import rarfile
    hasrar = True
except ImportError:
    pass

def die(msg):
    sys.stderr.write("alogger: %s\n" % msg)
    sys.exit(1)

# ----
# What we're interested in heuristics:

# This is a list of MIME filename extensions that we consider to always
# be interesting and worth reporting, regardless of anything else about
# the MIME part.
iexts = (".zip", ".rar", ".js", )

# This is a list of content-type *prefixes* that we consider to be
# indications of attachments.
itypes = ("application/", "audio/", "video/", "text/xml", "text/vnd.")

# This is a list of file extensions + content-types that we're not
# interested in even if they appear to be attachments.
# NO LONGER USED, RETAINED FOR REFERENCE.
# We now log everything.
sexts = ((".pdf", "application/pdf"), (".pdf", "application/octet-stream"),
         (".jpg", "image/jpeg"), (".jpg", "image/jpg"),
         (".gif", "image/gif"), (".png", "image/png"),
         (".txt", "text/plain"),
         (".ics", "application/ics"),
         (".p7s", "application/pkcs7-signature"),
         )
# also .bmp + image/bmp?

# Is this an interesting attachment, or even an attachment at all?
# You would think that this is straightforward, but in practice
# MUAs do all sorts of crazy things like sending attachments with
# content-dispositions of 'inline'. As a result we look for various
# indications that things will not be displayed inline.
#
def is_interesting_attachment(ctype, cdisp, mfname):
    mfext = get_ext(mfname)
    # Anything that claims to be a .zip is automatically interesting
    # regardless of all other characteristics.
    if mfext in iexts:
        return True
    # Certain content-types of declared attachments are not interesting.
    # NOPE: Our decision is 'log everything, we can sort it out later'.
    #if cdisp == "attachment" and (mfext, ctype) in sexts:
    #   return False
    if cdisp != "inline":
        # Anything that declares itself non-inline is interesting
        return True

    # The MIME part is declared as 'inline', but this may be the MUA
    # being generic. We look at a prefix of the content-type to see
    # if it's definitely something we want to check.
    for it in itypes:
        if ctype.startswith(it):
            return True

    # If it has a declared MIME filename, we sort of assume it's
    # interesting ... except for all images, which MUAs sometimes
    # attach filenames to even for inlined ones.
    if ctype.startswith("image/"):
        return False
    if mfname:
        return True

    # It's inline, it has no MIME filename, and it's not a dangerous
    # content-type. It's not interesting.
    return False

# -----

# Given a filename, return a lower-cased extension or '' if it has
# none. The extension starts with a '.', and it may include multiple
# components if the first extension is, eg, '.gz'; this way we report
# '.tar.gz' instead of just '.gz'.
def get_ext(fname):
    fname = fname.lower()
    bn = os.path.basename(fname)
    sl = bn.split('.')
    # if there's no '.' or the only '.' is at the start (ie, a dotfile),
    # we're done.
    if len(sl) < 2 or (len(sl) == 2 and sl[0] == ''):
        return ''
    # ends with a '.'? We report that specially and punt.
    if sl[-1] == '':
        return 'DOT-AT-END'

    # Extend the selection of the extension to two components if the
    # last component appears to just be a compression marker, eg '.gz'.
    if sl[-1] in ('xz', 'gz', 'z') and len(sl) >= 3:
        return '.' + sl[-2] + '.' + sl[-1]
    else:
        return '.' + sl[-1]

# Is this a ZIP file?
def is_zip(fname):
    if not fname:
        return False
    return zipfile.is_zipfile(fname)

def is_tar(fname):
    if not fname:
        return False
    return tarfile.is_tarfile(fname)

def is_rar(fname):
    if not fname or not hasrar:
        return False
    return rarfile.is_rarfile(fname)

# Extract the file names from a zip file inside another zip file.
# This can use some memory if people are nasty, since we read
# the entire inner zipfile into bytes and then recycle that into
# a file object, but memory is probably cheap.
def inner_zipfile(fname, innername):
    flist = []
    with zipfile.ZipFile(fname, "r") as zf:
        try:
            byts = zf.read(innername)
            si = cStringIO.StringIO(byts)
            with zipfile.ZipFile(si, "r") as zf2:
                flist = zf2.namelist()
        except zipfile.BadZipfile:
            pass
    return flist

def zipfile_extlist(fname):
    with zipfile.ZipFile(fname, "r") as zf:
        try:
            flist = zf.namelist()
        except zipfile.BadZipfile as e:
            return "bad zip file: %s" % str(e)
    res = ["zip " + process_flist(flist), ]
    # Go through the file list and try to list the contents of any
    # nested .zip files (ie a .zip inside a top-level .zip),
    # because malware really does do this. We could be more
    # general by being willing to do this for any known archive
    # extension/format that we already process, but we decline for
    # various reasons including that we haven't seen that sort of
    # trick yet.
    # We do this for .jar files too, because we've seen some malware
    # samples with this.
    for fn in flist:
        if fn.lower().endswith(".zip") or fn.lower().endswith(".jar"):
            ifl = inner_zipfile(fname, fn)
            if ifl:
                res.append("inner zip " + process_flist(ifl))
    return "; ".join(res)

def tarfile_extlist(fname):
    try:
        # Using tarfile.open() here auto-handles various compression
        # schemes.
        tf = tarfile.open(fname)
        flist = tf.getnames()
        tf.close()
    except tarfile.TarError as e:
        return "bad tar file: %s" % str(e)
    return "tar " + process_flist(flist)

def rarfile_extlist(fname):
    try:
        rf = rarfile.RarFile(fname)
        flist = rf.namelist()
        rf.close()
    except rarfile.Error as e:
        return "bad rar file: %s" % str(e)
    return "rar " + process_flist(flist)

def process_flist(flist):
    extl = {}
    for fn in flist:
        if fn[-1] == '/':
            continue
        ext = get_ext(fn)
        if ext == '':
            ext = "none"
        extl[ext] = extl.setdefault(ext, 0) + 1

    eres = []
    for k, v in extl.items():
        if v == 1:
            eres.append(k)
        else:
            eres.append("%s[%d]" % (k, v))
    if not eres:
        return "no files?!"
    eres.sort()
    return "exts: " + " ".join(eres)

# TODO: need a RAR file scanner, eg
# http://rarfile.readthedocs.io/en/latest/api.html
# We probably want to defer this until alkyone and mailswitch are
# 16.04 machines so we can use the Ubuntu-packaged rarfile package.

def extra_info(fname):
    if not fname:
        return ""
    r = get_ext(fname)
    if not r:
        return ""
    return "MIME file ext: "+r

# ----
def cslab_info(opts):
    if not (opts.subject or opts.csdbl):
        return ''
    res=[]
    if opts.subject:
        if opts.subject.startswith("[PMX:SPAM]"):
            res.append('pmx-spam')
        elif opts.subject.startswith("[PMX:VIRUS]"):
            res.append('pmx-virus')
    if opts.csdbl:
        res.append("in-dnsbl")
    if not res:
        return ''
    return "email is %s" % " ".join(res)
    
# -----

# We may be called with Unicode message strings under some circumstances.
# In this case we 'encode' everything to ASCII with out of range characters
# replaced with backslashed escape sequences.
# (See the docs for the standard library codecs package for what
# standard error handlers are available.)
#
# (The likely circumstance is when a ZIP file has filenames in Unicode,
# which relentlessly forces everything upwards to Unicode strings.)
def deuni(msg):
    if isinstance(msg, unicode):
        return msg.encode("ascii", errors="backslashreplace")
    else:
        return msg

def logit_stdout(msg):
    sys.stdout.write("%s\n" % msg)

def quotestr(msg):
    return repr(msg)[1:-1]
def logit_syslog(msg):
    syslog.openlog("attachment-logger", syslog.LOG_PID, syslog.LOG_MAIL)
    syslog.syslog(syslog.LOG_INFO, quotestr(msg))

def process(opts):
    eximid = opts.eximid
    ctype = opts.ctype.lower()
    cdisp = opts.cdisp.lower()
    mfname = opts.mfname
    fname = opts.fname
    # empty content-disposition means that this is the main body (!!)
    # must screen this out soon.
    if cdisp == '':
        return
    if not is_interesting_attachment(ctype, cdisp, mfname):
        return

    fninfo = extra_info(mfname.lower())
    extra = ''
    if is_zip(fname):
        extra = zipfile_extlist(fname)
    elif is_tar(fname):
        extra = tarfile_extlist(fname)
    elif is_rar(fname):
            extra = rarfile_extlist(fname)

    # For now all content-types are interesting to report. We
    # may try to reduce the noise if the C-T matches the
    # MIME filename.
    msgl = ["%s %s %s" % (eximid, cdisp, ctype),]
    if fninfo:
        msgl.append(fninfo)
    if extra:
        msgl.append(extra)
    csi = cslab_info(opts)
    if csi:
        msgl.append(csi)

    msg = deuni("; ".join(msgl))

    if opts.syslog:
        logit_syslog(msg)
    if opts.stdout:
        logit_stdout(msg)

def setup():
    p = argparse.ArgumentParser(usage="%(prog)s [options] EXIMID C-TYPE C-DISP MIMENAME FILE",
                                description="Report on MIME attachments. Run from Exim.",
                                epilog="There is no default output; it must be given one or more of -S and -L to be useful (ie, to report results).")
    p.add_argument("eximid", metavar="EXIMID", type=str,
                   help="Exim ID of the message")
    p.add_argument("ctype", metavar="C-TYPE", type=str,
                   help="MIME Content-Type of the part")
    p.add_argument("cdisp", metavar="C-DISP", type=str,
                   help="MIME Content-Disposition of the part")
    p.add_argument("mfname", metavar="MIMENAME", type=str,
                   default='',
                   help="MIME filename of the part (may be blank)")
    p.add_argument("fname", metavar="FILE", type=str, default='',
                   help="On-disk file with the contents of the decoded part (may be blank)")
    p.add_argument("-L", "--syslog", dest="syslog", action="store_true",
                   default=False,
                   help="log attachment information to syslog (under the name 'attachment-logger')")
    p.add_argument("-S", "--stdout", dest="stdout", action="store_true",
                   default=False,
                   help="log attachment information to stdout")
    p.add_argument("--subject", dest="subject", type=str, default="",
                   metavar="STR",
                   help="Email Subject: header for PMX scoring detection")
    p.add_argument("--csdnsbl", dest="csdbl", type=str, default="",
                   metavar="STR",
                   help="Email X-CS-DNSBL: header for reporting")
    return p

def main():
    p = setup()
    opts = p.parse_args()
    process(opts)

if __name__ == "__main__":
    main()
    sys.exit(0)
