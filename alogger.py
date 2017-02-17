#!/usr/bin/python3
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
import sys, zipfile, tarfile, os.path, syslog, argparse, traceback
import io

hasrar = False
try:
    import rarfile
    hasrar = True
except ImportError:
    pass

hasfile = False
try:
    import magic
    hasfile = True
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
no_c_disp = "<unknown>"
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

    # A missing content-disposition may be the main body of a non
    # multipart message or a multipart part with no C-D header.
    # Both happen and we sadly can't tell them apart right now.
    # For now we consider this to be a form of 'inline' and thus
    # not automatically interesting by itself. Attachments without
    # a C-D will hopefully have an interesting MIME type.
    if cdisp not in ("inline", no_c_disp):
        # Anything that declares itself non-inline is interesting
        return True

    # If the content-type is blank, this is automatically interesting.
    # According to the Exim documentation this happens if the part
    # supplies no Content-Type.
    if ctype == "":
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
    # In theory ZIP filenames are stored in a length-counted field
    # with no terminator. In practice, apparently some viruses play
    # silly games with sticking null bytes into the ZIP file names and
    # as a result the zipfile module explicitly truncates filenames at
    # the first null byte. When the null byte is the first byte, we
    # get a 0-length name.
    #
    # If we really wanted to, we could fish out the original name
    # as .orig_filename on the ZipInfo structures. We'd have to
    # call .infolist() and process the results instead of just calling
    # .namelist(). We may do this at some point.
    if len(fname) == 0:
        return "no-fname"

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
    if sl[-1] in ('xz', 'gz', 'z', '7z') and len(sl) >= 3:
        return '.' + sl[-2] + '.' + sl[-1]
    else:
        return '.' + sl[-1]

def getmagic(fname):
    if not hasfile or not fname:
        return ""
    m = magic.open(magic.MIME_TYPE | magic.COMPRESS)
    if not m:
        return ""
    if m.load() != 0:
        return ""
    r = m.file(fname)
    if r is None:
        return ""
    return r

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
#
# Returns a (filenames, error-string) tuple.
def inner_zipfile(fname, innername):
    flist = []
    with zipfile.ZipFile(fname, "r") as zf:
        try:
            try:
                byts = zf.read(innername)
            except (RuntimeError, NotImplementedError) as e:
                # Invalid password. Yes, really. This is what gets
                # thrown by the zipfile module. My anger is palpable.
                # It is extremely tempting to make our own copy and fix
                # this. NIE is raised for various zip archive flags, too.
                return ([], "encrypted zipfile? (%s)" % e)
            si = io.BytesIO(byts)
            with zipfile.ZipFile(si, "r") as zf2:
                flist = zf2.namelist()
        except zipfile.BadZipfile as e:
            return ([], "bad zipfile (%s)" % e)
        except UnicodeDecodeError:
            return ([], "bad zip filenames (unicode decode error)")
    return (flist, "")

def zipfile_extlist(fname):
    try:
        with zipfile.ZipFile(fname, "r") as zf:
            flist = zf.namelist()
    except zipfile.BadZipfile as e:
        return "bad zip file: %s" % str(e)
    except UnicodeDecodeError:
        return "bad zip filenames (unicode decode error)"
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
            ifl, error = inner_zipfile(fname, fn)
            if error:
                res.append("inner zip error: "+error)
            else:
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
        if len(fn) > 0 and fn[-1] == '/':
            # skip directories.
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

# Use libmagic via the magic module to determine extra file type
# information. If this file type information is identical to the
# content-type, we don't bother reporting it.
def extra_file_info(filename, ctype):
    r = getmagic(filename)
    if r and r != ctype:
        return "file magic: "+r
    else:
        return ""

# Include libmagic information if all the file extension information
# we have is a compression type.
# TODO: messy, should be in one spot, not here + get_ext().
# NOTE: does not include .7z, because it turns out libmagic can't
# report anything useful about them.
#
# ALSO: if we have a file that claims to be a .zip but that is_zip()
# doesn't think is one, we report what extra info we can get.
def sniff_extra(ext, filename):
    # We must check for the extension ending with a compression type,
    # not just being one, because if the file name is 'blah.fred.gz'
    # get_ext() will return the extension as '.fred.gz'.
    for i in (".gz", ".xz", ".z"):
        if ext.endswith(i):
            return True
    # We could extend this check for other archive types, but I'm
    # not doing that until we have a need for it.
    if ext == ".zip" and not is_zip(filename):
        return True
    return False

# Generate MIME filename extension information plus information sniffed
# from using libmagic. If there's no filename extension, we always sniff.
# If there is an extension, we sniff in cases where it may give us
# additional information, like compressed files that libmagic can deal
# with or .zips that aren't actually ZIP archives.
def extra_info(fname, filename, ctype):
    if not fname:
        return extra_file_info(filename, ctype)
    r = get_ext(fname)
    if not r:
        return extra_file_info(filename, ctype)

    msg = "MIME file ext: "+r
    # Possibly use libmagic to sniff extra information.
    if sniff_extra(r, filename):
        r2 = extra_file_info(filename, ctype)
        if r2:
            msg += "; "+r2
    return msg

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

# In Python 3, all of our strings are Unicode and may contain both
# control characters and non-ASCII characters. How these are handled
# by either sys.stdout or syslog.syslog() is uncertain, so we take
# the brute force approach: we coerce everything to backslash-escaped
# ASCII, with control characters encoded as "\xNN". We must do this in
# two steps; encoding control characters, and then encoding Unicode.
#
# Since it is more convenient for callers, we return a (Unicode)
# string, not a byte(string).
ctrldict = {c: "\\x%02x" % c for c in range(0,32)}
ctrldict[127] = "\\x7f"
# A few special characters get special escapes
ctrldict[ord("\n")] = "\\n"; ctrldict[ord("\r")] = "\\r";
ctrldict[ord("\t")] = "\\t"
ctrldict[ord("\\")] = "\\\\"
def deuni(msg):
    dctrl = msg.translate(ctrldict)
    asc = dctrl.encode("ascii", errors="backslashreplace")
    return asc.decode("ascii")

#
# Our message strings for logging have gone through deuni() and so
# should be completely safe to write to things that need to encode
# them.
#
# (These are famous last words.)
def logit_stdout(msg):
    sys.stdout.write("%s\n" % msg)

def logit_syslog(msg):
    syslog.openlog("attachment-logger", syslog.LOG_PID, syslog.LOG_MAIL)
    syslog.syslog(syslog.LOG_INFO, msg)

#
#
def process(opts):
    eximid = opts.eximid
    ctype = opts.ctype.lower()
    cdisp = opts.cdisp.lower()
    mfname = opts.mfname
    fname = opts.fname

    # An empty content-disposition can mean one of two things:
    # either it's the main body of a non-multipart message, or
    # some joker sent us a MIME attachment *without* a C-D
    # (which malware does). In either case, we'd better process
    # anything suspicious; after all, people can directly send
    # ZIP files or the like.
    # We rewrite the blank C-D value to a standard value so that
    # our log messages and so on are clear(er).
    if cdisp == '':
        cdisp = no_c_disp
    if not is_interesting_attachment(ctype, cdisp, mfname):
        return

    fninfo = extra_info(mfname.lower(), fname, ctype)
    extra = ''
    if is_zip(fname):
        extra = zipfile_extlist(fname)
    elif is_tar(fname):
        extra = tarfile_extlist(fname)
    elif is_rar(fname):
        extra = rarfile_extlist(fname)

    # Fix a blank content-type (ie, the part supplied no Content-Type
    # header).
    if ctype == "":
        ctype = "<missing>"

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
    try:
        process(opts)
    except:
        if opts.syslog == True:
            syslog.openlog("attachment-logger", syslog.LOG_PID, syslog.LOG_MAIL)
            (ty, inf, trc) = sys.exc_info()
            syslog.syslog("ERROR: Python exception on message: %s" % opts.eximid)
            for e in traceback.format_exception(ty, inf, trc):
                lines = str(e).split("\n")
                for l in lines:
                    l2 = l.strip()
                    if not l2:
                        continue
                    syslog.syslog("T: %s" % l)
            syslog.syslog("T: (end)")
        else:
            raise

if __name__ == "__main__":
    main()
    sys.exit(0)
