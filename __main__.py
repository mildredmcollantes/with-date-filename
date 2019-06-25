import os, sys
import argparse
import csv
import hashlib
from zipfile import ZipFile
import platform
import datetime

def main(options):
    output = options.name
    # print(output)
    for roots, dirs, files in os.walk(options.dir):
        for file in files:
            with open(output, 'a') as f:
                filepath = os.path.join(roots, file)
                filesize = _get_fileSize(filepath)
                sha1, md5 = get_hashes(filepath)
                csv_writer(f, roots, file, filesize, sha1, md5)

    _zipfile(output)

def _datetime(output):
    timestamp = os.path.getmtime(output)
    return datetime.datetime.fromtimestamp(timestamp).replace(microsecond=0)


def _zipfile(output):
    timestamp = _datetime(output)
    outzip = output + ".zip-" + str(timestamp)
    ZipFile(outzip, mode="w").write(output)


def _get_fileSize(file):
    return os.path.getsize(file)


def get_hashes(filepath):
    try:
        BLOCKSIZE = 65536
        sha1hash = hashlib.sha1()
        md5hash = hashlib.md5()
        with open(filepath, 'rb') as afile:
            buf = afile.read(BLOCKSIZE)
            while len(buf) > 0:
                sha1hash.update(buf)
                buf = afile.read(BLOCKSIZE)
            sha1 = sha1hash.hexdigest()
            md5 = md5hash.hexdigest()
    except Exception as ex:
        print(ex)

    return (sha1, md5)


def csv_writer(csvfile, filepath, file, filesize, sha1, md5):
    try:
        spamwriter = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
        spamwriter.writerow([filepath] + [file] + [filesize] + [sha1] + [md5])
    except Exception as ex:
        print(ex)


def _get_args():
    parser = None
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("dir", help="input directory")
        parser.add_argument("name",  help="filename of output file")
    except Exception as ex:
        print("[ERROR] Problem in getting options: {}".format(ex))
    finally:
        return parser


if __name__ == "__main__":
    options = (_get_args()).parse_args()
    if options:
        main(options)