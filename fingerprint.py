#!/usr/bin/env python3


import hashlib, pefile, ssdeep, argparse, magic, subprocess, os, shutil


def get_hashes(filepath):
	with open(filepath,'rb') as f:
		content = f.read()
		md5Hash = hashlib.md5(content).hexdigest()
		sha256Hash = hashlib.sha256(content).hexdigest()
		sha1Hash = hashlib.sha1(content).hexdigest()
		ssdeepHash = ssdeep.hash_from_file(filepath)

		if is_pe(filepath):
			pe = pefile.PE(filepath)
			impHash = pe.get_imphash()
		else:
			impHash = "Not a PE file"

	return md5Hash, sha256Hash, sha1Hash, ssdeepHash, impHash


def get_file_type(filepath):
	fileOut = magic.from_file(filepath)
	tridOut = subprocess.run(['trid', filepath], capture_output=True, text=True, check=True).stdout
	return fileOut, tridOut


def is_pe(filepath):
	try:
		pe = pefile.PE(filepath)
		return True
	except pefile.PEFormatError:
		return False


def dumps(filename,filepath):
	# HEX
	hexOutFile = f'analysis/{filename}_out/hex.txt'
	hex = subprocess.run(['xxd',filepath], capture_output=True, text=True, check=True).stdout
	with open(hexOutFile,'w') as f:
		f.write(hex)
	# STRINGS
	strOutFile = f'analysis/{filename}_out/strings.txt'
	strings = subprocess.run(['strings',filepath], capture_output=True, text=True, check=True).stdout
	with open(strOutFile,'w') as f:
		f.write(strings)


def clamscan(filename,filepath):
	clamscanOutFile = f'analysis/{filename}_out/clamscan.txt'
	with open(clamscanOutFile,'w') as f:
		try:
			scan = subprocess.run(['clamscan',filepath], text=True, check=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
			if scan.stdout:
				f.write(scan.stdout)
			if scan.stderr:
				f.write(scan.stderr)
		except subprocess.CalledProcessError as e:
			if e.stdout:
				f.write(e.stdout)
			if e.stderr:
				f.write(e.stderr)


def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("--path", help="Path du dossier contenant les samples")
	args = parser.parse_args()

	if os.path.isdir(args.path):
		for filename in os.listdir(args.path):
			filepath = args.path + filename
			os.makedirs(f'analysis/{filename}_out/')
			infoFile = f'analysis/{filename}_out/infos.txt'
			md5H,sha256H,sha1H,ssdeepH,impH = get_hashes(filepath)
			fileOut,tridOut = get_file_type(filepath)
			isPE = is_pe(filepath)
			infos = f"Sample name : {filename}\nIs PE ? : {isPE}\n\n\n---HASHES---\n\nMD5 : {md5H}\nSHA256 : {sha256H}\nSHA1 : {sha1H}\nSSDEEP : {ssdeepH}\nIMP Hash : {impH}\n\n\n---File detection---\n\nFile command output :\n{fileOut}\n\nTRiD command output :\n{tridOut}\n"
			with open(infoFile,'w') as f:
				f.write(infos)
			dumps(filename,filepath)
			clamscan(filename,filepath)
			shutil.copy(filepath,f'analysis/{filename}_out/')
			print(f"Finished processing {filename}.")

if __name__=="__main__":
	main()
