### Presentation
Simple malware samples fingerprinting script. It outputs MD5, SHA256, SHA1 and IMP (if the sample is a PE) hashes, as well as strings, hex dump, and file/trid/clamscan commands results.

### Installation : 
Python modules
```
python3 -m pip -r requirements.txt
```
Clamav
```
sudo apt install clamav-freshclam
sudo apt install clamav
freshclam
```
TriD
```
wget http://mark0.net/download/trid_linux_64.zip
unzip trid_linux_64.zip
wget http://mark0.net/download/triddefs.zip
unzip triddefs.zip
sudo mv trid triddefs.trd /usr/local/bin/
rm triddefs.zip trid_linux_64.zip readme.txt
sudo chmod +x /usr/local/bin/trid
```
### Use
Pass the path to a folder containing your samples (and ONLY your samples) as an argument, like so :
```
python3 fingerprint.py --path path/to/samples/
```

