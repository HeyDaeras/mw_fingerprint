### Presentation
Simple malware samples fingerprinting script. It outputs MD5, SHA256, SHA1 and IMP (if the sample is a PE) hashes, as well as strings, hex dump, and file/trid/clamscan commands results.

### Installation : 
```
python3 -m pip -r requirements.txt
sudo apt install clamav-freshclam
sudo apt install clamav
freshclam
```

### Use
Pass the path to a folder containing your samples (and ONLY your samples) as an argument, like so :
```
python3 fingerprint.py --path path/to/samples/
```

