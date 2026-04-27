import tarfile
import os

app_dir = 'ms_defender_mail_quarantine'
tar_name = 'ms_defender_mail_quarantine/releases/ms_defender_mail_quarantine_v1.3.1.tar'

def filter_file(tarinfo):
    # Exclude the releases directory itself from being added
    if 'releases' in tarinfo.name:
        return None
        
    # Set permissions: 755 for directories, 644 for files
    if tarinfo.isdir():
        tarinfo.mode = 0o755
    else:
        tarinfo.mode = 0o644
        
    # Set ownership to root or empty to avoid weird windows SIDs
    tarinfo.uid = 0
    tarinfo.gid = 0
    tarinfo.uname = 'root'
    tarinfo.gname = 'root'
    
    return tarinfo

print(f"Building {tar_name} with forced Linux permissions...")
with tarfile.open(tar_name, "w") as tar:
    tar.add(app_dir, filter=filter_file)
    
print("Done!")
