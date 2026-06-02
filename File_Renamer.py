import os

folder_path = "folder/path" #Change to folder
new_name = "file" #base name for renamed files

files = os.listdir(folder_path)

count = 1
for filename in files:
    old_path = os.path.join(folder_path, filename)

    #Skip directories
    if os.path.isdir(old_path):
        continue
    
    #Get file extension
    ext = os.path.splitext(filename)[1]

    #Build new filename
    new_filename = f"{new_name}_{count}{ext}"
    new_path = os.path.join(folder_path, filename)

    #Rename the file
    os.rename()
    print(f"Renamed: {filename} → {new_filename}")

    count += 1

