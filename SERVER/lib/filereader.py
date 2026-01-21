import os
import ujson

def storejson(filename, data_dict):
    try:
        with open(filename, "w") as f:
            ujson.dump(data_dict, f)
        print(f"Saved data to {filename}")
    except Exception as e:
        print(f"Error saving JSON to {filename}: {e}")


# reads files and searches them
def readfile(file, searchfor="§$placeholder§$", searchfor2="§$placeholder§$", returnfile=False):
    with open(file, "r") as file:
        if not returnfile:
            while True:
                chunk = file.read(1024)
                if not chunk:
                    break
                lines = chunk.splitlines()
                for line in lines:
                    if searchfor in line or searchfor2 in line:
                        return True
            return False
        else:
            all_lines = []
            while True:
                chunk = file.read(1024)
                if not chunk:
                    break
                all_lines.append(chunk)
            if all_lines:
                final = ''.join(all_lines)
            else:
                return None
            return final



def readbinary(file_path):
    with open(file_path, 'rb') as file:
        while True:
            chunk = file.read(1024)  # Read 1 KB at a time
            if not chunk:
                break
            yield chunk


def replaceinfile(file, searchfor, replace, filepath=True, wholeline=True):
    if filepath:
        with open(file, "r") as f:
            lines = f.readlines()
    else:
        lines = file
    if filepath:
        with open(file, "w") as f:
            for line in lines:
                if searchfor in line:
                    if wholeline:
                        line = replace
                    else:
                        line = line.replace(searchfor, replace)
                f.write(line)
    else:
        if searchfor in lines:
            lines = lines.replace(searchfor, replace)
        return lines
    
    
def countLines(file):
    with open(file, "r") as f:
        lines = f.readlines()
        return len(lines)


def getPath(request):
    # Split the request into lines
    lines = request.split('\n')

    # The first line should contain the request line (e.g., "GET / HTTP/1.1")
    request_line = lines[0]

    # Split the request line by spaces to extract the path
    parts = request_line.split()

    # Check if there are enough parts to extract the path
    if len(parts) < 2:
        return None

    # The path is the second part of the split request line
    path = parts[1]

    # Return the path
    return path


def findInFile(file_path, start_to_search):
    # List to store the content after the start string for all matching lines
    matching_lines = []

    # Open the file in read mode with UTF-8 encoding
    with open(file_path, 'r', encoding='utf-8') as file:
        # Iterate over each line in the file
        for line in file:
            # Check if the line starts with the specified start string
            if line.startswith(start_to_search):
                # Append the content after the start string to the list
                # Strip leading and trailing whitespace and append the rest of the line
                matching_lines.append(line[len(start_to_search):].strip())

    # Return the list of matching lines
    return matching_lines

def write_to_file(filename, content, replace=False):
    try:
        if not replace:
            mode = 'a'
        else:
            mode = 'w'
        with open(filename, mode) as file:  # 'a' for append mode
            file.write(str(content))
            file.write("\n")
    except Exception as e:
        print("Error writing to file:", e)


def clearFile(filename):
    try:
        with open(filename, 'w') as file:
            file.write("")
        print("Data has been erased on ", filename)
    except Exception as e:
        print("Error erasing file:", e)


def truncate_file(file_path, num_lines=10):
    try:
        print(f"Opening file: {file_path}")
        with open(file_path, 'r') as file:
            print("Reading lines from file...")
            lines = file.readlines()

        # Calculate the starting index to keep from the end
        start_index = max(0, len(lines) - num_lines)
        print(f"Start index calculated: {start_index}")

        # Select the lines to retain from the calculated index to the end
        retained_lines = lines[start_index:]

        print(f"Retained lines: {retained_lines}")

        with open(file_path, 'w') as file:
            print("Writing retained lines to file...")
            file.writelines(retained_lines)

        print(f"Retained {num_lines} lines from the end in '{file_path}'.")
    except Exception as e:
        print(f"Error occurred: {e}")


def listFiles(directory):
    try:
        print(f"Listing files and folders in directory: {directory}")

        files = []

        # Check if the directory ends with "/"
        if directory.endswith('/'):
            path_prefix = directory
        else:
            path_prefix = directory + '/'

        print(f"Using path prefix: {path_prefix}")

        # Iterate over the items in the directory
        for item in os.listdir(directory):
            # Get the full path of the item
            item_path = path_prefix + item  # Concatenate directory and item

            # Get the status of the item
            status = os.stat(item_path)
            print(status[0])

            # Check if the item is a regular file (st_mode S_ISREG) or a directory (st_mode S_ISDIR)
            if status[0] == 32768:
                files.append(item_path)

        print("Files found:", files)

        # Return the list of files and folders as a dictionary
        return files
    except Exception as e:
        print(f"Error listing files and folders: {e}")
        return None


def listFolders(directory):
    try:
        print(f"Listing files and folders in directory: {directory}")

        folders = []

        # Check if the directory ends with "/"
        if directory.endswith('/'):
            path_prefix = directory
        else:
            path_prefix = directory + '/'

        print(f"Using path prefix: {path_prefix}")

        # Iterate over the items in the directory
        for item in os.listdir(directory):
            # Get the full path of the item
            item_path = path_prefix + item  # Concatenate directory and item

            # Get the status of the item
            status = os.stat(item_path)
            # Check if the item is a regular file (st_mode S_ISREG) or a directory (st_mode S_ISDIR)
            if status[0] == 16384:
                folders.append(item_path)

        print("Files found:", folders)

        return folders
    except Exception as e:
        print(f"Error listing files and folders: {e}")
        return None


