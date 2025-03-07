import os

def list_tree_excluding(root, exclude_folders, output_file=None):
    """
    Recursively prints the directory tree of the specified root directory,
    excluding directories listed in exclude_folders. Optionally writes the
    output to a text file if output_file is provided.
    
    Args:
        root (str): The root directory to start listing.
        exclude_folders (list): A list of folder names to exclude from the tree.
        output_file (str, optional): Path to the file where the tree output will be saved.
    """
    output_lines = []
    
    for dirpath, dirnames, filenames in os.walk(root):
        # Exclude specific folders from being traversed
        dirnames[:] = [d for d in dirnames if d not in exclude_folders]
        
        # Calculate the indentation level based on the depth
        level = dirpath.replace(root, "").count(os.sep)
        indent = "    " * level
        
        # Get the current directory's basename
        current_dir = os.path.basename(dirpath)
        if current_dir == "":
            current_dir = root  # In case we're at the root
        
        # Create a line for the directory
        line = f"{indent}{current_dir}/"
        output_lines.append(line)
        print(line)
        
        # Create lines for the files in the directory
        for file in filenames:
            file_line = f"{indent}    {file}"
            output_lines.append(file_line)
            print(file_line)
    
    # If an output file is provided, write the results to the file
    if output_file:
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("\n".join(output_lines))
            print(f"\nProject tree exported to {output_file}")
        except IOError as e:
            print(f"Error writing to file {output_file}: {e}")

if __name__ == "__main__":
    # Get the current working directory as the root for the project tree
    current_directory = os.getcwd()
    
    # Specify folders to exclude from the tree
    exclude_folders = ["node_modules", ".git"]
    
    # Define the output file path
    output_filename = "project_tree.txt"
    
    # Generate the project tree and export it to a file
    list_tree_excluding(current_directory, exclude_folders, output_file=output_filename)
