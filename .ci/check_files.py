import os

required_structure = {
    'install': {
        'include': {
            'arkworks': ['arkworks.h'],
            'bandersnatch_vrfs': ['bandersnatch_vrfs.h'],
            'schnorrkel': ['schnorrkel.h']
        },
        'lib': {
            'cmake': {
                'arkworks': ['arkworksConfig.cmake'],
                'bandersnatch_vrfs': ['bandersnatch_vrfsConfig.cmake'],
                'schnorrkel': ['schnorrkelConfig.cmake']
            },
            '': ['libarkworks_crust.a', 'libbandersnatch_vrfs_crust.a', 'libschnorrkel_crust.a']
        }
    }
}

def check_structure(base_path, structure):
    for folder, contents in structure.items():
        current_path = os.path.join(base_path, folder)

        if isinstance(contents, dict):
            if not os.path.isdir(current_path):
                print(f"Missing directory: {current_path}")
            else:
                check_structure(current_path, contents)
        else:
            for file in contents:
                file_path = os.path.join(base_path, folder, file)
                if not os.path.isfile(file_path):
                    print(f"Missing file: {file_path}")

base_path = '../'

check_structure(base_path, required_structure)
