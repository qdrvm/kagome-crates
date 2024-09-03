import os
import sys

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
    all_present = True
    for folder, contents in structure.items():
        current_path = os.path.join(base_path, folder)

        if isinstance(contents, dict):
            if not os.path.isdir(current_path):
                print(f"Missing directory: {current_path}")
                all_present = False
            else:
                if not check_structure(current_path, contents):
                    all_present = False
        else:
            for file in contents:
                file_path = os.path.join(base_path, folder, file)
                if not os.path.isfile(file_path):
                    print(f"Missing file: {file_path}")
                    all_present = False

    return all_present


base_path = '../'

if check_structure(base_path, required_structure):
    print("All required files and directories are present. Test passed successfully!")
    sys.exit(0)
else:
    print("Some required files or directories are missing. Test failed.")
    sys.exit(1)
