import re

# Read the file contents into a string variable
with open('simple_int_overflow.sol', 'r') as f:
    example_string = f.read()

# Define regular expression pattern to match pragma solidity version or package version
pattern = r"(pragma solidity\s+>=\s*([\d\.]+)\s*<\s*([\d\.]+);)|(\^([\d\.]+);)|(\>=([\d\.]+);)"

# Find the pragma solidity version or package version using regular expression
match = re.search(pattern, example_string)

if match:
    # Extract the version number(s) from the match object
    version_numbers = [match.group(i) for i in range(2, 7) if match.group(i)]
    print("Floating sol version issue detected..")
    print('fixing the issue')

    # Remove all symbols from the version number(s)
    cleaned_version_numbers = [re.sub(r'[^\d\.]', '', version_number) for version_number in version_numbers]

    if len(cleaned_version_numbers) == 1:
        # Update the Solidity version number in the input file
        updated_contents = re.sub(pattern, '' + cleaned_version_numbers[0] + ';', example_string)
        with open('simple_int_overflow.sol', 'w') as f:
            f.write(updated_contents)
    else:
        # Determine the larger version number if a comparison is present
        version1, version2 = cleaned_version_numbers
        if version1 > version2:
            larger_version_number = version1
        else:
            larger_version_number = version2

        # Update the package version number in the input file
        updated_contents = re.sub(pattern, '^' + larger_version_number + ';', example_string)
        with open('simple_int_overflow.sol', 'w') as f:
            f.write(updated_contents)
else:
    print("No pragma solidity version or package version found in file.")
