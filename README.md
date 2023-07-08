# Script Maker Hash v1.0

Python program that can hash a word, decrypt a hash, and add a word to a word list file. The program uses the hashlib library to calculate the hashes and can perform parallel processing using the concurrent.futures module.

## Getting Started

To get started, clone the repository to your local machine:

```
git clone https://github.com/<username>/script-maker-hash.git
```

### Prerequisites

- Python 3.x

### Installation

No installation is required. Simply navigate to the cloned repository and run the program using the following command:

```
python script_maker_hash.py
```

### Usage

To use the program, follow the prompts in the menu:

1. Hash a word
2. Decrypt a hash
3. Add a word to the word list file
q. Quit

#### Hash a word

To hash a word, select option 1 from the menu and follow the prompts. The program will ask you to enter the hash type (MD5, SHA1, SHA256, or SHA512) and the word to hash. The hashed word will be displayed and saved to the word list file.

#### Decrypt a hash

To decrypt a hash, select option 2 from the menu and follow the prompts. The program will ask you to enter the encoded hash, and it will try to decrypt it using the words in the word list file. If a match is found, the password will be displayed.

#### Add a word to the word list file

To add a word to the word list file, select option 3 from the menu and follow the prompts. The program will ask you to enter the word to add, and it will check if the word is already in the file. If the word is not in the file, it will be added along with its MD5 hash.

## Contributing

Contributions are welcome! To contribute, fork the repository and create a new branch for your changes. Once you have made your changes, submit a pull request for review.

## License

This project is licensed under the MIT License - see the [LICENSE.txt] file for details.

## Acknowledgments

This program was created by Script Maker.
