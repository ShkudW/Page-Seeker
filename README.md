# Page-Seeker

Page-Seeker is a web scraping tool designed to find sensitive information on websites.
It supports scanning websites built with various CMS platforms and searching for specific data patterns.

## Features
- Identify CMS of the target website.
- Scan dynamically loaded files using Selenium.
- Perform fuzzing to find additional files.
- Search for sensitive information such as usernames, passwords, emails, IP addresses, and hashes.
- Generate a comprehensive HTML report.

## Requirements
- Python 3.6 or higher
- Geckodriver (for Selenium with Firefox)



## Side Installation:

1. It is required to download Geckodriver, recommended version (linux64):
   ```
    https://github.com/mozilla/geckodriver/releases
    ```
    
3. After downloading, extract the file:
    ```
    tar -xvzf ./geckodriver-v0.34.0-linux64.tar.gz
    ```
    
4. Move the file to this path:
    ```
    mv geckodriver /usr/local/bin/
    ```
    
5. Apply full permissions to the File:
    ```
    sudo chmod +x /usr/local/bin/geckodriver
    ```


## Installation

1. Clone the repository:
    ```
    git clone https://github.com/ShkudW/Page-Seeker.git
    ```
2. Apply full permissions to the tool's directory:
    ```
    sudo chmod -R 777 Page-Seeker
    ```
3. Navigate to the project directory:
    ```
    cd Page-Seeker
    ```
4. Install the required packages:
    ```
    pip install -r requirements.txt
    ```


## Usage


//Run the Tool without root privilege ot without sudo command//

python3 Web-Seeker.py -url https://target.com -outfile FileName.html -geckodriver /usr/local/bin/geckodriver

--------------------------------

'-outfile' -> For this flag, only specify the file name with the .html extension. 
            The file will be automatically saved in the 'Report' directory

'-geckodriver' /usr/local/bin/geckodriver -> !!It is required to use this flag!!



## WordLists:


    The tool has several wordlists:

    1. General
    2. Expanded
    3. Specific for Wordpress sites if the tool detects that the target site is Wordpress
    4. Specific for Joomla sites if the tool detects that the target site is Joomla

    Please note that to use the expanded wordlist, you must rename it to wordlist.txt and change the name of the general wordlist from wordlist.txt to any other name, and revert the change if you want to use it again.

    Regarding the two CMS-specific wordlists, the tool uses them automaticall.

-----------------------------------------------------------------------------------------------------
    !!! Please note that using the wordlists other than the 'General' one will result in a longer execution time for the tool. Please be patient !!!
-----------------------------------------------------------------------------------------------------
