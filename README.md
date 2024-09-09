# PE-Header-Parser
PE-Header-Parser is a command-line tool designed for analyzing Portable Executable (PE) files and displaying the results in a structured format.

# Features

![image](https://github.com/user-attachments/assets/1ff6dacb-2653-4259-aaaa-1fde926c187b)

1- Display file information (size, timestamps, checksum, MD5, etc.)

2- Print DOS Header details

3- Print NT Header signature

4- Print File Header

5- Print Optional Header

6- Print Section Header

7- Print Import Table (DLL and function names)

8- Perform hex dump

9- Display meaningful strings

10- Query and print VirusTotal scan results for the file

# Dependencies

This project uses the cJSON library for JSON parsing. The library was added from another GitHub repository. You can add it to your project by following the steps below.

# Installation:

1. Clone the repository:
   git clone https://github.com/aycagl/PE-Header-Parser.git
3. Add cJSON to your project:
  * Clone the cJSON repository from GitHub:
    git clone https://github.com/DaveGamble/cJSON.git
3. Build the executable. Compile the source code using your preferred C compiler.

# Virustotal Integration 

* To use the VirusTotal functionality, you will need your own VirusTotal API key.
* Replace the placeholder YOUR_API_KEY in the code with your actual API key:
const char* apiKey = "YOUR_API_KEY";

Once built, you can run the tool by passing the path to the PE file you want to analyze.
