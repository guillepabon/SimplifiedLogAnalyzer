# SimplifiedLogAnalyzer
This repository contains the code and resources for retrieving Apache HTTP and VSFTPD log files and provides different options to extract logs and summarize the content:

(1) Requests from a given Client <br />
(2) Type of request and frequency <br />
(3) Response status code <br />
(4) Raw log <br />

# Contents
* log-analizer.py: Main python script.
* vsftpd.log: Sample VSFTPD log.
* apache.log: Sample APACHE log.

# Setup and Installation
No special installation is required. Python 3.1.0. or greater.

# Usage
Execute the script (a virtual environment is recommended):
 python log-analizer.py

* The code requires the user to specify the filename to be used
* The next section requires the user to specify the type of log file that was referenced
* The user is asked to input the start date, start time, end date, and end time parameters
* Different options are presented in order to analyze the log data: Each option expects a numeric value input and references a function previously defined that aggregates the data, finds unique occurrences, and counts them.
