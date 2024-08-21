# -*- coding: utf-8 -*-
"""""""""""""""""""""""""""""""""""
Created at some time between November and December 2022
Simplified Log Analyzer project

APACHE log filename:
    file_name = 'apache.log'

VSFTPD log filename:
    file_name = 'vsftpd.log'

"""""""""""""""""""""""""""""""""""

import os.path
from datetime import datetime
from collections import Counter

def read_apache_log_file(file_name, start_date, end_date):
    try:
        with open(file_name) as log_file:
            return [apache_regex(line, start_date, end_date) for line in log_file if apache_regex(line, start_date, end_date) is not None]
        
    except OSError:
        print(f'File not found: {file_name}')

def apache_regex(line, start_date, end_date):
    element = {}
    split_line = line.split()
    timestamp_str = split_line[3].replace('[', '')
    date = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S')
    if(date >= start_date and date <= end_date):
        element['ip'] = split_line[0]
        element['date'] = date
        element['method'] = split_line[5].replace('"', '')
        element['destination'] = split_line[6]
        element['statusCode'] = split_line[8]
        element['browser'] = split_line[11].replace('"', '')
        
        return element

def apache_IP_counter(load_log):
    apache_iplist = []
    for items in load_log:
        apache_iplist.append(items['ip'])
    ipcount = Counter(apache_iplist)
    for i,c in ipcount.items():
        print("IP Address: " + str(i) + " - " + "Count: " + str(c)) 
    
def apache_Type_counter(load_log):
    apache_typelist = []
    for items in load_log:
        apache_typelist.append(items['method'])
    ipcount = Counter(apache_typelist)
    for i,c in ipcount.items():
        print("Request type: " + str(i) + " - " + "Count: " + str(c)) 

def apache_Browser_counter(load_log):
    apache_browserlist = []
    for items in load_log:
        apache_browserlist.append(items['browser'])
    ipcount = Counter(apache_browserlist)
    for i,c in ipcount.items():
        print("Browser used: " + str(i) + " - " + "Count: " + str(c))

def apache_Response_counter(load_log):
    apache_Responselist = []
    for items in load_log:
        apache_Responselist.append(items['statusCode'])
    statuscount = Counter(apache_Responselist)
    for i,c in statuscount.items():
        print("Status Code received: " + str(i) + " - " + "Count: " + str(c))
        
def apache_Raw_log(load_log):
    for i in load_log:
        print(str(i)) 

def read_vsftpd_log_file(file_name, start_date, end_date):
    try:
        with open(file_name) as log_file:
            return [vsftpd_regex(line, start_date, end_date) for line in log_file if vsftpd_regex(line, start_date, end_date) is not None]
        
    except OSError:
        print(f'File not found: {file_name}')

def vsftpd_regex(line, start_date, end_date):
    element = {}
    split_line = line.split()
    timestamp_b = split_line[1]
    timestamp_d = split_line[2]
    timestamp_Y = split_line[4]
    timestamp_time = split_line[3]
    timestamp_str = str(f"{timestamp_d}/{timestamp_b}/{timestamp_Y}:{timestamp_time}")
    date = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S')
    
    if(date >= start_date and date <= end_date):
        element['date'] = date
        
        if(split_line[7] == "CONNECT:"):
            element['client'] = split_line[9].replace('"', '').replace(',', '')
            element['activity'] = split_line[7].replace(':', '')
            element['status'] = ""
            element['resource'] = ""
        
        elif(split_line[9] == "LOGIN:"):
            element['client'] = split_line[11].replace('"', '').replace(',', '')
            element['activity'] = split_line[9].replace(':', '')
            element['status'] = split_line[8]
            element['resource'] = ""
        
        elif(split_line[9] == "DOWNLOAD:"):
            element['client'] = split_line[11].replace('"', '').replace(',', '')
            element['activity'] = split_line[9].replace(':', '')
            element['status'] = split_line[8]
            element['resource'] = split_line[12].replace('"', '').replace(',', '')
            
        return element

def vsftpd_Client_counter(load_log):
    vsftpd_clientlist = []
    for items in load_log:
        vsftpd_clientlist.append(items['client'])
    clientcount = Counter(vsftpd_clientlist)
    for i,c in clientcount.items():
        print("Client: " + str(i) + " - " + "Count: " + str(c)) 

def vsftpd_Type_counter(load_log):
    vsftpd_typelist = []
    for items in load_log:
        vsftpd_typelist.append(items['activity'])
    typecount = Counter(vsftpd_typelist)
    for i,c in typecount.items():
        print("Request type: " + str(i) + " - " + "Count: " + str(c))

def vsftpd_Response_counter(load_log):
    vsftpd_Responselist = []
    for items in load_log:
        vsftpd_Responselist.append(items['status'])
    statuscount = Counter(vsftpd_Responselist)
    for i,c in statuscount.items():
        print("Status received: " + str(i) + " - " + "Count: " + str(c))
        
def vsftpd_Raw_log(load_log):
    for i in load_log:
        print(str(i)) 
        

if __name__ == "__main__":
    exit = False 
    #Initialize the log entry specification. The program will loop until exit is stated
    while not exit:
        print("*****   Type 'exit' to exit the program.   *****")
        file_name = str(input("\nPlease specify the log filename: ")).lower()
        file_exists = os.path.exists(file_name) #Here we check the existence of the given filename
        
        if file_exists: 
            #Once we select a file, the program will the go through a type of log selection
            #These options are given as log formats are different, so each log type will have different parsing functions
            selector = False 
            while not selector:
                print("\n\tLog type selection. Enter 'main' to go back to log filename selector.")
                print("\t*****  apache, vsftpd  *****")
                log_type = str(input("Specify the log type:")).lower()
                
                #APACHE SERVICE TYPE LOG MANAGER
                while log_type == "apache":
                                        
                    print(f"Type {log_type} selected. Time frame available 19/12/2020 - 03/02/2021")
                    #Input of time frame for searching within the transformed log file
                    #Next, we ask the start date to be used as a reference when going through the log
                    sdate_input = False
                    while not sdate_input:
                        apache_start_date = input("Enter the start date (dd/mm/YYYY): ").lower()
                        #We validate the input date is in the correct format, otherwise an error is displayed
                        #In case of an error, the user will be prompted to enter a valid date again
                        try:
                            apache_start_date_object = datetime.strptime(apache_start_date, '%d/%m/%Y')
                            sdate_input = True
                        except ValueError as ve:
                            print('ValueError Raised:', ve)
                    
                    #Next, we ask the start time to be used as a reference when going through the log
                    stime_input = False
                    while not stime_input:
                        apache_start_time = input("Enter the start time (HH:mm:ss): ").lower()
                        #The time is also validated
                        try:
                            apache_start_time_object = datetime.strptime(apache_start_time, '%H:%M:%S').time()
                            stime_input = True
                        except ValueError as ve:
                            print('ValueError Raised:', ve)
                    
                    #Next, we gather the end date for searching within the transformed log file
                    edate_input = False
                    while not edate_input:
                        apache_end_date = input("Enter the end date (dd/mm/YYYY): ").lower()
                        try:
                            apache_end_date_object = datetime.strptime(apache_end_date, '%d/%m/%Y')
                            #Here we validate the end date would be either the same day as the start day, or in the future
                            if(apache_end_date_object >= apache_start_date_object):
                                edate_input = True
                            else:
                                print("\tHmmm, End date should happen after the Start date. Please try again")
                        except ValueError as ve:
                            print('ValueError Raised:', ve)
                    
                    #Finally, we gather the end time for searching within the transformed log file
                    etime_input = False
                    while not etime_input:
                        apache_end_time = input("Enter the end time (HH:mm:ss): ").lower()
                        try:
                            apache_end_time_object = datetime.strptime(apache_end_time, '%H:%M:%S').time()
                            etime_input = True
                        except ValueError as ve:
                            print('ValueError Raised:', ve)
                    
                    #Start date and start time is joined together in a format that will help us comparing it against the log file 
                    apache_start_date_object = apache_start_date_object.combine(apache_start_date_object,apache_start_time_object)
                    #End date and end time is also joined together
                    apache_end_date_object = apache_end_date_object.combine(apache_end_date_object,apache_end_time_object)
                    """""######################################################################################################################"""""
                    #Here we load the log. The response is already filtered depending of the defined time threshold 
                    load_log = read_apache_log_file(file_name, apache_start_date_object, apache_end_date_object)
                                        
                    """""######################################################################################################################"""""
                    
                    apache_action_request = False
                    while not apache_action_request:
                        print("***** Choose one of the options below (enter the number option): *****")
                        apache_action = input("(1) Requests initiated from a given IP \n(2) Type of request frequency \n(3) Response status code \n(4) Browsers used \n(5) Raw log \n(9) exit \n")
                        if apache_action.isnumeric():
                            if int(apache_action) < 6 and int(apache_action) > 0:
                                if int(apache_action) == 1:
                                    apache_IP_counter(load_log)
                                
                                if int(apache_action) == 2:
                                    apache_Type_counter(load_log)
                                    
                                if int(apache_action) == 3:
                                    apache_Response_counter(load_log)
                                
                                if int(apache_action) == 4:
                                    apache_Browser_counter(load_log)
                                    
                                if int(apache_action) == 5:
                                    apache_Raw_log(load_log)
                                    
                            elif int(apache_action) == 9:
                                print("***** Returning to Log file selection ......  *****")
                                selector = True
                                apache_action_request = True
                                log_type = ""
                                
                            else:
                                print("\tHmmm, Selection not recognized. Please try again")
                        
                        else:
                            print("\tHmmm, Option is not a number. Please try again")
                            
                            
                if log_type == "main":
                    print("***** Returning to Log file selection ......  *****")
                    requests = True
                
                
                #VSFTPD SERVICE TYPE LOG MANAGER - LINUX FTP SERVICE
                while log_type == "vsftpd":
                    print(f"Type {log_type} selected. Time frame available 12/12/2022 - 15/12/2021")
                    #Input of time frame for searching within the transformed log file
                    vdate_input = False
                    while not vdate_input:
                        vsftpd_start_date = input("Enter the start date (dd/mm/YYYY): ").lower()
                        try:
                            vsftpd_start_date_object = datetime.strptime(vsftpd_start_date, '%d/%m/%Y')
                            vdate_input = True
                        except ValueError as ve:
                            print('ValueError Raised:', ve)
                    
                    vtime_input = False
                    while not vtime_input:
                        vsftpd_start_time = input("Enter the start time (HH:mm:ss): ").lower()
                        try:
                            vsftpd_start_time_object = datetime.strptime(vsftpd_start_time, '%H:%M:%S').time()
                            vtime_input = True
                        except ValueError as ve:
                            print('ValueError Raised:', ve)
                    
                    vedate_input = False
                    while not vedate_input:
                        vsftpd_end_date = input("Enter the end date (dd/mm/YYYY): ").lower()
                        try:
                            vsftpd_end_date_object = datetime.strptime(vsftpd_end_date, '%d/%m/%Y')
                            if(vsftpd_end_date_object >= vsftpd_start_date_object):
                                vedate_input = True
                            else:
                                print("\tHmmm, End date should happen after the Start date. Please try again")
                        except ValueError as ve:
                            print('ValueError Raised:', ve)
                    
                    vetime_input = False
                    while not vetime_input:
                        vsftpd_end_time = input("Enter the end time (HH:mm:ss): ").lower()
                        try:
                            vsftpd_end_time_object = datetime.strptime(vsftpd_end_time, '%H:%M:%S').time()
                            vetime_input = True
                        except ValueError as ve:
                            print('ValueError Raised:', ve)
                    
                    
                    vsftpd_start_date_object = vsftpd_start_date_object.combine(vsftpd_start_date_object,vsftpd_start_time_object)
                    vsftpd_end_date_object = vsftpd_end_date_object.combine(vsftpd_end_date_object,vsftpd_end_time_object)
                    """""######################################################################################################################"""""
                    
                    load_log = read_vsftpd_log_file(file_name, vsftpd_start_date_object, vsftpd_end_date_object)
                                        
                    """""######################################################################################################################"""""
                    
                    vsftpd_action_request = False
                    while not vsftpd_action_request:
                        print("***** Choose one of the options below (enter the number option): *****")
                        vsftpd_action = input("(1) Requests from a given Client \n(2) Type of request and frequency \n(3) Response status code \n(4) Raw log \n(9) exit \n")
                        if vsftpd_action.isnumeric():
                            if int(vsftpd_action) < 5 and int(vsftpd_action) > 0:
                                if int(vsftpd_action) == 1:
                                    vsftpd_Client_counter(load_log)
                                
                                if int(vsftpd_action) == 2:
                                    vsftpd_Type_counter(load_log)
                                    
                                if int(vsftpd_action) == 3:
                                    vsftpd_Response_counter(load_log)
                                                                
                                if int(vsftpd_action) == 4:
                                    vsftpd_Raw_log(load_log)
                                    
                            elif int(vsftpd_action) == 9:
                                print("***** Returning to Log file selection ......  *****")
                                selector = True
                                vsftpd_action_request = True
                                log_type = ""
                                
                            else:
                                print("\tHmmm, Selection not recognized. Please try again")
                        
                        else:
                            print("\tHmmm, Option is not a number. Please try again")
                            
                else:
                    print(f"\tHmmm, Log type {log_type} not recognized. Please try again")
                
                
        elif file_name == "exit":
            exit = True
            
        else: 
            print("\tHmmm, File not found. Check the name and try again")