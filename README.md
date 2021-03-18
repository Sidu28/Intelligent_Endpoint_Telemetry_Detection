## Project Overview 

This repository defines a product that provides a comprehensive approach to file security. Specifically, we aim to (a) establish a common, open-source standard for representation of file/endpoint telemetry and (b) leverage our developed standard with machine intelligence algorithms to develop a privacy-aware malware detection system that utilizes system-level information to recognize the presence of malware in a given file.

[![Test Status](https://github.com/cs210/vmware/actions/workflows/ci.yml/badge.svg)](https://github.com/cs210/vmware/actions/workflows/ci.yml)

## Setup Instructions

Create a virtual environment (for sake of example, called `venv`):
```
python3 -m virtualenv venv
```
Enter your virtual environment
```
source venv/bin/activate
```
Install requirements
```
pip3 install -r requirements.txt
```
Extract sample features on a PE file
```
python3 main.py --file=[FILENAME]
```

Extract features for multiple files into a dataframe and generate visualizations.  Specify directory containing PE files, and optionally a label for those files.  Default label value is 1.
```
python3 main.py --dir=[DIRECTORY] --label=[0 or 1]
```

Run randomforest on extracted features
```
python3 random_forest.py --file=[FILENAME]
```

To generate images for comparing feature distributions for associated columns for bad and good PE Files
```
python3 main.py --good=[GoodPE CSV] --bad=[BadPE CSV]
```


## Team Members
 
Member | Email | Photo
--- | --- | ---
Shashank | saddagarla@stanford.edu | <img src="https://github.com/cs210/vmware/blob/master/photos/content.jpg?raw=false" width=200>
Kevin | huke@stanford.edu | <img src="https://github.com/cs210/vmware/blob/master/photos/kevin.JPG?raw=false" width=200>
Siddhartha | kachapah@stanford.edu | <img src="https://github.com/cs210/vmware/blob/master/photos/siddhartha3.jpg?raw=false" width=200>
Manan | manans@stanford.edu | <img src="https://github.com/cs210/vmware/blob/master/photos/manan.jpeg?raw=false" width=200>
 
## Team Skills Matrix
 
Member | Skills | Personal Traits | Desired Growth | Weaknesses
--- | --- | --- | --- | ---
Shashank | probability, statistics, machine learning | works extremely well under pressure, team-oriented, pragmatic/rational thinker | software project management, security skills, design thinking | bureaucracy, deadlines
Kevin | ML, theory + math, some front end experience, database | Organized, critical thinker | project management, building software from scratch, design process | Not very creative, computer systems
Siddhartha | Machine Learning, data science, math | problem solver, patient  | project management, code management, security | front end,web development, UI/UX
Manan | systems, machine learning, math, crypto | relatively organized, detail-oriented, abstract thinker | project management, team organization, enterprise system design + ideation | webdev, very structured environments

## Team Communication and Links

Documentation and Task Management: [Notion](https://www.notion.so/728d3fa25cd349bdbf0f3b30e6f20b36?v=1637bfece18c4260949885b5902fee8a)
